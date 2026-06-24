"""Scrimward command-line interface.

``main`` is the click group referenced by ``[project.scripts] scrimward``.

Commands:

- ``scrimward proxy [--host] [--port] [--upstream]`` — run the redaction proxy
  under uvicorn in the foreground.
- ``scrimward wrap claude [-- claude-args…]`` — ensure the proxy is up, point the
  wrapped tool at it, run it as a subprocess, restore on exit.

The ``wrap`` flow models Headroom's launcher: it sets ``ANTHROPIC_BASE_URL`` AND
writes ``env.ANTHROPIC_BASE_URL`` into the project-local
``.claude/settings.local.json`` (Claude Code's daemon re-reads settings fresh per
conversation, so the env var alone is not enough — issue #951). The previous
value is captured and restored in a ``finally``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import click

from . import __version__
from .config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_UPSTREAM, ENV_RULES, ENV_UPSTREAM

CLAUDE_SETTINGS_LOCAL = Path(".claude") / "settings.local.json"
CLAUDE_BASE_URL_KEY = "ANTHROPIC_BASE_URL"

# Global Scrimward state (rules live here so the proxy daemon reads them no
# matter which directory it was spawned from).
SCRIMWARD_HOME = Path.home() / ".scrimward"
RULES_PATH = SCRIMWARD_HOME / "rules.json"
_REPO_ROOT = Path(__file__).resolve().parent.parent

# Per-tool launch config for `scrimward wrap <tool>`. Each tool gets its own
# proxy instance + upstream, isolated by port, so one redactor can serve
# tools that talk to different providers.
WRAP_TOOLS: dict[str, dict] = {
    "claude": {
        "port": DEFAULT_PORT,
        "upstream": "https://api.anthropic.com",
        "env": "ANTHROPIC_BASE_URL",
        "base_suffix": "",
        "write_claude_settings": True,
    },
    "codex": {
        "port": DEFAULT_PORT + 1,
        "upstream": "https://api.openai.com",
        "env": "OPENAI_BASE_URL",
        "base_suffix": "/v1",
        "write_claude_settings": False,
    },
    "gemini": {
        # API-key mode (GOOGLE_GEMINI_BASE_URL → generativelanguage). The default
        # "Login with Google" mode routes through Cloud Code Assist and needs
        # CODE_ASSIST_ENDPOINT instead — see docs/integrations/gemini-cli.md.
        "port": DEFAULT_PORT + 2,
        "upstream": "https://generativelanguage.googleapis.com",
        "env": "GOOGLE_GEMINI_BASE_URL",
        "base_suffix": "",
        "write_claude_settings": False,
    },
}


@click.group()
@click.version_option(__version__, prog_name="scrimward")
def main() -> None:
    """Scrimward — mask your secrets before they leave your machine."""


@main.command("proxy")
@click.option("--host", default=DEFAULT_HOST, show_default=True, help="Bind host (loopback only by default).")
@click.option("--port", default=DEFAULT_PORT, show_default=True, type=int, help="Bind port.")
@click.option("--upstream", default=None, help=f"Upstream base URL (default: $REDACT_UPSTREAM or {DEFAULT_UPSTREAM}).")
def proxy_cmd(host: str, port: int, upstream: str | None) -> None:
    """Run the redaction proxy under uvicorn (foreground)."""
    import uvicorn

    from .proxy import create_app

    if upstream:
        os.environ[ENV_UPSTREAM] = upstream
    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="warning")


@main.command(
    "wrap",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("tool", type=click.Choice(sorted(WRAP_TOOLS)))
@click.option("--port", default=None, type=int, help="Override the proxy port (default: per-tool).")
@click.argument("tool_args", nargs=-1, type=click.UNPROCESSED)
def wrap_cmd(tool: str, port: int | None, tool_args: tuple[str, ...]) -> None:
    """Run an AI coding tool (claude, codex) with its traffic routed through Scrimward."""
    spec = WRAP_TOOLS[tool]
    port = port or spec["port"]
    base_url = f"http://{DEFAULT_HOST}:{port}{spec['base_suffix']}"
    _ensure_proxy(port, upstream=spec["upstream"])

    env = os.environ.copy()
    env[spec["env"]] = base_url
    previous = None
    if spec["write_claude_settings"]:
        previous = _write_base_url(f"http://{DEFAULT_HOST}:{port}")

    binary = shutil.which(tool) or tool
    click.echo(
        f"scrimward: routing {tool} via {spec['env']}={base_url} -> {spec['upstream']} (fail-closed)",
        err=True,
    )
    try:
        rc = subprocess.run([binary, *tool_args], env=env).returncode
    finally:
        if spec["write_claude_settings"]:
            _restore_base_url(previous)
    raise SystemExit(rc)


# --- helpers --------------------------------------------------------------


# A bootstrap command is one whose EXECUTABLE is scrimward / scrimward-py (after
# optional env-assignments and a path prefix) — NOT any command that merely
# contains the word "scrimward", which would disable the guard across the repo's
# own ~/Desktop/scrimward/ tree (`cat ~/Desktop/scrimward/.env`) or via a comment.
_SCRIMWARD_INVOCATION = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?scrimward(?:-py)?(?:\s|$)")


def _is_scrimward_bootstrap(command: str) -> bool:
    """True only if ``command`` actually invokes the scrimward CLI."""
    return bool(_SCRIMWARD_INVOCATION.match(command or ""))


def _healthz(port: int, host: str = DEFAULT_HOST) -> bool:
    """Return ``True`` if a Scrimward proxy answers ``/healthz`` on ``host:port``."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ensure_proxy(
    port: int, *, host: str = DEFAULT_HOST, upstream: str | None = None, timeout: float = 30.0
) -> None:
    """Start the proxy daemon (detached) if it is not already listening.

    Logs to a FILE (not a pipe — avoids the macOS 64KB pipe-buffer deadlock),
    detaches via ``start_new_session``, and polls ``/healthz`` until ready.
    ``upstream`` (when given) is passed to the daemon as ``REDACT_UPSTREAM`` so
    a per-tool proxy forwards to that tool's provider.
    """
    if _healthz(port, host):
        return
    log_dir = Path.home() / ".scrimward"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "proxy.log"
    proxy_env = os.environ.copy()
    proxy_env.setdefault(ENV_RULES, str(RULES_PATH))
    if upstream:
        proxy_env[ENV_UPSTREAM] = upstream
    with open(log_path, "ab") as log:
        subprocess.Popen(
            [sys.executable, "-m", "scrimward.cli", "proxy", "--host", host, "--port", str(port)],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=proxy_env,
            cwd=str(_REPO_ROOT),  # so `-m scrimward.cli` resolves the package
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _healthz(port, host):
            return
        time.sleep(0.5)
    raise SystemExit(
        f"scrimward: proxy did not become healthy on {host}:{port} within "
        f"{timeout:.0f}s (see {log_path}). Refusing to run the tool unprotected."
    )


def _write_base_url(proxy_url: str, settings_path: Path | None = None) -> str | None:
    """Set ``env.ANTHROPIC_BASE_URL`` in the project-local Claude settings.

    Returns the previous value (or ``None`` if unset) so the caller can restore
    it. Creates the file/dir if absent; preserves any other settings.
    """
    path = Path(settings_path) if settings_path is not None else CLAUDE_SETTINGS_LOCAL
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except json.JSONDecodeError:
            data = {}
    env = data.get("env")
    if not isinstance(env, dict):
        env = {}
        data["env"] = env
    previous = env.get(CLAUDE_BASE_URL_KEY)
    env[CLAUDE_BASE_URL_KEY] = proxy_url
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return previous


def _restore_base_url(previous: str | None, settings_path: Path | None = None) -> None:
    """Restore (or remove) ``ANTHROPIC_BASE_URL`` in the Claude settings file."""
    path = Path(settings_path) if settings_path is not None else CLAUDE_SETTINGS_LOCAL
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    env = data.get("env")
    if not isinstance(env, dict):
        return
    if previous is None:
        env.pop(CLAUDE_BASE_URL_KEY, None)
    else:
        env[CLAUDE_BASE_URL_KEY] = previous
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --- plugin commands: setup / status / rules / hooks ---------------------


def _proxy_url(port: int) -> str:
    return f"http://{DEFAULT_HOST}:{port}"


def _configured_base_url(settings_path: Path | None = None) -> str | None:
    """Return the ANTHROPIC_BASE_URL written into the project Claude settings."""
    path = Path(settings_path) if settings_path is not None else CLAUDE_SETTINGS_LOCAL
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    env = data.get("env") if isinstance(data, dict) else None
    return env.get(CLAUDE_BASE_URL_KEY) if isinstance(env, dict) else None


def _is_routed(port: int, settings_path: Path | None = None) -> bool:
    """True if this project is configured to route at our proxy AND it is healthy."""
    configured = _configured_base_url(settings_path) or os.environ.get(CLAUDE_BASE_URL_KEY)
    return configured == _proxy_url(port) and _healthz(port)


def _read_rules_doc() -> dict:
    SCRIMWARD_HOME.mkdir(parents=True, exist_ok=True)
    if not RULES_PATH.exists():
        return {"rules": [], "allowlist": {"literals": [], "patterns": []}}
    try:
        return json.loads(RULES_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"rules": [], "allowlist": {"literals": [], "patterns": []}}


def _write_rules_doc(doc: dict) -> None:
    SCRIMWARD_HOME.mkdir(parents=True, exist_ok=True)
    RULES_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


@main.command("setup")
@click.option("--port", default=DEFAULT_PORT, show_default=True, type=int)
def setup_cmd(port: int) -> None:
    """Start the proxy and route this project through it (run once, then RESTART your tool)."""
    if not RULES_PATH.exists():
        _write_rules_doc({"rules": [], "allowlist": {"literals": [], "patterns": []}})
    _ensure_proxy(port)
    _write_base_url(_proxy_url(port))
    click.echo(f"scrimward: proxy healthy on {_proxy_url(port)}; routing written to {CLAUDE_SETTINGS_LOCAL}.")
    click.echo("scrimward: RESTART your AI tool (exit and re-run it) for routing to take effect.")


@main.command("status")
@click.option("--port", default=DEFAULT_PORT, show_default=True, type=int)
def status_cmd(port: int) -> None:
    """Show whether the proxy is up and this project is routed through it."""
    click.echo(f"proxy ({_proxy_url(port)}) healthy : {_healthz(port)}")
    click.echo(f"this project routed        : {_is_routed(port)}")
    click.echo(f"custom rules               : {len(_read_rules_doc().get('rules', []))}")
    if not _is_routed(port):
        click.echo("→ NOT protected. Run `scrimward setup` (or /scrimward:setup) then restart your tool.")


@main.group("rules")
def rules_grp() -> None:
    """Manage custom redaction rules (~/.scrimward/rules.json)."""


@rules_grp.command("add")
@click.argument("name")
@click.argument("value")
@click.option("--regex", is_flag=True, help="Treat VALUE as a regex (default: literal text).")
@click.option("--prefix", default="CUSTOM", show_default=True, help="Token family prefix.")
def rules_add(name: str, value: str, regex: bool, prefix: str) -> None:
    """Redact VALUE (a literal, or --regex) everywhere, as «PREFIX_…»."""
    import re as _re

    doc = _read_rules_doc()
    doc.setdefault("rules", [])
    doc["rules"] = [r for r in doc["rules"] if r.get("name") != name]
    doc["rules"].append(
        {"name": name, "pattern": value if regex else _re.escape(value), "token_prefix": prefix}
    )
    _write_rules_doc(doc)
    click.echo(f"scrimward: added rule {name!r} (prefix {prefix}). Restart the proxy to apply.")


@rules_grp.command("list")
def rules_list() -> None:
    rules = _read_rules_doc().get("rules", [])
    if not rules:
        click.echo("(no custom rules)")
    for r in rules:
        click.echo(f"  {r.get('name')}: /{r.get('pattern')}/ -> «{r.get('token_prefix')}_…»")


@rules_grp.command("remove")
@click.argument("name")
def rules_remove(name: str) -> None:
    doc = _read_rules_doc()
    before = len(doc.get("rules", []))
    doc["rules"] = [r for r in doc.get("rules", []) if r.get("name") != name]
    _write_rules_doc(doc)
    click.echo(f"scrimward: removed {before - len(doc['rules'])} rule(s) named {name!r}.")


@main.group("hook")
def hook_grp() -> None:
    """Internal: Claude Code hook entrypoints (not for direct use)."""


def _read_hook_input() -> dict:
    """Read + parse the hook's stdin JSON (Claude Code feeds hooks JSON)."""
    try:
        if not sys.stdin.isatty():
            raw = sys.stdin.read()
            if raw.strip():
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    return {}


@hook_grp.command("session-start")
@click.option("--port", default=DEFAULT_PORT, type=int)
def hook_session_start(port: int) -> None:
    """SessionStart: best-effort start the proxy; report protection status."""
    _read_hook_input()
    try:
        _ensure_proxy(port, timeout=8.0)
    except SystemExit:
        pass
    if _is_routed(port):
        msg = f"🛡 Scrimward active: this project's cloud traffic routes through the local redaction proxy (127.0.0.1:{port})."
    elif _configured_base_url() == _proxy_url(port):
        msg = "🛡 Scrimward is configured; if tool use is blocked the proxy isn't healthy yet — run `scrimward status` or re-run /scrimward:setup."
    else:
        msg = (
            "⚠ Scrimward is installed but NOT protecting this session yet. Run /scrimward:setup, then RESTART your "
            "tool. Until routing is active, tool use is blocked (fail-closed) so nothing leaks unredacted."
        )
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": msg}}))


@hook_grp.command("guard")
@click.option("--port", default=DEFAULT_PORT, type=int)
def hook_guard(port: int) -> None:
    """PreToolUse: fail-closed — deny tool use unless traffic is routed through the proxy."""
    payload = _read_hook_input()
    if _is_routed(port):
        return  # allow
    # Bootstrap escape hatch: never block Scrimward's OWN setup/status commands,
    # or the user couldn't run /scrimward:setup to turn routing on.
    if payload.get("tool_name") in ("Bash", "Shell"):
        cmd = (payload.get("tool_input") or {}).get("command", "")
        if _is_scrimward_bootstrap(cmd):
            return
    reason = (
        "Scrimward fail-closed guard: this session is NOT routed through the local redaction proxy, so anything "
        "sent to the cloud could leak secrets/PII. Run /scrimward:setup and restart your AI tool to activate "
        "redaction, then retry."
    )
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )


if __name__ == "__main__":  # pragma: no cover
    main()
