"""Redactly command-line interface.

``main`` is the click group referenced by ``[project.scripts] redactly``.

Commands:

- ``redactly proxy [--host] [--port] [--upstream]`` — run the redaction proxy
  under uvicorn in the foreground.
- ``redactly wrap claude [-- claude-args…]`` — ensure the proxy is up, point the
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
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import click

from . import __version__
from .config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_UPSTREAM, ENV_UPSTREAM

CLAUDE_SETTINGS_LOCAL = Path(".claude") / "settings.local.json"
CLAUDE_BASE_URL_KEY = "ANTHROPIC_BASE_URL"


@click.group()
@click.version_option(__version__, prog_name="redactly")
def main() -> None:
    """Redactly — mask your secrets before they leave your machine."""


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
@click.argument("tool", type=click.Choice(["claude"]))
@click.option("--port", default=DEFAULT_PORT, show_default=True, type=int, help="Proxy port to ensure/route to.")
@click.argument("tool_args", nargs=-1, type=click.UNPROCESSED)
def wrap_cmd(tool: str, port: int, tool_args: tuple[str, ...]) -> None:
    """Run an AI coding tool with its traffic routed through Redactly."""
    proxy_url = f"http://{DEFAULT_HOST}:{port}"
    _ensure_proxy(port)

    env = os.environ.copy()
    env[CLAUDE_BASE_URL_KEY] = proxy_url
    previous = _write_base_url(proxy_url)

    binary = shutil.which(tool) or tool
    click.echo(f"redactly: routing {tool} through {proxy_url} (fail-closed)", err=True)
    try:
        result = subprocess.run([binary, *tool_args], env=env)
        rc = result.returncode
    finally:
        _restore_base_url(previous)
    raise SystemExit(rc)


# --- helpers --------------------------------------------------------------


def _healthz(port: int, host: str = DEFAULT_HOST) -> bool:
    """Return ``True`` if a Redactly proxy answers ``/healthz`` on ``host:port``."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ensure_proxy(port: int, *, host: str = DEFAULT_HOST, timeout: float = 30.0) -> None:
    """Start the proxy daemon (detached) if it is not already listening.

    Logs to a FILE (not a pipe — avoids the macOS 64KB pipe-buffer deadlock),
    detaches via ``start_new_session``, and polls ``/healthz`` until ready.
    """
    if _healthz(port, host):
        return
    log_dir = Path.home() / ".redactly"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "proxy.log"
    with open(log_path, "ab") as log:
        subprocess.Popen(
            [sys.executable, "-m", "redactly.cli", "proxy", "--host", host, "--port", str(port)],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _healthz(port, host):
            return
        time.sleep(0.5)
    raise SystemExit(
        f"redactly: proxy did not become healthy on {host}:{port} within "
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


if __name__ == "__main__":  # pragma: no cover
    main()
