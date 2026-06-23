"""The FastAPI redaction proxy — FAIL-CLOSED, default-DENY.

Request lifecycle (every outbound request):

1. **Buffer** the entire request body (default-DENY: nothing is forwarded
   un-inspected).
2. **Pick an adapter** — the first registered adapter whose ``matches(path,
   headers)`` is ``True``. If **none** match → BLOCK (5xx), forward nothing.
   There is no passthrough default.
3. **Redact** via ``adapter.redact_request(body, redactor)``. If it raises (bad
   JSON, unexpected shape, redactor error) → BLOCK (5xx), forward nothing.
   Never forward the original body on error.
4. **Forward** to ``REDACT_UPSTREAM`` with httpx. Auth headers
   (``authorization``, ``x-api-key``, ``anthropic-version``, ``anthropic-beta``)
   are forwarded **verbatim**; hop-by-hop headers plus ``host`` and
   ``content-length`` are stripped; **no identifying headers are added**
   (subscription stealth — the proxy must be invisible to the provider).
5. **Un-mask** the streamed reply locally via ``adapter.unmask_stream`` and
   return it as a ``StreamingResponse``.

``GET /healthz`` is the liveness probe and is the only route that does not go
through the redaction pipeline.

This is the deliberate inversion of Headroom's fail-OPEN proxy: where Headroom
forwards the original on any compression failure, Scrimward refuses.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Mapping, Sequence

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from . import config as _config
from .adapters import ADAPTERS
from .adapters.base import Adapter
from .config import Config
from .engine import Redactor
from .vault import Vault, _current_vault, set_current_vault

# Hop-by-hop headers (RFC 7230 §6.1) plus ``host`` / ``content-length``. These
# are connection-scoped and must NOT be forwarded to the upstream; httpx sets
# its own. Auth headers are deliberately NOT in this set — they pass verbatim.
HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        # accept-encoding is stripped so httpx negotiates an encoding it can
        # actually decode (Headroom hit this — a forwarded br/zstd accept that
        # httpx can't decompress corrupts the streamed body).
        "accept-encoding",
    }
)

# Response headers that describe the upstream's *transport framing* and must NOT
# be copied onto our StreamingResponse: httpx has already decoded the body, and
# Starlette frames its own length/encoding. Copying these would mis-declare the
# (now un-masked, re-length-shifted) body to the client.
_RESPONSE_DROP_HEADERS: frozenset[str] = frozenset(
    {
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
    }
)


def filter_upstream_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` safe to forward upstream.

    Strips hop-by-hop + ``host`` + ``content-length`` + ``accept-encoding``
    (see :data:`HOP_BY_HOP_HEADERS`); forwards everything else — crucially the
    auth headers — **verbatim**. Adds NOTHING (no ``x-scrimward-*``, no proxy
    fingerprint): the proxy must be invisible to the provider.

    Filtering is case-insensitive (HTTP header names are case-insensitive); the
    original casing of forwarded headers is preserved so the wire bytes match
    what the tool sent (subscription stealth).
    """
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in HOP_BY_HOP_HEADERS:
            continue
        out[name] = value
    return out


def _filter_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Strip transport-framing headers from the upstream response.

    The body we hand back has been decoded by httpx and re-framed by Starlette
    (and its length changed by un-masking), so the upstream's
    ``content-length`` / ``content-encoding`` / ``transfer-encoding`` no longer
    describe it. Everything else (rate-limit headers, ``content-type``, …) is
    passed through so the client sees a transparent reply.
    """
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _RESPONSE_DROP_HEADERS:
            continue
        out[name] = value
    return out


def _blocked(reason: str, *, status_code: int = 502) -> JSONResponse:
    """Build the fail-closed block response — 5xx, forwards NOTHING.

    Returned whenever the proxy cannot guarantee the body was redacted: no
    adapter matched the path, or ``redact_request`` raised. The original body
    never reaches the wire.
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "type": "scrimward_blocked",
                "message": reason,
            }
        },
    )


def _pick_adapter(
    adapters: Sequence[Adapter], path: str, headers: Mapping[str, str]
) -> Adapter | None:
    """Return the first adapter whose ``matches`` is True, else ``None``.

    Registry order is match priority. ``None`` (no match) is a fail-closed
    condition handled by the caller — there is no passthrough default.
    """
    for adapter in adapters:
        if adapter.matches(path, headers):
            return adapter
    return None


def create_app(
    config: Config | None = None,
    *,
    adapters: Sequence[Adapter] | None = None,
) -> FastAPI:
    """Build and return the FastAPI app for the Scrimward proxy.

    Wires:

    - ``GET /healthz`` → liveness (bypasses the redaction pipeline).
    - catch-all ``POST`` → buffer → pick adapter (fail-closed if none) →
      ``redact_request`` (fail-closed on raise) → httpx forward to
      ``config.upstream`` with verbatim auth + stripped hop-by-hop headers →
      ``StreamingResponse`` via ``adapter.unmask_stream``.

    ``config`` defaults to :func:`scrimward.config.load`. The upstream comes from
    ``config.upstream`` (``REDACT_UPSTREAM``) so tests can point it at a mock.
    ``adapters`` defaults to the built-in registry; tests may inject their own.
    """
    cfg = config if config is not None else _config.load()
    registry: Sequence[Adapter] = adapters if adapters is not None else ADAPTERS
    upstream = cfg.upstream.rstrip("/")

    app = FastAPI(title="Scrimward", version="0.0.1")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Liveness probe — does NOT go through the redaction pipeline."""
        return JSONResponse({"status": "ok", "upstream": upstream})

    @app.post("/{full_path:path}")
    async def proxy(full_path: str, request: Request):
        # --- 1. Buffer the entire body (default-DENY: inspect everything). ---
        body = await request.body()
        # Reconstruct the path-with-leading-slash + query so adapters and the
        # upstream URL see exactly what the tool requested.
        path = request.url.path
        headers = dict(request.headers)

        # --- 2. Pick an adapter; no match is a fail-closed block. ---
        adapter = _pick_adapter(registry, path, headers)
        if adapter is None:
            return _blocked(
                f"no adapter matched path {path!r}; refusing to forward "
                "un-inspectable request (fail-closed)"
            )

        # --- 3. Build a per-request vault + redactor, then redact. ---
        #
        # The vault is session-scoped; one request = one session here. It is
        # in-memory unless ``config.vault_path`` is set. A redactor is built
        # over it with the configured user rules + allowlist.
        session_id = uuid.uuid4().hex
        vault = Vault(session_id, path=cfg.vault_path)
        redactor = Redactor(
            vault,
            user_rules=cfg.user_rules,
            allowlist=cfg.allowlist,
        )

        try:
            redacted_body = adapter.redact_request(body, redactor)
        except Exception as exc:  # noqa: BLE001 — fail-closed on ANY redactor error
            # The original body NEVER reaches the wire. Block with 5xx.
            return _blocked(
                f"redaction failed for path {path!r}: {type(exc).__name__}: {exc}; "
                "forwarding nothing (fail-closed)"
            )

        # --- 4. Forward to upstream with verbatim auth + stripped hop-by-hop. ---
        target_url = upstream + path
        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"
        outbound_headers = filter_upstream_headers(headers)

        client = httpx.AsyncClient(timeout=None)
        try:
            upstream_req = client.build_request(
                "POST",
                target_url,
                content=redacted_body,
                headers=outbound_headers,
            )
            upstream_resp = await client.send(upstream_req, stream=True)
        except Exception as exc:  # noqa: BLE001 — upstream unreachable
            await client.aclose()
            return _blocked(
                f"upstream forward failed: {type(exc).__name__}: {exc}",
                status_code=502,
            )

        # --- 5. Un-mask the streamed reply locally and stream it back. ---
        #
        # The un-masker receives ``vault`` explicitly (per the Adapter
        # contract), so substitution does not depend on context. The ContextVar
        # is bound as belt-and-braces for any helper that reaches for the
        # active vault, and the upstream response + client are closed when the
        # stream finishes or the client disconnects.
        async def _stream() -> AsyncIterator[bytes]:
            ctx_token = set_current_vault(vault)
            try:
                async for chunk in adapter.unmask_stream(
                    upstream_resp.aiter_bytes(), vault
                ):
                    yield chunk
            finally:
                # Reset in the SAME context the token was minted in (the
                # generator's). Resetting from a different context would raise.
                try:
                    _current_vault.reset(ctx_token)
                except ValueError:  # pragma: no cover — defensive
                    set_current_vault(None)

        async def _cleanup() -> None:
            try:
                await upstream_resp.aclose()
            finally:
                await client.aclose()

        response_headers = _filter_response_headers(dict(upstream_resp.headers))
        media_type = upstream_resp.headers.get("content-type")

        return StreamingResponse(
            _stream(),
            status_code=upstream_resp.status_code,
            headers=response_headers,
            media_type=media_type,
            background=BackgroundTask(_cleanup),
        )

    return app


def _default_app() -> FastAPI:
    """Build the module-level ``app`` for ``uvicorn scrimward.proxy:app``.

    Uses :func:`scrimward.config.load` (env + rules file) when available. While
    the surrounding scaffold is still stubbed, ``config.load`` raises
    ``NotImplementedError``; we fall back to a concrete default :class:`Config`
    so ``app`` stays importable (the route wiring is independent of how the
    config was sourced). Once ``config.load`` is implemented this transparently
    uses it.
    """
    try:
        return create_app()
    except NotImplementedError:
        return create_app(Config())


# Module-level ASGI app for ``uvicorn scrimward.proxy:app`` and the CLI.
app = _default_app()
