"""Baseline HTTP security hardening.

These are the load-bearing controls that should be present on any deployment and
are not expected to change as the product grows: security response headers, a
content security policy, optional transport enforcement, and an optional
per-client rate limit on the whole surface.

They are deliberately conservative and self-contained (no new dependencies). The
integration API keeps its own per-key rate limit and audit log in
``engine/agent_control.py``; this module is the outer envelope around the entire
app, applied to the dashboard backend and the static assets as well.

Everything here is configurable by environment variable so a stricter or looser
posture is a deployment decision, never a code change:

  VERA_ENABLE_HSTS        "1" to send Strict-Transport-Security (only behind TLS)
  VERA_FORCE_HTTPS        "1" to 308-redirect http -> https (respects X-Forwarded-Proto)
  VERA_CSP                override the Content-Security-Policy string entirely
  VERA_RATE_LIMIT         requests per window per client IP (0/unset = disabled)
  VERA_RATE_WINDOW        window length in seconds (default 60)
  VERA_HOSTED_MODE        "1" to require an issued key on every /api call,
                           for running the engine on your own server while
                           the dashboard runs on the operator's machine
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

# A policy tight enough to matter, loose enough that the built dashboard still
# runs: same-origin scripts only, inline styles allowed (the UI uses style props
# and Vite injects a little inline CSS), fonts from this origin only (they are
# bundled, nothing is fetched from a CDN), and no framing of the app by another
# site. Overridable wholesale with VERA_CSP.
_DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

_PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=()"


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response, including error responses."""

    def __init__(self, app):
        super().__init__(app)
        self.csp = os.environ.get("VERA_CSP", _DEFAULT_CSP)
        self.hsts = _flag("VERA_ENABLE_HSTS")

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", _PERMISSIONS_POLICY)
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        h.setdefault("Content-Security-Policy", self.csp)
        # Only assert HSTS when explicitly enabled: sending it on a plain-http
        # dev instance would pin the browser to https for a host that has none.
        if self.hsts:
            h.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Redirect http -> https when the platform terminates TLS upstream.

    Off by default. Trusts ``X-Forwarded-Proto`` because on Render/Fly/Railway
    the app itself receives plain http behind the load balancer.
    """

    async def dispatch(self, request: Request, call_next):
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto == "http" and request.url.hostname not in {"localhost", "127.0.0.1"}:
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(str(https_url), status_code=308)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A simple fixed-window rate limit per client IP across the whole surface.

    Disabled unless VERA_RATE_LIMIT is a positive integer. In-memory and
    per-process, which is the right scope for the single-instance deployment the
    app already requires (state is held in memory, so requests in a session must
    reach one machine anyway). Health checks are never limited.
    """

    def __init__(self, app):
        super().__init__(app)
        try:
            self.limit = int(os.environ.get("VERA_RATE_LIMIT", "0"))
        except ValueError:
            self.limit = 0
        try:
            self.window = float(os.environ.get("VERA_RATE_WINDOW", "60"))
        except ValueError:
            self.window = 60.0
        self._hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if self.limit <= 0 or request.url.path == "/api/health":
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - self.window
        hits = self._hits[client]
        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= self.limit:
            retry = round(self.window - (now - hits[0]), 1)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests.",
                    "retry_after_seconds": max(retry, 0.0),
                },
                headers={"Retry-After": str(int(max(retry, 1)))},
            )

        hits.append(now)
        return await call_next(request)



class HostedEngineAuthMiddleware(BaseHTTPMiddleware):
    """Require a key for the engine when it is hosted rather than local.

    WHY
    ---
    VERA's value is the engine: the two-axis model, the evidence fusion, the
    migration formalism. Deployed the ordinary way — one container, dashboard
    and API together — anyone who can reach the dashboard can also call every
    engine endpoint directly, and the whole scoring surface travels with it.

    Hosted mode splits that. The dashboard is a static bundle an operator can
    run anywhere and point at a remote engine with `VITE_API_URL`; the engine
    stays on infrastructure its author controls, and every call to it must
    carry an issued key. What ships to the customer is a client. What holds the
    method stays put.

    Enabled ONLY by `VERA_HOSTED_MODE=1`, so the default single-container and
    air-gapped deployments are completely unaffected — they have no key to
    present and need none.

    Exempt paths, deliberately:
      * `/api/v1/manifest` — a caller must be able to discover how to
        authenticate before it holds anything to authenticate with.
      * `/api/health` — a load balancer cannot hold a customer key.
      * everything outside `/api` — the static dashboard is the client, and
        serving it is not privileged.

    `/api/v1/*` already authenticates itself through the same key store, so it
    is left to do that rather than being checked twice with different rules.
    """

    #: Paths under /api that must stay reachable without a key.
    EXEMPT = ("/api/v1/manifest", "/api/health", "/api/healthz")

    def __init__(self, app):
        super().__init__(app)
        self.enabled = _flag("VERA_HOSTED_MODE")

    async def dispatch(self, request, call_next):
        if not self.enabled:
            return await call_next(request)

        path = request.url.path
        if not path.startswith("/api") or path.startswith("/api/v1"):
            return await call_next(request)
        if any(path.startswith(p) for p in self.EXEMPT):
            return await call_next(request)
        # A browser preflight carries no Authorization header by design.
        if request.method == "OPTIONS":
            return await call_next(request)

        header = request.headers.get("authorization", "")
        raw = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not raw:
            raw = request.headers.get("x-vera-key", "").strip()

        from engine.api_keys import get_store

        if get_store().verify(raw) is None:
            # Say which mode refused, so an operator who has simply not set a
            # key is not left debugging a bare 401.
            return JSONResponse(
                status_code=401,
                content={
                    "error": "This VERA engine is running in hosted mode and requires a key.",
                    "remedy": (
                        "Send it as `Authorization: Bearer <key>`. Keys are issued "
                        "in Settings -> API access on the instance that owns this "
                        "engine."
                    ),
                },
            )
        return await call_next(request)


def install(app) -> None:
    """Wire the middleware stack in the correct order.

    Added last-runs-first in Starlette, so this installs the rate limit as the
    outermost gate (reject floods before any work), then the HTTPS redirect,
    with the header-stamping innermost so it decorates every response that makes
    it back out - including 429s and redirects.
    """
    app.add_middleware(SecurityHeadersMiddleware)
    # Runs outside the header stamper so a refusal is still decorated,
    # and inside the rate limit so a flood is dropped before any key work.
    app.add_middleware(HostedEngineAuthMiddleware)
    if _flag("VERA_FORCE_HTTPS"):
        app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(RateLimitMiddleware)
