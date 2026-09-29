import os
from contextlib import asynccontextmanager
from pathlib import Path

# Load .env before anything reads the environment.
#
# store.py resolves VERA_DB_PATH at import time and the LLM bridge reads its
# configuration when first constructed, so this has to happen above those
# imports rather than inside a startup hook. Deliberately not `override=True`:
# a variable already set by the shell, by run.ps1, or by a host such as Render
# is the more specific instruction and wins over a checked-out file.
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:  # python-dotenv absent: environment variables still work
    pass

# NTRO mode by default when started as `python main.py`: read-only agent, local
# qwen3:1.7b, VERA_OFFLINE=1. Only variables still unset after .env are
# filled, and only here, before the imports below read them; importing `main`
# (the test suite does) changes nothing. See engine/ntro_mode.py.
if __name__ == "__main__":
    from engine import ntro_mode

    _filled = ntro_mode.apply_defaults()
    if _filled:
        print(f"[vera] NTRO defaults applied: {', '.join(_filled)}")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import store
from api import auth as auth_api
from api import security
from api.chat_stream import router as chat_stream_router
from api.graph_summary import router as graph_summary_router
from api.projects import router as projects_router
from api.integration import router as integration_router
from api.routes import get_threat_model, router
from engine.version import TOOL_VERSION


@asynccontextmanager
async def lifespan(_: FastAPI):
    # VERA_OFFLINE=1: wrap the socket layer before anything can open a
    # connection. A no-op when the variable is unset.
    from engine import offline

    if offline.install():
        print("[vera] offline guard on: outbound connections limited to this machine and named scan targets")

    # Fit the survival ensemble and open the database once at boot rather than
    # on the first request, so the first scan of a demo is not slowed by it.
    # (@app.on_event has been deprecated since FastAPI 0.93.)
    store.init()
    get_threat_model()

    # Load any AI providers configured in .env into the agent pool. A key
    # pasted into a file should just work; making an operator re-enter it in
    # the UI would be a second place for the same secret to be wrong.
    try:
        from engine.core.agents import seed_from_environment

        seeded = seed_from_environment()
        if seeded:
            print(f"[vera] agent pool seeded from environment: {', '.join(seeded)}")
    except Exception as exc:  # never let this stop the server booting
        print(f"[vera] agent pool seeding skipped: {exc}")

    # Optionally load an estate at boot.
    #
    # Off by default: locally, an empty inventory until someone runs a scan is
    # the honest state, and the UI says so. On a shared deployment it is not -
    # the instance sleeps, wakes with no state, and a visitor who does not know
    # to press "load demo estate" sees an empty tool and concludes it is broken.
    #
    # VERA_AUTOLOAD_VAULT loads demo/vault/ (23 assets — CISO showcase).
    # VERA_AUTOLOAD_DEMO loads the larger synthetic estate (~195 assets).
    # Vault wins when both are set; they are different datasets.
    persona = os.environ.get("VERA_ORG_PERSONA", "Banking")
    autoload_vault = os.environ.get("VERA_AUTOLOAD_VAULT", "").lower() in {"1", "true", "yes"}
    autoload_demo = os.environ.get("VERA_AUTOLOAD_DEMO", "").lower() in {"1", "true", "yes"}

    if autoload_vault:
        from api.routes import run_vault_scan

        try:
            run_vault_scan(org_persona=persona, merge=False, vault_root=None)
        except Exception as exc:  # never let this stop the server booting
            print(f"[vera] vault autoload failed: {exc}")
    elif autoload_demo:
        from api.routes import run_demo_scan

        try:
            # Pass org_persona explicitly. Called as a plain function rather
            # than through the router, FastAPI's Query default is not resolved
            # and the parameter arrives as a Query object instead of a string.
            run_demo_scan(org_persona=persona)
        except Exception as exc:  # never let this stop the server booting
            print(f"[vera] demo autoload failed: {exc}")

    yield


app = FastAPI(
    title="VERA API",
    description=(
        "Enterprise cryptographic discovery and analysis for the post-quantum "
        "transition. Collects across code, dependencies, binaries, containers, "
        "configs, keystores, vaults and the wire; emits a schema-valid CycloneDX "
        "1.7 CBOM, SARIF and a signed manifest; and ranks every asset by Mosca "
        "margin against statutory deadlines."
    ),
    version=TOOL_VERSION,
    lifespan=lifespan,
)

# In development the dashboard runs on the Vite dev server, so the browser
# needs CORS. In production it is served from this same process, so requests
# are same-origin and none of this applies.
#
# Origins are pinned rather than wildcarded. Set VERA_ALLOWED_ORIGINS (comma
# separated) to add a deployed front end hosted separately.
_extra_origins = [
    origin.strip()
    for origin in os.environ.get("VERA_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

_origins = [
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:4173", "http://127.0.0.1:4173",
    *_extra_origins,
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    # DELETE forgets a stored API key or clears the agent audit log; PUT and
    # PATCH change settings and users.
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)

# Sign-in and roles on every /api call (api/auth.py). Added before the security
# envelope so a refusal still carries the security headers.
app.add_middleware(auth_api.AuthMiddleware, allowed_origins=_origins)

# Baseline HTTP hardening: security headers + CSP on every response, with
# optional HTTPS enforcement and a per-IP rate limit (both env-gated). See
# api/security.py. Installed before the routers so it wraps the whole surface,
# static assets included.
security.install(app)

app.include_router(router, prefix="/api")
app.include_router(auth_api.router, prefix="/api")

# The integration surface: the same tools, callable by another system.
# Versioned and mounted separately from /api because /api is this
# dashboard's private backend and changes with the UI, while /api/v1 is a
# contract someone else's code depends on.
app.include_router(integration_router, prefix="/api")
# Streaming agent turns. Same logic as /api/chat, different transport.
app.include_router(chat_stream_router, prefix="/api")
# A light projection of the dependency graph for table columns.
app.include_router(graph_summary_router, prefix="/api")
# Projects and saved assistant conversations (engine/projects.py).
app.include_router(projects_router, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "VERA", "version": TOOL_VERSION}


# --------------------------------------------------------------------------
# Serve the built dashboard from the API process.
#
# One service instead of two. The dashboard and the API share an origin, so
# there is no CORS to configure in production, no second deployment to keep in
# step, and a custom domain points at exactly one host.
#
# In development the front end still runs on the Vite dev server for hot
# reload, talking to this process cross-origin - which is what the CORS block
# above is for. That path is unaffected.
#
# Registered last so it cannot shadow /api routes.
# --------------------------------------------------------------------------

STATIC_DIR = Path(os.environ.get("VERA_STATIC_DIR", Path(__file__).parent / "static"))

if STATIC_DIR.is_dir() and (STATIC_DIR / "index.html").exists():
    app.mount(
        "/assets",
        StaticFiles(directory=STATIC_DIR / "assets"),
        name="assets",
    )

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    def spa_fallback(path: str):
        """Serve real files where they exist, otherwise the app shell.

        The dashboard keeps its own page state rather than using client-side
        routing, so this mainly covers favicons and a refresh on a deep link.
        """
        # An unknown /api path is a 404, not the app shell. Falling through to
        # index.html returned 200 with HTML, so a typo'd endpoint surfaced as
        # "Unexpected token <" from the JSON parser instead of a clean 404 -
        # and no API consumer could tell a missing route from a served page.
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"No such endpoint: /{path}")

        candidate = (STATIC_DIR / path).resolve()
        # Guard against path traversal escaping the static root.
        if candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")


if __name__ == "__main__":
    import argparse

    import uvicorn

    # Auto-reload is off by default, deliberately.
    #
    # uvicorn's reloader runs a supervisor plus a forked worker. If the
    # supervisor is killed without the worker - which is what happens when a
    # terminal is closed, or a process is killed by name rather than by tree -
    # the orphaned worker keeps the listening socket. The next start then fails
    # to bind and silently leaves the OLD worker serving stale code on port
    # 8000, which looks exactly like "my fix didn't work". Not something to
    # discover during a presentation.
    #
    # Pass --reload when actively editing.
    parser = argparse.ArgumentParser(description="Run the VERA API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="auto-reload on edit")
    args = parser.parse_args()

    uvicorn.run("main:app", host=args.host, port=args.port, reload=args.reload)
