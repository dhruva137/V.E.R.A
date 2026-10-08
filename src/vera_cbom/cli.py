"""``vera`` command line: scan local paths and write a CycloneDX CBOM.

A thin wrapper over the existing engine: the same ``/api/scan/local`` and
``/api/cbom`` code paths the server uses, run in-process.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

KINDS = ("source", "binary", "config", "keystore", "dependency", "image")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vera", description="V.E.R.A. cryptographic discovery -> CycloneDX CBOM.")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan local paths and write a CBOM")
    for k in KINDS:
        s.add_argument(f"--{k}", action="append", default=[], metavar="PATH", help=f"{k} path (repeatable)")
    s.add_argument("--spec", choices=("1.7", "1.6"), default="1.7", help="CycloneDX spec version")
    s.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    sv = sub.add_parser("serve", help="run the API server (needs vera-cbom[server])")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sub.add_parser("version", help="print versions")
    return p


def _prepare_env() -> None:
    """Keep writable state out of site-packages."""
    home = Path(os.environ.get("VERA_HOME") or Path.home() / ".vera")
    home.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("VERA_DB_PATH", str(home / "vera.db"))
    os.environ.setdefault("VERA_SIGNING_DIR", str(home / "signing"))


def _scan(args) -> int:
    paths = {k: getattr(args, k) for k in KINDS}
    if not any(paths.values()):
        print("vera scan: give at least one of " + ", ".join(f"--{k}" for k in KINDS), file=sys.stderr)
        return 2
    _prepare_env()
    # A one-shot scan uses a throwaway database so repeated runs do not accumulate state.
    os.environ["VERA_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="vera-")) / "vera.db")
    os.environ.setdefault("VERA_AUTH", "0")
    os.environ.setdefault("VERA_OFFLINE", "1")
    from fastapi.testclient import TestClient

    import main  # engine module, resolved via vera_cbom._backend

    client = TestClient(main.app)
    params = [(f"{k}_paths", str(Path(v))) for k, vs in paths.items() for v in vs]
    r = client.post("/api/scan/local", params=params)
    if r.status_code != 200:
        print(f"vera scan: {r.status_code} {r.text}", file=sys.stderr)
        return 1
    c = client.get("/api/cbom", params={"spec": args.spec})
    if c.status_code != 200:
        print(f"vera scan: CBOM export failed: {c.status_code} {c.text}", file=sys.stderr)
        return 1
    if args.output == "-":
        sys.stdout.write(c.text + "\n")
    else:
        Path(args.output).write_text(c.text, encoding="utf-8")
        n = len(json.loads(c.text).get("components", []))
        print(f"vera: wrote {args.output} ({n} components, CycloneDX {args.spec})", file=sys.stderr)
    return 0


def _serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("vera serve needs the server extra: pip install 'vera-cbom[server]'", file=sys.stderr)
        return 1
    _prepare_env()
    import main

    uvicorn.run(main.app, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    import vera_cbom  # puts the engine on sys.path

    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return _scan(args)
    if args.cmd == "serve":
        return _serve(args)
    if args.cmd == "version":
        from engine.version import TOOL_NAME, TOOL_VERSION

        print(f"vera-cbom {vera_cbom.__version__} ({TOOL_NAME} engine {TOOL_VERSION})")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
