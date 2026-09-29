"""Regenerate the synthetic vault and verify showcase invariants.

The vault files are ordinary outputs of demo/vault/make_vault.py — deterministic,
synthetic, no key material. This wrapper exists so a founder can refresh the
estate and confirm the CISO script still holds in one command, offline.

Run:  python demo/showcase/make_all.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHOWCASE = Path(__file__).resolve().parent
VAULT_MAKE = REPO_ROOT / "demo" / "vault" / "make_vault.py"


def _load_make_vault():
    spec = importlib.util.spec_from_file_location("make_vault", VAULT_MAKE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {VAULT_MAKE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    del argv  # make_vault takes no flags; run_demo reads sys.argv itself
    print("regenerating demo/vault …")
    _load_make_vault().main()
    print()
    if str(SHOWCASE) not in sys.path:
        sys.path.insert(0, str(SHOWCASE))
    import run_demo
    return run_demo.main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
