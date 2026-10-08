"""V.E.R.A. packaged for PyPI as ``vera-cbom``.

The engine is written as flat top-level modules (``engine``, ``collectors`` ...).
To avoid installing those generic names into site-packages, the wheel keeps them
under ``vera_cbom/_backend`` and importing this package puts that directory on
``sys.path``. Nothing about the engine's behaviour changes.
"""
import sys
from pathlib import Path

__version__ = "0.1.0"
BACKEND_DIR = Path(__file__).resolve().parent / "_backend"

# Source checkout (development): fall back to the repository's backend/.
if not BACKEND_DIR.is_dir():
    BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
