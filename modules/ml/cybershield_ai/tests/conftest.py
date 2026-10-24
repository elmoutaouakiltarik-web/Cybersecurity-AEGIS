"""sys.path bootstrap per i test del pacchetto cybershield_pro (layout src/)."""
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_PKG = _HERE.parent
_SRC = str(_PKG / "src")
for _p in (_SRC, str(_PKG)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
