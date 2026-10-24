"""Pytest bootstrap: rende importabili i pacchetti dei moduli AEGIS.

I test usano import diretti (es. `from lan_scanner import ...`) perché i
moduli girano come script standalone; questo conftest aggiunge le directory
dei moduli a sys.path così pytest li trova senza installazione.
"""
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent

_MODULE_DIRS = [
    _ROOT / "modules" / "network",
    _ROOT / "modules" / "industrial",
    _ROOT / "modules" / "ml" / "cybershield_ai",
    _ROOT / "modules" / "endpoint",
    _ROOT / "core" / "orchestrator",
]

for _dir in _MODULE_DIRS:
    if _dir.is_dir() and str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))
