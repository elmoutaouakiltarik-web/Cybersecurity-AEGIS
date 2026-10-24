"""sys.path bootstrap per i test del modulo network (import da script standalone)."""
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_MOD_DIR = str(_HERE.parent)
if _MOD_DIR not in sys.path:
    sys.path.insert(0, _MOD_DIR)
