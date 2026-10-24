"""Bootstrap dei test: rende importabile il pacchetto `site_assessment`.

Il conftest della radice aggiunge `modules/industrial` a sys.path, ma quando
pytest viene lanciato su piu' directory il rootdir puo' cambiare. Qui la
dipendenza e' esplicita, cosi' i test funzionano anche da soli.
"""
import pathlib
import sys

_INDUSTRIAL = pathlib.Path(__file__).resolve().parents[2]
if str(_INDUSTRIAL) not in sys.path:
    sys.path.insert(0, str(_INDUSTRIAL))
