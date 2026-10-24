"""Cybersecurity-AEGIS — Industrial Site Assessment.

Modulo per valutare la sicurezza di una rete industriale (fabbrica, linea,
cabina di trasformazione, depuratore, impianto di processo) con un approccio
sicuro per la produzione:

* **passivo prima di tutto**: analizza pcap o cattura live senza inviare nulla;
* **read-only sui protocolli di processo**: nessuna scrittura, nessun exploit;
* **autorizzazione obbligatoria**: senza riferimento scritto non parte nulla;
* **report diviso** tra interventi applicabili in produzione e interventi
  da pianificare in fermata.

Uso rapido da riga di comando (dalla cartella ``modules/industrial``)::

    python -m site_assessment preflight
    python -m site_assessment assess --site "Linea 2" --auth-ref "WO-2026-014" \\
        --target 192.168.10.0/24 --pcap cattura.pcapng --out reports/linea2
    python -m site_assessment selftest
"""
from __future__ import annotations

__version__ = "1.0.0"

_LAZY = {
    "AssessmentResult": (".models", "AssessmentResult"),
    "Asset": (".models", "Asset"),
    "Finding": (".models", "Finding"),
    "Engagement": (".safety", "Engagement"),
    "SafetyGuard": (".safety", "SafetyGuard"),
    "SiteAssessor": (".assessor", "SiteAssessor"),
    "PassiveAnalyzer": (".passive", "PassiveAnalyzer"),
    "RiskEngine": (".risk", "RiskEngine"),
}


def __getattr__(name: str):
    if name in _LAZY:
        module_name, attr = _LAZY[name]
        from importlib import import_module

        return getattr(import_module(module_name, __name__), attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["__version__", *sorted(_LAZY)]
