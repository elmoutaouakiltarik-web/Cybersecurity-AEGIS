"""Baseline dell'impianto e confronto nel tempo.

Il valore operativo di un assessment non e' il report una tantum, ma il
confronto: *cosa e' cambiato* da quando l'impianto era "pulito". Con una
baseline salvata, ogni nuova esecuzione evidenzia in pochi secondi device
nuovi, porte comparse e firmware cambiati.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .models import AssessmentResult, utcnow_iso

LOGGER = logging.getLogger("aegis.site.baseline")

BASELINE_VERSION = 1


def snapshot(result: AssessmentResult) -> Dict[str, Any]:
    """Riduce un assessment a cio' che conta per il confronto."""
    return {
        "version": BASELINE_VERSION,
        "generated_at": utcnow_iso(),
        "site": result.site,
        "client": result.client,
        "assessment_id": result.id,
        "assets": [
            {
                "ip": a.ip,
                "mac": a.mac,
                "hostname": a.hostname,
                "vendor": a.vendor,
                "device_type": a.device_type,
                "model": a.model,
                "firmware": a.firmware,
                "purdue_level": a.purdue_level,
                "zone": a.zone,
                "protocols": sorted(a.protocols),
                "ports": sorted(
                    [{"port": p.port, "proto": p.proto, "service": p.service}
                     for p in a.ports if p.state == "open"],
                    key=lambda p: p["port"],
                ),
            }
            for a in sorted(result.assets, key=lambda x: x.ip)
        ],
        "finding_ids": sorted({f.id for f in result.findings}),
        "protocol_counts": _protocol_counts(result),
    }


def _protocol_counts(result: AssessmentResult) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for conversation in result.conversations:
        if conversation.ot_protocol:
            counts[conversation.ot_protocol] = counts.get(conversation.ot_protocol, 0) + conversation.packets
    return counts


def save(result: AssessmentResult, path: str) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot(result), indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("Baseline salvata in %s", target)
    return str(target)


def load(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Confronta due snapshot e ritorna le differenze rilevanti."""
    base_assets = {a["ip"]: a for a in baseline.get("assets", [])}
    curr_assets = {a["ip"]: a for a in current.get("assets", [])}

    new_assets = [
        {"ip": ip, "label": a.get("hostname") or a.get("vendor") or ip}
        for ip, a in curr_assets.items() if ip not in base_assets
    ]
    removed_assets = [
        {"ip": ip, "label": a.get("hostname") or a.get("vendor") or ip}
        for ip, a in base_assets.items() if ip not in curr_assets
    ]

    new_ports: List[Dict[str, Any]] = []
    closed_ports: List[Dict[str, Any]] = []
    changed_identities: List[Dict[str, Any]] = []
    for ip, current_asset in curr_assets.items():
        previous = base_assets.get(ip)
        if not previous:
            continue
        prev_ports = {(p["port"], p.get("proto", "tcp")): p for p in previous.get("ports", [])}
        curr_ports = {(p["port"], p.get("proto", "tcp")): p for p in current_asset.get("ports", [])}
        for key, port in curr_ports.items():
            if key not in prev_ports:
                new_ports.append({"ip": ip, "port": port["port"], "service": port.get("service", "")})
        for key, port in prev_ports.items():
            if key not in curr_ports:
                closed_ports.append({"ip": ip, "port": port["port"], "service": port.get("service", "")})

        for field_name in ("firmware", "model", "vendor", "device_type"):
            before = str(previous.get(field_name, "") or "")
            after = str(current_asset.get(field_name, "") or "")
            if before and after and before != after:
                changed_identities.append(
                    {"ip": ip, "field": field_name, "before": before, "after": after}
                )

    base_findings = set(baseline.get("finding_ids", []))
    curr_findings = set(current.get("finding_ids", []))
    new_findings = sorted(curr_findings - base_findings)

    has_drift = bool(new_assets or removed_assets or new_ports or changed_identities)
    return {
        "generated_at": utcnow_iso(),
        "baseline_generated_at": baseline.get("generated_at", ""),
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "changed_identities": changed_identities,
        "new_findings": new_findings,
        "has_drift": has_drift,
        "summary": _summary(new_assets, removed_assets, new_ports, changed_identities),
    }


def _summary(new_assets: List[Dict[str, Any]], removed: List[Dict[str, Any]],
             new_ports: List[Dict[str, Any]], changed: List[Dict[str, Any]]) -> str:
    if not (new_assets or removed or new_ports or changed):
        return "Nessuna differenza rispetto alla baseline."
    parts = []
    if new_assets:
        parts.append(f"{len(new_assets)} nuovi asset")
    if removed:
        parts.append(f"{len(removed)} asset scomparsi")
    if new_ports:
        parts.append(f"{len(new_ports)} nuove porte")
    if changed:
        parts.append(f"{len(changed)} identita' cambiate")
    return "Drift rilevato: " + ", ".join(parts) + "."


def diff_with_file(result: AssessmentResult, path: str) -> Dict[str, Any]:
    baseline = load(path)
    return diff(baseline, snapshot(result))
