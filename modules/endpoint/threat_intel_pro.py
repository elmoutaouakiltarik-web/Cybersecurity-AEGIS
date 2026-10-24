#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Professional Threat Intelligence
=======================================================
  - CISA KEV (Known Exploited Vulnerabilities) catalog — daily refresh
  - HIBP Pwned Passwords k-anonymity check
  - MITRE ATT&CK Navigator layer export from observed techniques
  - APT group lookup by technique
  - CT (Certificate Transparency) log lookup via crt.sh

All requests use public, free, no-auth APIs. K-anonymity protects HIBP
password lookups (we never send the password, only the first 5 chars of SHA-1).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("aegis.endpoint.threat_intel_pro")


# ──────────────────────────────────────────────────────────────────────────────
# CISA KEV — Known Exploited Vulnerabilities catalog
# ──────────────────────────────────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKevCatalog:
    """In-memory CISA KEV catalog with disk cache. Daily refresh."""

    def __init__(self, cache_dir: str) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cisa_kev.json"
        self.by_cve: Dict[str, Dict[str, Any]] = {}
        self.meta: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self._index(data)
        except Exception as e:
            LOGGER.warning("Failed to load CISA KEV cache: %s", e)

    def _index(self, data: Dict[str, Any]) -> None:
        vulns = data.get("vulnerabilities") or []
        with self._lock:
            self.by_cve.clear()
            for v in vulns:
                cve = (v.get("cveID") or "").upper()
                if cve:
                    self.by_cve[cve] = v
            self.meta = {
                "title":      data.get("title"),
                "catalog_version": data.get("catalogVersion"),
                "date_released":   data.get("dateReleased"),
                "count":           data.get("count") or len(vulns),
                "indexed_at":      datetime.now(timezone.utc).isoformat(),
            }

    def refresh(self, force: bool = False) -> Dict[str, Any]:
        # Daily freshness window
        if not force and self.cache_file.exists():
            age = time.time() - self.cache_file.stat().st_mtime
            if age < 24 * 3600:
                return {"ok": True, "skipped": True,
                        "reason": "cache fresh",
                        "meta": self.meta}
        req = urllib.request.Request(CISA_KEV_URL, headers={
            "User-Agent": "Cybersecurity-AEGIS/1.0 (+defensive)"
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        self.cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._index(data)
        return {"ok": True, "skipped": False, "meta": self.meta}

    def lookup(self, cve: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.by_cve.get(cve.upper())

    def search(self, vendor: str = "", product: str = "",
                days: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.by_cve.values())
        results = []
        cutoff = None
        if days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
        for v in items:
            if vendor and vendor.lower() not in (v.get("vendorProject") or "").lower():
                continue
            if product and product.lower() not in (v.get("product") or "").lower():
                continue
            if cutoff and (v.get("dateAdded") or "") < cutoff:
                continue
            results.append(v)
        results.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        return results

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "count": len(self.by_cve),
                "meta":  self.meta,
            }


# ──────────────────────────────────────────────────────────────────────────────
# HIBP Pwned Passwords — k-anonymity check
# The Have I Been Pwned API uses a k-anonymity model: client sends only the
# first 5 hex chars of the SHA-1 of the password, then matches the rest of
# the hash against the response locally. The plain password NEVER leaves
# this host.
# Endpoint: https://api.pwnedpasswords.com/range/<first 5 sha1 hex>
# ──────────────────────────────────────────────────────────────────────────────

HIBP_URL = "https://api.pwnedpasswords.com/range/"


def hibp_check_password(password: str) -> Dict[str, Any]:
    """Return {pwned: bool, count: int} for the given password using k-anonymity."""
    if not password:
        return {"error": "empty password"}
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = HIBP_URL + prefix
    req = urllib.request.Request(url, headers={
        "User-Agent": "Cybersecurity-AEGIS/1.0",
        "Add-Padding": "true",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
    except Exception as e:
        return {"error": f"HIBP API failed: {e}"}
    count = 0
    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
            break
    return {
        "pwned": count > 0,
        "count": count,
        "severity": "critical" if count > 1000 else "high" if count > 0 else "info",
        "advice": (
            "Password compromessa: trovata in dump pubblici. NON USARLA. "
            "Genera una passphrase nuova (4+ parole random) o usa un password manager."
        ) if count > 0 else "Password non trovata in dump noti. Continua a usare un password manager.",
        "method": "k-anonymity (SHA-1 prefix only; plain password mai trasmesso)",
    }


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Navigator layer export
# Produces a JSON file compatible with https://mitre-attack.github.io/attack-navigator/
# ──────────────────────────────────────────────────────────────────────────────

def navigator_layer_from_findings(findings: List[Dict[str, Any]],
                                    name: str = "AEGIS observed techniques",
                                    description: str = "Auto-generated") -> Dict[str, Any]:
    """Group findings by MITRE technique and build a Navigator layer."""
    techniques: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        tid = f.get("technique") or ""
        if not tid:
            continue
        tid = tid.upper().strip()
        # Strip ICS prefix variants
        if tid.startswith("ATTACK."):
            tid = tid[7:].upper()
        if not tid.startswith("T"):
            continue
        sev_w = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.get("severity", "info"), 0)
        if tid not in techniques:
            techniques[tid] = {"techniqueID": tid, "score": 0, "comment": "", "color": ""}
        techniques[tid]["score"] = max(techniques[tid]["score"], sev_w)
        existing_comment = techniques[tid]["comment"]
        new_comment = f.get("title", "")
        if new_comment and new_comment not in existing_comment:
            techniques[tid]["comment"] = (existing_comment + " | " + new_comment).strip(" |")[:1000]
    # Assign colors per score
    for t in techniques.values():
        s = t["score"]
        t["color"] = (
            "#cc0000" if s >= 4 else
            "#ff8800" if s == 3 else
            "#3399ff" if s == 2 else
            "#66cc66" if s == 1 else "#cccccc"
        )
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "5.0.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max"},
        "hideDisabled": False,
        "techniques": list(techniques.values()),
        "gradient": {"colors": ["#66cc66", "#ff8800", "#cc0000"], "minValue": 0, "maxValue": 4},
        "legendItems": [
            {"label": "Critical",    "color": "#cc0000"},
            {"label": "High",        "color": "#ff8800"},
            {"label": "Medium",      "color": "#3399ff"},
            {"label": "Low",         "color": "#66cc66"},
        ],
        "metadata": [
            {"name": "generator", "value": "AEGIS-OMNI"},
            {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
            {"name": "technique_count", "value": str(len(techniques))},
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# APT group lookup by technique (static MITRE Groups subset)
# ──────────────────────────────────────────────────────────────────────────────

APT_GROUPS = {
    "T1003": ["G0050 APT32", "G0007 APT28", "G0016 APT29", "G0096 APT41"],
    "T1059.001": ["G0007 APT28", "G0029 Lazarus", "G0050 APT32"],
    "T1071.001": ["G0016 APT29", "G0050 APT32", "G0007 APT28"],
    "T1078": ["G0016 APT29", "G0035 Dragonfly", "G0007 APT28"],
    "T1110": ["G0007 APT28", "G0035 Dragonfly", "G0061 FIN8"],
    "T1190": ["G0007 APT28", "G0125 HAFNIUM", "G0096 APT41"],
    "T1021.001": ["G0029 Lazarus", "G0050 APT32", "G0007 APT28"],
    "T1546.003": ["G0007 APT28", "G0064 APT33"],
    "T0855": ["G1006 Sandworm Team", "G0034 Sandworm", "G0049 OilRig"],
    "T0866": ["G1006 Sandworm Team", "G0035 Dragonfly"],
}


def apt_groups_for_technique(technique_id: str) -> List[str]:
    """Return the list of MITRE APT groups associated with this technique."""
    tid = technique_id.upper().strip()
    return APT_GROUPS.get(tid, [])


# ──────────────────────────────────────────────────────────────────────────────
# Certificate Transparency lookup (crt.sh) — find sub-domain leaks
# ──────────────────────────────────────────────────────────────────────────────

def crtsh_lookup(domain: str, max_results: int = 100) -> Dict[str, Any]:
    """Query crt.sh for all certificates issued for a domain.
    Useful to detect rogue / phishing certs on sub-domains.
    """
    if not domain:
        return {"error": "empty domain"}
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Cybersecurity-AEGIS/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": f"crt.sh HTTP {e.code}"}
    except Exception as e:
        return {"error": f"crt.sh failed: {e}"}
    seen_names = set()
    rows = []
    for entry in data[:1000]:
        name = entry.get("name_value", "").lower()
        for n in name.split("\n"):
            n = n.strip()
            if n and n not in seen_names:
                seen_names.add(n)
                rows.append({
                    "common_name": n,
                    "issuer":      entry.get("issuer_name", ""),
                    "not_before":  entry.get("not_before", ""),
                    "not_after":   entry.get("not_after", ""),
                    "id":          entry.get("id"),
                })
                if len(rows) >= max_results:
                    break
        if len(rows) >= max_results:
            break
    return {
        "domain":        domain,
        "total_unique":  len(seen_names),
        "results":       rows,
        "queried_at":    datetime.now(timezone.utc).isoformat(),
    }
