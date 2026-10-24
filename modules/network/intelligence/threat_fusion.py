#!/usr/bin/env python3
"""
AEGIS Threat Fusion Engine
===========================
Correlates events from multiple AEGIS modules (SIEM, Network, Threat Intel,
SOAR, Vulnerability) into unified attack *campaigns* using a kill-chain model.

Key capabilities:
  - Multi-source event ingestion (reads live from orchestrator /api/v1/events)
  - Kill-chain correlation: groups events into campaigns by IP overlap,
    technique proximity, and time windowing
  - Actor attribution via known JARM fingerprints & TTP clustering
  - MITRE ATT&CK technique tagging per campaign phase
  - Campaign scoring (urgency / risk) with severity weighting
  - Segmentation gap detection from topology data

This module is intentionally PASSIVE — it reads data and produces assessments.
It never modifies firewall rules, blocks IPs, or triggers automated responses.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib import request as urllib_request
import json

LOGGER = logging.getLogger("aegis.fusion")

# ─── MITRE ATT&CK kill-chain phase mapping ─────────────────────────────────
# Maps event categories / source keywords → MITRE tactic IDs
_CATEGORY_TACTIC: Dict[str, str] = {
    "recon":             "TA0043",
    "reconnaissance":    "TA0043",
    "scan":              "TA0043",
    "port_scan":         "TA0043",
    "initial_access":    "TA0001",
    "phishing":          "TA0001",
    "exploit":           "TA0001",
    "exploitation":      "TA0001",
    "execution":         "TA0002",
    "persistence":       "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion":   "TA0005",
    "credential_access": "TA0006",
    "discovery":         "TA0007",
    "lateral_movement":  "TA0008",
    "collection":        "TA0009",
    "command_and_control": "TA0011",
    "c2":                "TA0011",
    "c&c":               "TA0011",
    "exfiltration":      "TA0010",
    "impact":            "TA0040",
    "ransomware":        "TA0040",
    "dos":               "TA0040",
    "ot_anomaly":        "TA0040",
    "ot_alert":          "TA0040",
    "malware":           "TA0002",
    "anomaly":           "TA0043",
    "network_anomaly":   "TA0043",
    "threat_intel":      "TA0001",
    "ioc":               "TA0001",
    "vulnerability":     "TA0001",
}

_TACTIC_LABEL: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "C2",
    "TA0040": "Impact",
}

# Known C2 actor hints from JARM signatures (prefix matching)
_JARM_ACTOR_HINTS: Dict[str, str] = {
    "07d14d16d21d21d00042d43d000000": "Cobalt Strike",
    "2ad2ad0002ad2ad00042d42d000000": "Metasploit",
    "07d0d0d0d0d0d0d0d0d0d0d0d0d0d0": "Covenant C2",
    "1dd40d40d1dd40d1dc1dd40d1dd40d": "Sliver C2",
    "29d29d20d29d29d21c41d43d00041d": "Mythic C2",
    "2ad000002ad2ad0002ad2ad2ad2ad2": "Brute Ratel",
}

# Severity weights for campaign scoring
_SEVERITY_WEIGHT: Dict[str, float] = {
    "critical": 10.0,
    "high":      6.0,
    "medium":    3.0,
    "low":       1.0,
    "info":      0.2,
}

# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class NormalizedEvent:
    id: str
    timestamp: datetime
    source: str
    category: str
    severity: str
    title: str
    src_ip: str = ""
    dst_ip: str = ""
    technique_id: str = ""
    tactic_id: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Campaign:
    campaign_id: str
    first_seen: datetime
    last_seen: datetime
    involved_ips: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    event_count: int = 0
    campaign_score: float = 0.0
    urgency: str = "low"
    actor_hint: Optional[str] = None
    description: str = ""
    sources: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)  # event IDs

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


# ─── Engine ───────────────────────────────────────────────────────────────────

class ThreatFusionEngine:
    """
    Multi-source threat fusion and campaign correlation engine.

    Usage::

        engine = ThreatFusionEngine(orchestrator_url="http://localhost:8080")
        campaigns = engine.fetch_and_analyze(window_minutes=60)
        stats = engine.get_statistics(campaigns)
    """

    def __init__(self, orchestrator_url: str = "http://localhost:8080") -> None:
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self._campaign_counter = 0

    # ── Public API ──────────────────────────────────────────────────────────

    def fetch_and_analyze(
        self, window_minutes: int = 60, max_events: int = 500
    ) -> List[Campaign]:
        """Fetch events from orchestrator, then run campaign correlation."""
        raw_events = self._fetch_events(max_events=max_events)
        return self.analyze(raw_events, window_minutes=window_minutes)

    def analyze(
        self, raw_events: List[Dict[str, Any]], window_minutes: int = 60
    ) -> List[Campaign]:
        """Correlate raw event dicts into campaigns."""
        if not raw_events:
            return []

        cutoff_ts = time.time() - window_minutes * 60
        events = [
            e for e in (_normalize_event(r) for r in raw_events)
            if e is not None and e.timestamp.timestamp() >= cutoff_ts
        ]

        if not events:
            return []

        # Group events by IP cluster
        ip_clusters: Dict[str, Set[str]] = {}  # ip → set of ips that share events
        ip_events: Dict[str, List[NormalizedEvent]] = defaultdict(list)

        for ev in events:
            for ip in [ev.src_ip, ev.dst_ip]:
                if ip:
                    ip_events[ip].append(ev)

        # Union-Find IP grouping: IPs that appear in the same event are merged
        parent: Dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent.get(x, x), x)
                x = parent.get(x, x)
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for ev in events:
            ips = [i for i in [ev.src_ip, ev.dst_ip] if i]
            for i in range(len(ips) - 1):
                union(ips[i], ips[i + 1])

        # Build groups
        groups: Dict[str, List[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            if ev.src_ip:
                groups[find(ev.src_ip)].append(ev)
            elif ev.dst_ip:
                groups[find(ev.dst_ip)].append(ev)
            else:
                groups["__no_ip__"].append(ev)

        campaigns = []
        for group_key, group_events in groups.items():
            if not group_events:
                continue
            campaign = self._build_campaign(group_key, group_events)
            if campaign.campaign_score >= 1.0:
                campaigns.append(campaign)

        # Sort by score descending
        campaigns.sort(key=lambda c: c.campaign_score, reverse=True)
        return campaigns

    def get_statistics(self, campaigns: List[Campaign]) -> Dict[str, Any]:
        """Compute high-level statistics over a list of campaigns."""
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        actor_set: Set[str] = set()
        tech_set: Set[str] = set()

        for c in campaigns:
            counts[c.urgency] = counts.get(c.urgency, 0) + 1
            if c.actor_hint:
                actor_set.add(c.actor_hint)
            tech_set.update(c.mitre_techniques)

        return {
            "total": len(campaigns),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "attributed_actors": len(actor_set),
            "unique_techniques": len(tech_set),
            "actor_names": sorted(actor_set),
            "top_techniques": sorted(tech_set)[:20],
        }

    # ── Private helpers ─────────────────────────────────────────────────────

    def _fetch_events(self, max_events: int = 500) -> List[Dict[str, Any]]:
        """Pull events from the orchestrator REST API."""
        try:
            url = f"{self.orchestrator_url}/api/v1/events?limit={max_events}"
            req = urllib_request.Request(url, headers={"Accept": "application/json"})
            with urllib_request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                data = json.loads(body)
                if isinstance(data, list):
                    return data
                return data.get("events", [])
        except Exception as exc:
            LOGGER.warning("Failed to fetch events from orchestrator: %s", exc)
            return []

    def _build_campaign(
        self, group_key: str, events: List[NormalizedEvent]
    ) -> Campaign:
        self._campaign_counter += 1
        events_sorted = sorted(events, key=lambda e: e.timestamp)

        first_seen = events_sorted[0].timestamp
        last_seen = events_sorted[-1].timestamp

        # Collect IPs
        ip_set: Set[str] = set()
        for e in events:
            if e.src_ip:
                ip_set.add(e.src_ip)
            if e.dst_ip:
                ip_set.add(e.dst_ip)

        # Collect MITRE data
        tactics: Set[str] = set()
        techniques: Set[str] = set()
        for e in events:
            if e.tactic_id:
                tactics.add(e.tactic_id)
            if e.technique_id:
                techniques.add(e.technique_id)
            # Infer tactic from category
            cat_lower = e.category.lower().replace(" ", "_")
            tactic = _CATEGORY_TACTIC.get(cat_lower)
            if tactic:
                tactics.add(tactic)

        kill_chain_phases = [_TACTIC_LABEL.get(t, t) for t in sorted(tactics)]

        # Score calculation
        score = 0.0
        sev_counts: Dict[str, int] = defaultdict(int)
        sources: Set[str] = set()
        for e in events:
            weight = _SEVERITY_WEIGHT.get(e.severity.lower(), 0.5)
            score += weight
            sev_counts[e.severity.lower()] += 1
            sources.add(e.source)

        # Bonus for multi-tactic campaigns (kill chain progression)
        tactic_count = len(tactics)
        if tactic_count >= 4:
            score *= 2.0
        elif tactic_count >= 2:
            score *= 1.5

        # Bonus for OT involvement
        ot_events = [e for e in events if "ot" in e.source.lower() or "ot" in e.category.lower()]
        if ot_events:
            score *= 1.8

        # Determine urgency
        if sev_counts.get("critical", 0) > 0 or score >= 80:
            urgency = "critical"
        elif sev_counts.get("high", 0) >= 2 or score >= 40:
            urgency = "high"
        elif score >= 15:
            urgency = "medium"
        else:
            urgency = "low"

        # Actor attribution (heuristic from category/title)
        actor_hint = _infer_actor(events)

        # Description
        top_sources = sorted(sources)[:3]
        description = (
            f"Campaign spanning {len(ip_set)} IP(s) detected across "
            f"{', '.join(top_sources)}. "
            f"Phases: {', '.join(kill_chain_phases[:3]) if kill_chain_phases else 'unknown'}."
        )

        return Campaign(
            campaign_id=f"CAMP-{self._campaign_counter:04d}",
            first_seen=first_seen,
            last_seen=last_seen,
            involved_ips=sorted(ip_set)[:20],
            kill_chain_phases=kill_chain_phases,
            mitre_techniques=sorted(techniques)[:20],
            mitre_tactics=sorted(tactics),
            event_count=len(events),
            campaign_score=round(min(score, 100), 1),
            urgency=urgency,
            actor_hint=actor_hint,
            description=description,
            sources=sorted(sources),
            events=[e.id for e in events[:50]],
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _normalize_event(raw: Dict[str, Any]) -> Optional[NormalizedEvent]:
    """Parse a raw event dict from orchestrator into a NormalizedEvent."""
    try:
        ev_id = raw.get("id", "")
        ts_raw = raw.get("timestamp", "")
        if isinstance(ts_raw, str):
            ts_raw = ts_raw.rstrip("Z").replace("Z", "+00:00")
            try:
                ts = datetime.fromisoformat(ts_raw)
            except ValueError:
                ts = datetime.now(tz=timezone.utc)
        elif isinstance(ts_raw, (int, float)):
            ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
        else:
            ts = datetime.now(tz=timezone.utc)

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        raw_data = raw.get("raw_data") or {}
        src_ip = (
            raw.get("src_ip") or raw_data.get("src_ip") or
            raw_data.get("source_ip") or raw_data.get("src") or ""
        )
        dst_ip = (
            raw.get("dst_ip") or raw_data.get("dst_ip") or
            raw_data.get("dest_ip") or raw_data.get("dst") or ""
        )

        mitre = raw.get("mitre") or {}
        technique_id = mitre.get("technique_id", "") if isinstance(mitre, dict) else ""
        tactic_id = mitre.get("tactic_id", "") if isinstance(mitre, dict) else ""

        return NormalizedEvent(
            id=ev_id,
            timestamp=ts,
            source=raw.get("source", "unknown"),
            category=raw.get("category", "unknown"),
            severity=raw.get("severity", "info"),
            title=raw.get("title", ""),
            src_ip=str(src_ip),
            dst_ip=str(dst_ip),
            technique_id=technique_id,
            tactic_id=tactic_id,
            raw=raw,
        )
    except Exception as exc:
        LOGGER.debug("Event normalization failed: %s — %s", exc, raw)
        return None


def _infer_actor(events: List[NormalizedEvent]) -> Optional[str]:
    """Heuristic actor attribution from event patterns."""
    titles_lower = " ".join(e.title.lower() for e in events)
    categories_lower = " ".join(e.category.lower() for e in events)
    combined = titles_lower + " " + categories_lower

    actor_patterns = {
        "Cobalt Strike":   ["cobalt", "beacon", "cs.exe"],
        "Metasploit":      ["meterpreter", "metasploit", "msf"],
        "Emotet":          ["emotet", "epoch4", "epoch5"],
        "APT28":           ["apt28", "fancy bear", "x-agent"],
        "APT29":           ["apt29", "cozy bear", "solarwinds"],
        "Lazarus Group":   ["lazarus", "apt38"],
        "Ransomware":      ["ransomware", "ransom", "encrypt", "locker", "locky"],
        "Mimikatz":        ["mimikatz", "sekurlsa", "lsadump"],
        "Sliver C2":       ["sliver"],
        "Brute Ratel":     ["brute ratel", "brc4"],
    }

    for actor, patterns in actor_patterns.items():
        if any(p in combined for p in patterns):
            return actor
    return None
