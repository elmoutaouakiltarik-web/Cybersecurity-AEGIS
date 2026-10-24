#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Live Threat Intelligence Feeds
=====================================================
Pulls real, public, free IOC feeds:
  - URLhaus       — malicious URLs (Abuse.ch)
  - Feodo Tracker — botnet C2 IPs (Abuse.ch)
  - MalwareBazaar — recent malware SHA-256 (Abuse.ch)
  - Tor Exit list — known Tor exit nodes (torproject.org)
  - Spamhaus DROP — hijacked/abusive networks (CIDR)

All downloads are cached on disk under <cache_dir>/iocs/. Re-fetches are
throttled by the freshness window (default 12h). Failures are logged and the
last-good cache is reused. No API keys required.

The IOC database is exposed via:
  GET  /ioc/feeds        — feed metadata + counts
  GET  /ioc/lookup?<...> — match an IP, domain, hash, or URL
"""
from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

LOGGER = logging.getLogger("aegis.endpoint.ioc")


@dataclass
class FeedSpec:
    feed_id: str
    name: str
    url: str
    kind: str               # ip | domain | url | hash | cidr
    description: str
    license: str = "free"
    headers: Dict[str, str] = field(default_factory=dict)


FEEDS: List[FeedSpec] = [
    FeedSpec(
        feed_id="abuse_urlhaus",
        name="Abuse.ch URLhaus (malicious URLs)",
        url="https://urlhaus.abuse.ch/downloads/text/",
        kind="url",
        description="Curated malicious URL list — distribution sites, payload URLs.",
    ),
    FeedSpec(
        feed_id="abuse_feodo",
        name="Abuse.ch Feodo Tracker C2",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        kind="ip",
        description="Active C2 IPs for Emotet, Dridex, Heodo, TrickBot, QakBot.",
    ),
    FeedSpec(
        feed_id="abuse_mb_recent",
        name="MalwareBazaar recent SHA-256",
        url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
        kind="hash",
        description="SHA-256 hashes of recent malware samples uploaded to MalwareBazaar.",
    ),
    FeedSpec(
        feed_id="tor_exit_nodes",
        name="Tor exit node list",
        url="https://check.torproject.org/torbulkexitlist",
        kind="ip",
        description="Current Tor exit relay IPs. Anonymising network — investigate inbound from these.",
    ),
    FeedSpec(
        feed_id="spamhaus_drop",
        name="Spamhaus DROP (hijacked/abusive nets)",
        url="https://www.spamhaus.org/drop/drop.txt",
        kind="cidr",
        description="Spamhaus 'Do not Route Or Peer' — hijacked or otherwise allocated to spammers.",
    ),
]


class IOCDatabase:
    """In-memory IOC store with disk-cached feed refresh."""

    def __init__(self, cache_dir: str, freshness_hours: int = 12,
                 max_per_feed: int = 200_000) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.freshness = timedelta(hours=freshness_hours)
        self.max_per_feed = max_per_feed
        self._lock = threading.RLock()

        # Indexes
        self.ips: Dict[str, str] = {}          # ip -> feed_id (or category)
        self.cidrs: List[Tuple[ipaddress._BaseNetwork, str]] = []
        self.domains: Dict[str, str] = {}      # domain -> feed_id
        self.urls: Set[str] = set()            # exact URLs
        self.hashes: Set[str] = set()
        self.feed_meta: Dict[str, Dict[str, Any]] = {}

        # Bootstrap from cache so we have something even if the network is down.
        self._load_cache()

    # ── Public lookups ──────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if ip in self.ips:
                return {"matched": True, "type": "ip", "value": ip, "feed": self.ips[ip]}
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, label in self.cidrs:
                try:
                    if addr in net:
                        return {"matched": True, "type": "cidr", "value": ip,
                                "network": str(net), "feed": label}
                except TypeError:
                    continue
            return None

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            d = domain.strip().lower().rstrip(".")
            if d in self.domains:
                return {"matched": True, "type": "domain", "value": d, "feed": self.domains[d]}
            # Wildcard-style parent match: bad.example.com matches example.com listing
            parts = d.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in self.domains:
                    return {"matched": True, "type": "domain_parent", "value": d,
                            "matched_on": parent, "feed": self.domains[parent]}
            return None

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            u = url.strip()
            if u in self.urls:
                return {"matched": True, "type": "url", "value": u, "feed": "abuse_urlhaus"}
            # Fallback: extract host and check domain index
            try:
                from urllib.parse import urlparse
                host = urlparse(u).hostname
                if host:
                    return self.lookup_domain(host)
            except Exception:
                pass
            return None

    def lookup_hash(self, h: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            hn = h.strip().lower()
            if hn in self.hashes:
                return {"matched": True, "type": "hash", "value": hn, "feed": "abuse_mb_recent"}
            return None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "ip_count": len(self.ips),
                "cidr_count": len(self.cidrs),
                "domain_count": len(self.domains),
                "url_count": len(self.urls),
                "hash_count": len(self.hashes),
                "feeds": list(self.feed_meta.values()),
            }

    # ── Refresh ─────────────────────────────────────────────────────────────

    def refresh_all(self, force: bool = False) -> Dict[str, Any]:
        """Re-download every feed that's stale."""
        results: Dict[str, Any] = {}
        for spec in FEEDS:
            try:
                results[spec.feed_id] = self.refresh_feed(spec, force=force)
            except Exception as e:
                LOGGER.exception("Feed %s refresh failed", spec.feed_id)
                results[spec.feed_id] = {"ok": False, "error": str(e)}
        self._rebuild_indexes()
        return {
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
            "per_feed": results,
            "stats": self.stats(),
        }

    def refresh_feed(self, spec: FeedSpec, force: bool = False) -> Dict[str, Any]:
        cache_file = self.cache_dir / f"{spec.feed_id}.txt"
        meta_file = self.cache_dir / f"{spec.feed_id}.meta.json"
        now = datetime.now(timezone.utc)
        if not force and cache_file.exists() and meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                last = datetime.fromisoformat(meta.get("fetched_at"))
                if now - last < self.freshness:
                    self.feed_meta[spec.feed_id] = meta
                    return {"ok": True, "skipped": True, "reason": "cache fresh",
                            "fetched_at": meta.get("fetched_at"), "rows": meta.get("rows", 0)}
            except Exception:
                pass

        LOGGER.info("Refreshing IOC feed %s from %s", spec.feed_id, spec.url)
        req = urllib.request.Request(spec.url, headers={
            "User-Agent": "Cybersecurity-AEGIS/1.0 (+defensive use)",
            **spec.headers,
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
        except urllib.error.URLError as e:
            return {"ok": False, "error": str(e), "fallback": "previous cache reused"}

        cache_file.write_bytes(data)
        rows = data.decode("utf-8", errors="replace").count("\n")
        meta = {
            "feed_id": spec.feed_id, "name": spec.name, "kind": spec.kind,
            "url": spec.url, "fetched_at": now.isoformat(),
            "size_bytes": len(data), "rows": rows,
            "description": spec.description, "license": spec.license,
        }
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self.feed_meta[spec.feed_id] = meta
        return {"ok": True, "skipped": False, "fetched_at": now.isoformat(),
                "size_bytes": len(data), "rows": rows}

    # ── Internals: parse and index cached files ─────────────────────────────

    def _load_cache(self) -> None:
        for spec in FEEDS:
            meta_file = self.cache_dir / f"{spec.feed_id}.meta.json"
            if meta_file.exists():
                try:
                    self.feed_meta[spec.feed_id] = json.loads(meta_file.read_text(encoding="utf-8"))
                except Exception:
                    pass
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        with self._lock:
            self.ips.clear()
            self.cidrs.clear()
            self.domains.clear()
            self.urls.clear()
            self.hashes.clear()
            for spec in FEEDS:
                cache_file = self.cache_dir / f"{spec.feed_id}.txt"
                if not cache_file.exists():
                    continue
                try:
                    text = cache_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                self._index_feed(spec, text)
            LOGGER.info(
                "IOC indexes rebuilt: %d IPs, %d CIDRs, %d domains, %d URLs, %d hashes",
                len(self.ips), len(self.cidrs), len(self.domains), len(self.urls), len(self.hashes),
            )

    def _index_feed(self, spec: FeedSpec, text: str) -> None:
        added = 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            if added >= self.max_per_feed:
                break
            try:
                if spec.kind == "ip":
                    ipaddress.ip_address(line)
                    self.ips[line] = spec.feed_id
                elif spec.kind == "cidr":
                    # Spamhaus DROP format: "192.0.2.0/24 ; SBL12345"
                    cidr = line.split()[0].split(";")[0].strip()
                    if "/" in cidr:
                        net = ipaddress.ip_network(cidr, strict=False)
                        self.cidrs.append((net, spec.feed_id))
                elif spec.kind == "domain":
                    self.domains[line.lower().rstrip(".")] = spec.feed_id
                elif spec.kind == "url":
                    self.urls.add(line)
                    # Also index the host of every URL so a domain lookup works.
                    try:
                        from urllib.parse import urlparse
                        host = urlparse(line).hostname
                        if host:
                            self.domains[host.lower()] = spec.feed_id
                    except Exception:
                        pass
                elif spec.kind == "hash":
                    if len(line) in (32, 40, 64):
                        self.hashes.add(line.lower())
                added += 1
            except Exception:
                continue
