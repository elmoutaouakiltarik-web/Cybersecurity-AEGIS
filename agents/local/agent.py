#!/usr/bin/env python3
"""Cybersecurity-AEGIS local endpoint agent.

Collects safe local telemetry and sends normalized defensive events to the
orchestrator. Expensive or sensitive scans are opt-in through environment
variables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore


# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger("aegis.agent")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SystemCollector:
    def collect(self) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "timestamp": now_iso(),
        }
        if psutil is None:
            return base
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(str(Path.home().anchor or "/"))
        base.update(
            {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "process_count": len(psutil.pids()),
                "boot_time": psutil.boot_time(),
            }
        )
        return base


class FileIntegrityMonitor:
    def __init__(self, db_path: Path, paths: Iterable[str]) -> None:
        self.db_path = db_path
        self.paths = [Path(path.strip()) for path in paths if path.strip()]
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_hashes (
                    path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    checked_at TEXT NOT NULL
                )
                """
            )

    def check(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        with sqlite3.connect(self.db_path) as conn:
            for path in self.paths:
                if not path.exists() or not path.is_file():
                    continue
                digest = sha256_file(path)
                stat = path.stat()
                row = conn.execute("SELECT sha256, mtime FROM file_hashes WHERE path = ?", (str(path),)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO file_hashes VALUES (?, ?, ?, ?, ?)",
                        (str(path), digest, stat.st_size, stat.st_mtime, now_iso()),
                    )
                    continue
                if row[0] != digest:
                    finding = {
                        "path": str(path),
                        "old_hash": row[0],
                        "new_hash": digest,
                        "old_mtime": row[1],
                        "new_mtime": stat.st_mtime,
                    }
                    findings.append(finding)
                    conn.execute(
                        "UPDATE file_hashes SET sha256 = ?, size = ?, mtime = ?, checked_at = ? WHERE path = ?",
                        (digest, stat.st_size, stat.st_mtime, now_iso(), str(path)),
                    )
        return findings


class OSQueryCollector:
    def __init__(self) -> None:
        self.binary = find_binary("osqueryi")

    def run_basic_hunts(self) -> List[Dict[str, Any]]:
        if not self.binary:
            return []
        queries = {
            "listening_ports": "SELECT pid, port, protocol, address FROM listening_ports LIMIT 50;",
            "suspicious_process_paths": (
                "SELECT pid, name, path, cmdline FROM processes "
                "WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' LIMIT 25;"
            ),
        }
        findings: List[Dict[str, Any]] = []
        for name, query in queries.items():
            try:
                result = subprocess.run(
                    [self.binary, "--json", query],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0 and result.stdout.strip():
                try:
                    rows = json.loads(result.stdout)
                except json.JSONDecodeError:
                    rows = []
                if rows:
                    findings.append({"query": name, "rows": rows[:10], "count": len(rows)})
        return findings


class CybersecurityAegisAgent:
    def __init__(self, orchestrator_url: str, state_dir: Path) -> None:
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self.system = SystemCollector()
        self.osquery = OSQueryCollector()
        self.fim = FileIntegrityMonitor(state_dir / "fim.db", default_fim_paths())

    def run_once(self) -> Dict[str, Any]:
        telemetry = self.system.collect()
        LOGGER.info("telemetry %s", json.dumps(telemetry, sort_keys=True))

        fim_findings = self.fim.check()
        for finding in fim_findings:
            self.send_event(
                category="endpoint",
                severity="high",
                title=f"File integrity change: {finding['path']}",
                description="A monitored local file changed since the previous baseline.",
                raw_data=finding,
            )

        hunts = self.osquery.run_basic_hunts()
        for hunt in hunts:
            self.send_event(
                category="endpoint",
                severity="medium",
                title=f"OSQuery hunt results: {hunt['query']}",
                description=f"{hunt['count']} rows returned by defensive hunt query.",
                raw_data=hunt,
            )

        secret_scan_paths = parse_csv(os.getenv("AGENT_SECRET_SCAN_PATHS", ""))
        secret_findings = run_secret_scanners(secret_scan_paths)
        for finding in secret_findings:
            self.send_event(
                category="identity",
                severity="high",
                title=f"Potential exposed secret found by {finding['tool']}",
                description="A local opt-in secret scanner reported a finding.",
                raw_data=finding,
            )

        return {
            "telemetry": telemetry,
            "fim_findings": len(fim_findings),
            "osquery_hunts": len(hunts),
            "secret_findings": len(secret_findings),
        }

    def send_event(self, category: str, severity: str, title: str, description: str, raw_data: Dict[str, Any]) -> None:
        payload = {
            "source": "local_agent",
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "tags": ["agent", category],
            "raw_data": raw_data,
        }
        if requests is None:
            LOGGER.info("event %s", json.dumps(payload, sort_keys=True))
            return
        try:
            requests.post(f"{self.orchestrator_url}/api/v1/ingest/generic", json=payload, timeout=3, headers=_INGEST_HEADERS)
        except Exception as exc:  # pragma: no cover - network dependent
            LOGGER.debug("orchestrator ingest failed: %s", exc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_fim_paths() -> List[str]:
    configured = parse_csv(os.getenv("AGENT_FIM_PATHS", ""))
    if configured:
        return configured
    if os.name == "nt":
        return [r"C:\Windows\System32\drivers\etc\hosts"]
    return ["/etc/passwd", "/etc/hosts", "/etc/ssh/sshd_config"]


def parse_csv(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def find_binary(name: str) -> Optional[str]:
    path_dirs = os.getenv("PATH", "").split(os.pathsep)
    extensions = [""]
    if os.name == "nt":
        extensions.extend([".exe", ".bat", ".cmd"])
    for folder in path_dirs:
        for ext in extensions:
            candidate = Path(folder) / f"{name}{ext}"
            if candidate.exists() and candidate.is_file():
                return str(candidate)
    return None


def run_secret_scanners(paths: Iterable[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in paths:
        for tool, command in scanner_commands(path).items():
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if not result.stdout.strip():
                continue
            findings.append({"tool": tool, "path": path, "summary": result.stdout[:2000]})
    return findings


def scanner_commands(path: str) -> Dict[str, List[str]]:
    commands: Dict[str, List[str]] = {}
    gitleaks = find_binary("gitleaks")
    if gitleaks:
        commands["gitleaks"] = [gitleaks, "detect", "--source", path, "--no-git", "--redact", "--verbose"]
    trufflehog = find_binary("trufflehog")
    if trufflehog:
        commands["trufflehog"] = [trufflehog, "filesystem", path, "--no-update", "--json"]
    return commands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cybersecurity-AEGIS local endpoint agent")
    parser.add_argument("--orchestrator-url", default=os.getenv("ORCHESTRATOR_URL", "http://localhost:8080"))
    parser.add_argument("--state-dir", default=os.getenv("AGENT_STATE_DIR", ".aegis/agent"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("AGENT_INTERVAL_SECONDS", "60")))
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", os.getenv("CYBERFORGE_LOG_LEVEL", "INFO")).upper()
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args()
    agent = CybersecurityAegisAgent(args.orchestrator_url, Path(args.state_dir))
    if args.once:
        result = agent.run_once()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    while True:
        agent.run_once()
        time.sleep(max(args.interval, 5))


if __name__ == "__main__":
    raise SystemExit(main())
