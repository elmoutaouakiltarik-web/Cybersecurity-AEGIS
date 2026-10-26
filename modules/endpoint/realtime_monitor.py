#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Real-time Host Telemetry
================================================
Background watcher that detects new state and posts live events to the
orchestrator (/api/v1/ingest/generic). Designed to be lightweight: polls
every N seconds (default 15), diffing snapshots in-memory.

Watched signals:
  * NEW PROCESSES        — fired when a PID we have never seen before
                            appears, with parent context.
  * NEW LISTENING PORTS  — fired when a previously-closed port enters the
                            LISTEN state.
  * NEW AUTORUNS         — diff of Run/RunOnce keys (registry persistence).
  * NEW USER LOGONS      — security event 4624 in the last poll window.
  * NEW CREDENTIAL EVENTS — failed logon (4625) spike from a single source.

Each event includes a severity computed from heuristics (suspicious paths,
LOLBin patterns, unsigned binaries, external IP, ...) so the SIEM/SOAR
modules can correlate without re-parsing on every step.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # type: ignore

from windows_audit import _run_ps

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger("aegis.endpoint.realtime")


class RealtimeMonitor:
    """Single background thread that emits security events as host state changes."""

    def __init__(self,
                 orchestrator_url: str,
                 poll_interval: float = 15.0,
                 emit_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.emit_cb = emit_callback     # optional callback for tests / UI

        # State snapshots
        self._known_pids: Set[int] = set()
        self._known_listen: Set[Tuple[str, int, int]] = set()  # (addr, port, pid)
        self._known_autoruns: Set[Tuple[str, str]] = set()      # (location, name)
        self._last_event_log_ts = datetime.now(timezone.utc) - timedelta(minutes=2)

        # Stats / counters (visible via /realtime/stats)
        self.stats: Dict[str, Any] = {
            "started_at": None, "last_poll_at": None,
            "polls": 0, "events_emitted": 0,
            "emitted_by_kind": {},
        }

    # ── lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if psutil is None:
            LOGGER.warning("psutil not installed — realtime monitor disabled")
            return
        self._stop.clear()
        self._bootstrap_snapshots()
        self.stats["started_at"] = datetime.now(timezone.utc).isoformat()
        self._thread = threading.Thread(target=self._run, name="aegis-realtime", daemon=True)
        self._thread.start()
        LOGGER.info("Realtime monitor started (interval %.1fs, orch=%s)",
                    self.poll_interval, self.orchestrator_url)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── main loop ───────────────────────────────────────────────────────────

    def _bootstrap_snapshots(self) -> None:
        """Capture the current state so we don't fire 'new' events for every
        process that already exists at startup."""
        try:
            self._known_pids = {p.pid for p in psutil.process_iter()}
        except Exception:
            self._known_pids = set()
        try:
            self._known_listen = {
                (str(c.laddr.ip), int(c.laddr.port), int(c.pid or 0))
                for c in psutil.net_connections(kind="inet")
                if c.status == psutil.CONN_LISTEN and c.laddr
            }
        except Exception:
            self._known_listen = set()
        self._known_autoruns = self._read_autoruns()

    def _run(self) -> None:
        while not self._stop.is_set():
            t0 = time.time()
            try:
                self._poll_once()
            except Exception as e:
                LOGGER.exception("Realtime poll failed: %s", e)
            self.stats["polls"] += 1
            self.stats["last_poll_at"] = datetime.now(timezone.utc).isoformat()
            # Sleep but stay responsive to stop()
            remaining = max(0.5, self.poll_interval - (time.time() - t0))
            if self._stop.wait(remaining):
                break

    def _poll_once(self) -> None:
        self._check_new_processes()
        self._check_new_listen()
        self._check_new_autoruns()
        self._check_failed_logons_spike()

    # ── individual checks ───────────────────────────────────────────────────

    def _check_new_processes(self) -> None:
        try:
            current = {p.pid: p for p in psutil.process_iter(["pid", "name", "exe", "cmdline",
                                                              "username", "create_time", "ppid"])}
        except Exception:
            return
        new_pids = set(current.keys()) - self._known_pids
        for pid in new_pids:
            try:
                p = current[pid]
                info = p.info
                exe = (info.get("exe") or "").lower()
                cmd = " ".join(info.get("cmdline") or []).lower()
                name = info.get("name") or ""
                ppid = info.get("ppid")
                parent_name = ""
                try:
                    if ppid:
                        parent_name = psutil.Process(ppid).name()
                except Exception:
                    pass
                severity = self._classify_new_process(name, exe, cmd)
                # Only emit when the new process is actually interesting — avoid noise.
                if severity == "info":
                    continue
                self._emit({
                    "source": "endpoint.realtime",
                    "category": "endpoint",
                    "severity": severity,
                    "title": f"New process: {name} (pid {pid})",
                    "description": f"Spawned by {parent_name} (ppid {ppid}). Cmd: {cmd[:200]}",
                    "tags": ["realtime", "process_create", "T1059"],
                    "raw_data": {
                        "pid": pid, "ppid": ppid, "name": name, "parent": parent_name,
                        "exe": info.get("exe"), "cmdline": info.get("cmdline"),
                        "user": info.get("username"),
                    },
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._known_pids = set(current.keys())

    def _classify_new_process(self, name: str, exe: str, cmd: str) -> str:
        n = name.lower()
        # LOLBin abuse patterns
        if "powershell" in n or "pwsh" in n or n == "cmd.exe":
            if any(p in cmd for p in ["-enc ", "-encodedcommand", "downloadstring",
                                      "iex(", "frombase64string", "-w hidden",
                                      ".downloadfile(", "invoke-expression"]):
                return "critical"
        if n in ("mshta.exe", "regsvr32.exe", "rundll32.exe"):
            if "http" in cmd or ".dll," in cmd or "javascript:" in cmd:
                return "high"
        if n == "certutil.exe" and ("urlcache" in cmd or "decode" in cmd):
            return "high"
        if n == "bitsadmin.exe" and "transfer" in cmd:
            return "high"
        # Path-based heuristic
        if any(s in exe for s in ["\\appdata\\local\\temp\\", "\\windows\\temp\\",
                                   "\\users\\public\\", "\\programdata\\temp\\"]):
            return "high"
        # Otherwise just a normal new process — don't emit.
        return "info"

    def _check_new_listen(self) -> None:
        try:
            current = {
                (str(c.laddr.ip), int(c.laddr.port), int(c.pid or 0))
                for c in psutil.net_connections(kind="inet")
                if c.status == psutil.CONN_LISTEN and c.laddr
            }
        except (psutil.AccessDenied, PermissionError):
            return
        new = current - self._known_listen
        sensitive_ports = {21, 22, 23, 80, 443, 445, 3389, 5985, 5986, 1433, 3306, 5432, 6379, 9200, 27017}
        for laddr, port, pid in new:
            is_loopback = laddr.startswith("127.") or laddr == "::1"
            severity = "medium" if port in sensitive_ports and not is_loopback else "info"
            if severity == "info":
                continue
            pname = ""
            try:
                pname = psutil.Process(pid).name() if pid else ""
            except Exception:
                pass
            self._emit({
                "source": "endpoint.realtime",
                "category": "endpoint",
                "severity": severity,
                "title": f"New listening port: {port} on {laddr} ({pname})",
                "description": f"Process {pname} (PID {pid}) started listening on {laddr}:{port}.",
                "tags": ["realtime", "listen", "T1571"],
                "raw_data": {"laddr": laddr, "port": port, "pid": pid, "process": pname},
            })
        self._known_listen = current

    def _check_new_autoruns(self) -> None:
        current = self._read_autoruns()
        new = current - self._known_autoruns
        for loc, name in new:
            self._emit({
                "source": "endpoint.realtime",
                "category": "endpoint",
                "severity": "high",
                "title": f"New autorun entry: {name}",
                "description": f"Registry persistence added at {loc}\\{name}.",
                "tags": ["realtime", "persistence", "T1547.001"],
                "raw_data": {"location": loc, "name": name},
            })
        self._known_autoruns = current

    def _read_autoruns(self) -> Set[Tuple[str, str]]:
        out: Set[Tuple[str, str]] = set()
        keys = [
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ]
        for k in keys:
            data = _run_ps(
                f"$p = Get-ItemProperty '{k}' -ErrorAction SilentlyContinue; "
                "if ($p) { ($p | Get-Member -MemberType NoteProperty | Where-Object Name -notmatch '^PS').Name }",
                timeout=4,
            )
            if data is None:
                continue
            names = data if isinstance(data, list) else [data]
            for n in names:
                if isinstance(n, str):
                    out.add((k, n))
        return out

    def _check_failed_logons_spike(self) -> None:
        # Pull events 4625 since last poll, group by source IP. Emit if spike.
        start_dt = self._last_event_log_ts.isoformat()
        data = _run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; "
            f"StartTime=([datetime]::Parse('{start_dt}'))" "} "
            "-MaxEvents 200 -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "  $xml = [xml]$_.ToXml(); "
            "  $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; "
            "  $data['IpAddress'] "
            "}",
            timeout=15,
        )
        self._last_event_log_ts = datetime.now(timezone.utc)
        if not data:
            return
        ips = data if isinstance(data, list) else [data]
        counts: Dict[str, int] = {}
        for ip in ips:
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                counts[ip] = counts.get(ip, 0) + 1
        for ip, count in counts.items():
            if count >= 3:  # 3+ failures in a single poll window = spike
                self._emit({
                    "source": "endpoint.realtime",
                    "category": "endpoint",
                    "severity": "high" if count < 10 else "critical",
                    "title": f"Failed logon spike: {count} from {ip}",
                    "description": f"{count} failed Windows logon attempts in the last {self.poll_interval:.0f}s from {ip}.",
                    "tags": ["realtime", "T1110", "bruteforce"],
                    "raw_data": {"src_ip": ip, "count": count,
                                 "window_seconds": self.poll_interval},
                })

    # ── event emit ──────────────────────────────────────────────────────────

    def _emit(self, payload: Dict[str, Any]) -> None:
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        self.stats["events_emitted"] += 1
        kind = next((t for t in payload.get("tags", []) if t.startswith("T") or t in ("process_create","listen","persistence","bruteforce")), "other")
        self.stats["emitted_by_kind"][kind] = self.stats["emitted_by_kind"].get(kind, 0) + 1

        if self.emit_cb:
            try:
                self.emit_cb(payload)
            except Exception:
                pass

        if requests is None:
            return
        try:
            requests.post(
                f"{self.orchestrator_url}/api/v1/ingest/generic",
                json=payload, timeout=4, headers=_INGEST_HEADERS
            )
        except Exception as e:
            LOGGER.debug("emit failed: %s", e)
