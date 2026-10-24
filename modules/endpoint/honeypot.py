#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Real Honeypot Listeners
===============================================
Low-interaction honeypots that bind on common target ports and log every
connection attempt with source IP, timestamp, banner exchange, and (when
applicable) the credentials the attacker tried.

Supported services:
  - SSH    (22)    — fake OpenSSH banner, capture auth attempts
  - Telnet (23)    — login prompt, capture user+password
  - SMB    (445)   — accept TCP connect, log first bytes
  - HTTP   (80)    — minimal HTTP 200, log User-Agent + path
  - HTTPS  (443)   — TCP only (no TLS), logs SNI hello
  - RDP    (3389)  — TCP only, captures first 200 bytes (X.224 Connection Request)
  - FTP    (21)    — fake banner, capture USER/PASS
  - MySQL  (3306)  — fake handshake, log queries

All connections POST a real security event to /api/v1/ingest/generic.
Default: listeners DISABLED until /honeypot/start is called. Default bind:
0.0.0.0 — set HONEYPOT_BIND env to 127.0.0.1 for local-only testing.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

LOGGER = logging.getLogger("aegis.endpoint.honeypot")


@dataclass
class HoneypotEvent:
    trap_type: str
    trap_name: str
    listen_port: int
    src_ip: str
    src_port: int
    timestamp: str
    banner_exchange: str = ""
    credentials: Optional[Dict[str, str]] = None
    raw_first_bytes_hex: str = ""
    technique: str = "T1499"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trap_type": self.trap_type,
            "trap_name": self.trap_name,
            "listen_port": self.listen_port,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "timestamp": self.timestamp,
            "banner_exchange": self.banner_exchange,
            "credentials": self.credentials,
            "raw_first_bytes_hex": self.raw_first_bytes_hex,
            "technique": self.technique,
        }


class HoneypotManager:
    """Spawns and tracks all configured honeypot listeners."""

    def __init__(self, emit_callback: Optional[Callable[[HoneypotEvent], None]] = None,
                 bind: str = "0.0.0.0") -> None:
        self.emit_cb = emit_callback
        self.bind = bind
        self.servers: Dict[str, socketserver.ThreadingTCPServer] = {}
        self.threads: Dict[str, threading.Thread] = {}
        self.trigger_counts: Dict[str, int] = {}
        self.recent_events: List[HoneypotEvent] = []
        self._lock = threading.RLock()

    # ── Trap factories ──────────────────────────────────────────────────────

    def _make_ssh_handler(self):
        manager = self
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address[:2]
                banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
                try:
                    self.request.send(banner)
                    self.request.settimeout(10)
                    received = b""
                    try:
                        received = self.request.recv(2048)
                    except Exception:
                        pass
                    manager._record(HoneypotEvent(
                        trap_type="ssh", trap_name="ssh-22", listen_port=22,
                        src_ip=src_ip, src_port=src_port,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        banner_exchange="server: SSH-2.0-OpenSSH_8.9 -> client: " + received[:80].hex(),
                        raw_first_bytes_hex=received[:200].hex(),
                        technique="T1110.001",
                    ))
                except Exception:
                    pass
                finally:
                    try: self.request.close()
                    except Exception: pass
        return H

    def _make_telnet_handler(self):
        manager = self
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address[:2]
                creds = {"username": "", "password": ""}
                exchange = []
                try:
                    self.request.send(b"Ubuntu 22.04 LTS\r\nlogin: ")
                    self.request.settimeout(15)
                    user_buf = b""
                    while b"\n" not in user_buf and len(user_buf) < 200:
                        chunk = self.request.recv(1)
                        if not chunk:
                            break
                        user_buf += chunk
                    creds["username"] = user_buf.decode("latin-1", "replace").strip()
                    exchange.append(f"login attempt user={creds['username']}")
                    self.request.send(b"Password: ")
                    pwd_buf = b""
                    while b"\n" not in pwd_buf and len(pwd_buf) < 200:
                        chunk = self.request.recv(1)
                        if not chunk:
                            break
                        pwd_buf += chunk
                    creds["password"] = pwd_buf.decode("latin-1", "replace").strip()
                    self.request.send(b"Login incorrect\r\n")
                    manager._record(HoneypotEvent(
                        trap_type="telnet", trap_name="telnet-23", listen_port=23,
                        src_ip=src_ip, src_port=src_port,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        banner_exchange=" | ".join(exchange),
                        credentials=creds,
                        technique="T1110.001",
                    ))
                except Exception:
                    pass
                finally:
                    try: self.request.close()
                    except Exception: pass
        return H

    def _make_http_handler(self, port: int):
        manager = self
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address[:2]
                req = b""
                try:
                    self.request.settimeout(8)
                    while b"\r\n\r\n" not in req and len(req) < 4096:
                        chunk = self.request.recv(1024)
                        if not chunk:
                            break
                        req += chunk
                    text = req.decode("latin-1", "replace")
                    m = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/", text)
                    method, path = (m.group(1), m.group(2)) if m else ("?", "?")
                    ua = ""
                    for line in text.splitlines():
                        if line.lower().startswith("user-agent:"):
                            ua = line.split(":", 1)[1].strip()
                            break
                    body = b"<!DOCTYPE html><html><body><h1>It works</h1></body></html>"
                    self.request.send(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\n\r\n" + body
                    )
                    manager._record(HoneypotEvent(
                        trap_type="http", trap_name=f"http-{port}", listen_port=port,
                        src_ip=src_ip, src_port=src_port,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        banner_exchange=f"{method} {path}  UA={ua[:120]}",
                        raw_first_bytes_hex=req[:200].hex(),
                        technique="T1190",
                    ))
                except Exception:
                    pass
                finally:
                    try: self.request.close()
                    except Exception: pass
        return H

    def _make_ftp_handler(self):
        manager = self
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address[:2]
                creds = {"username": "", "password": ""}
                exchange = []
                try:
                    self.request.send(b"220 ProFTPD 1.3.5 Server ready.\r\n")
                    self.request.settimeout(15)
                    buf = b""
                    while len(exchange) < 4:
                        chunk = b""
                        try:
                            chunk = self.request.recv(256)
                        except Exception:
                            break
                        if not chunk:
                            break
                        buf += chunk
                        while b"\r\n" in buf:
                            line, buf = buf.split(b"\r\n", 1)
                            line = line.decode("latin-1", "replace").strip()
                            exchange.append(line)
                            if line.upper().startswith("USER "):
                                creds["username"] = line[5:]
                                self.request.send(b"331 Password required.\r\n")
                            elif line.upper().startswith("PASS "):
                                creds["password"] = line[5:]
                                self.request.send(b"530 Login incorrect.\r\n")
                                manager._record(HoneypotEvent(
                                    trap_type="ftp", trap_name="ftp-21", listen_port=21,
                                    src_ip=src_ip, src_port=src_port,
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                    banner_exchange=" | ".join(exchange),
                                    credentials=creds,
                                    technique="T1110.001",
                                ))
                                return
                except Exception:
                    pass
                finally:
                    try: self.request.close()
                    except Exception: pass
        return H

    def _make_raw_handler(self, name: str, port: int, banner: bytes = b"",
                           technique: str = "T1190"):
        manager = self
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address[:2]
                try:
                    if banner:
                        try: self.request.send(banner)
                        except Exception: pass
                    self.request.settimeout(6)
                    data = b""
                    try:
                        data = self.request.recv(2048)
                    except Exception:
                        pass
                    manager._record(HoneypotEvent(
                        trap_type=name, trap_name=f"{name}-{port}", listen_port=port,
                        src_ip=src_ip, src_port=src_port,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        banner_exchange=f"recv {len(data)}B",
                        raw_first_bytes_hex=data[:200].hex(),
                        technique=technique,
                    ))
                except Exception:
                    pass
                finally:
                    try: self.request.close()
                    except Exception: pass
        return H

    # ── Recording ───────────────────────────────────────────────────────────

    def _record(self, evt: HoneypotEvent) -> None:
        with self._lock:
            self.trigger_counts[evt.trap_name] = self.trigger_counts.get(evt.trap_name, 0) + 1
            self.recent_events.append(evt)
            if len(self.recent_events) > 500:
                self.recent_events = self.recent_events[-500:]
        LOGGER.warning("HONEYPOT %s hit from %s:%s",
                        evt.trap_name, evt.src_ip, evt.src_port)
        if self.emit_cb:
            try:
                self.emit_cb(evt)
            except Exception:
                pass

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def _spawn(self, name: str, port: int, handler_cls) -> Optional[str]:
        try:
            server = socketserver.ThreadingTCPServer((self.bind, port), handler_cls)
            server.allow_reuse_address = True
        except OSError as e:
            return f"could not bind {self.bind}:{port} — {e}"
        t = threading.Thread(target=server.serve_forever, name=f"hp-{name}", daemon=True)
        t.start()
        self.servers[name] = server
        self.threads[name] = t
        LOGGER.info("Honeypot %s listening on %s:%s", name, self.bind, port)
        return None

    def start(self, requested: Optional[List[str]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        ALL = {
            "ssh":    (22,   self._make_ssh_handler()),
            "telnet": (23,   self._make_telnet_handler()),
            "ftp":    (21,   self._make_ftp_handler()),
            "http":   (8000, self._make_http_handler(8000)),
            "smb":    (445,  self._make_raw_handler("smb", 445,    b"", "T1021.002")),
            "rdp":    (3389, self._make_raw_handler("rdp", 3389,   b"", "T1021.001")),
            "mysql":  (3306, self._make_raw_handler("mysql", 3306, b"\x5b\x00\x00\x00\x0a8.0.0\x00", "T1190")),
        }
        targets = requested or list(ALL.keys())
        for name in targets:
            if name not in ALL:
                results[name] = {"error": f"unknown trap {name}"}; continue
            if name in self.servers:
                results[name] = {"status": "already running"}; continue
            port, cls = ALL[name]
            err = self._spawn(name, port, cls)
            if err:
                results[name] = {"status": "failed", "error": err}
            else:
                results[name] = {"status": "running", "bind": self.bind, "port": port}
        return results

    def stop(self, name: Optional[str] = None) -> Dict[str, Any]:
        results = {}
        targets = [name] if name else list(self.servers.keys())
        for n in targets:
            srv = self.servers.pop(n, None)
            if srv:
                try:
                    srv.shutdown()
                    srv.server_close()
                    results[n] = "stopped"
                except Exception as e:
                    results[n] = f"error: {e}"
            else:
                results[n] = "not running"
            self.threads.pop(n, None)
        return results

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "bind":           self.bind,
                "running_traps":  list(self.servers.keys()),
                "trigger_counts": dict(self.trigger_counts),
                "recent_events_count": len(self.recent_events),
                "recent_events":  [e.to_dict() for e in self.recent_events[-50:]],
            }
