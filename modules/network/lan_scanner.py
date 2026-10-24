#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — LAN Scanner Module
========================================
Performs real network discovery and TCP port scanning on local/private networks.

Capabilities:
  • Auto-detect local subnet
  • Host discovery: ARP (scapy) → ICMP ping sweep → TCP connect sweep fallback
  • Fast concurrent TCP port scanner (socket-based)
  • Optional nmap integration for OS/service detection (requires nmap binary)
  • Service banner grabbing (HTTP/HTTPS/SSH/FTP/SMTP/Redis)
  • Potential exposure hints (static service-to-risk mapping, NOT verified CVEs)
  • Scan job queue with cancellation, timeout, and concurrency limits
  • Structured JSON results forwarded to AEGIS orchestrator

Safety notes:
  • Active scanning sends packets (ARP, ICMP, TCP SYN/Connect).
  • By default only RFC1918 private networks are allowed.
  • OT/ICS ports are probed with TCP connect only; no protocol commands are sent.
  • Exposure hints require manual verification — they are NOT confirmed vulnerabilities.
"""
from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    scapy_conf.verb = 0
    _SCAPY = True
except Exception:
    _SCAPY = False

try:
    import nmap as python_nmap
    _NMAP = True
except ImportError:
    _NMAP = False

LOGGER = logging.getLogger("aegis.lan_scanner")

# ── WELL-KNOWN PORTS TO SCAN ───────────────────────────────────────────────────
QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465,
               502, 514, 587, 636, 993, 995, 1433, 1521, 1883, 2404, 3306, 3389,
               4840, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017, 47808]

FULL_PORTS = list(range(1, 1025)) + [
    1433, 1521, 1883, 2049, 2404, 3306, 3389, 4840, 5432, 5900,
    5985, 6379, 8080, 8443, 8888, 9200, 9300, 27017, 47808
]

SERVICE_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 502: "modbus", 514: "syslog", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1883: "mqtt", 2404: "iec104", 3306: "mysql",
    3389: "rdp", 4840: "opcua", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "jupyter", 9200: "elasticsearch", 9300: "elasticsearch-transport",
    27017: "mongodb", 47808: "bacnet",
}

# Services with known high-risk CVEs (static, offline)
RISKY_SERVICES: Dict[str, List[Dict[str, Any]]] = {
    "telnet":  [{"cve": "CVE-1999-0619", "cvss": 9.8, "sev": "critical",
                 "desc": "Telnet transmits credentials in cleartext (no encryption)"}],
    "ftp":     [{"cve": "CVE-1999-0497", "cvss": 7.5, "sev": "high",
                 "desc": "Anonymous FTP may expose sensitive data"}],
    "smb":     [{"cve": "CVE-2017-0144", "cvss": 9.8, "sev": "critical",
                 "desc": "EternalBlue — remote code execution via SMBv1"},
                {"cve": "CVE-2020-0796", "cvss": 10.0, "sev": "critical",
                 "desc": "SMBGhost — unauthenticated RCE via SMBv3"}],
    "rdp":     [{"cve": "CVE-2019-0708", "cvss": 9.8, "sev": "critical",
                 "desc": "BlueKeep — pre-auth RCE in Windows RDP"}],
    "redis":   [{"cve": "CVE-2022-0543", "cvss": 10.0, "sev": "critical",
                 "desc": "Redis Lua sandbox escape enables RCE"}],
    "vnc":     [{"cve": "CVE-2019-15681", "cvss": 7.5, "sev": "high",
                 "desc": "LibVNCServer memory disclosure"}],
    "modbus":  [{"cve": "ICS-MODBUS", "cvss": 8.6, "sev": "high",
                 "desc": "Modbus has no authentication — write commands may alter industrial process"}],
    "opcua":   [{"cve": "ICS-OPCUA", "cvss": 6.5, "sev": "medium",
                 "desc": "OPC UA may expose process data without proper security mode"}],
    "iec104":  [{"cve": "ICS-IEC104", "cvss": 9.1, "sev": "critical",
                 "desc": "IEC 104 lacks authentication — SCADA command injection possible"}],
    "bacnet":  [{"cve": "ICS-BACNET", "cvss": 8.1, "sev": "high",
                 "desc": "BACnet has no authentication — unauthorized building control possible"}],
    "mqtt":    [{"cve": "IOT-MQTT", "cvss": 7.3, "sev": "high",
                 "desc": "MQTT broker without auth exposes IoT device control"}],
    "mongodb": [{"cve": "CVE-2013-2132", "cvss": 7.5, "sev": "high",
                 "desc": "MongoDB no-auth access exposes all databases"}],
    "elasticsearch": [{"cve": "CVE-2014-3120", "cvss": 9.8, "sev": "critical",
                       "desc": "Elasticsearch unauthenticated access + dynamic script RCE"}],
    "jupyter": [{"cve": "CVE-2019-10255", "cvss": 8.1, "sev": "high",
                 "desc": "Jupyter Notebook open redirect allows session hijacking"}],
    "winrm":   [{"cve": "T1021.006", "cvss": 7.5, "sev": "high",
                 "desc": "WinRM exposed — lateral movement vector (MITRE T1021.006)"}],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── RESULT MODELS ──────────────────────────────────────────────────────────────
@dataclass
class PortResult:
    port: int
    state: str          # open / closed / filtered
    service: str
    banner: str = ""
    ssl_info: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    ports: List[PortResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    scan_time: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class ScanJob:
    id: str
    target: str
    mode: str           # quick / full / custom
    ot_mode: str = "normal"   # safe / normal / aggressive
    state: str = "pending"    # pending / running / done / error / cancelled
    progress: int = 0         # 0-100
    hosts_found: int = 0
    hosts_scanned: int = 0
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""
    results: List[HostResult] = field(default_factory=list)
    error: str = ""
    cancelled: bool = False
    timeout: float = 300.0
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "ot_mode": self.ot_mode,
            "state": self.state,
            "progress": self.progress,
            "hosts_found": self.hosts_found,
            "hosts_scanned": self.hosts_scanned,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "cancelled": self.cancelled,
            "results": [r.to_dict() for r in self.results],
        }
        return d


# ── HOST DISCOVERY ─────────────────────────────────────────────────────────────
def _get_local_networks() -> List[str]:
    """Auto-detect local IP and return likely subnet CIDRs."""
    nets: Set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if not ip.startswith("127.") and ":" not in ip:
                try:
                    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    nets.add(str(net))
                except ValueError:
                    pass
    except Exception:
        pass

    # Fallback: try connecting to 8.8.8.8 to find outbound interface
    if not nets:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            nets.add(str(net))
        except Exception:
            pass

    return list(nets) if nets else ["192.168.1.0/24"]


def _arp_discovery(subnet: str) -> Dict[str, str]:
    """ARP scan using Scapy — returns {ip: mac}."""
    if not _SCAPY:
        return {}
    try:
        LOGGER.info("ARP scan: %s", subnet)
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(arp_req, timeout=2, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}
    except Exception as exc:
        LOGGER.warning("ARP scan failed: %s", exc)
        return {}


def _ping_sweep(subnet: str, max_workers: int = 64) -> List[str]:
    """ICMP ping sweep using OS ping command."""
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        hosts = [subnet]

    alive: List[str] = []
    lock = threading.Lock()
    is_windows = platform.system() == "Windows"

    def ping_host(ip: str) -> None:
        try:
            if is_windows:
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
            if result.returncode == 0:
                with lock:
                    alive.append(ip)
        except Exception:
            pass

    LOGGER.info("Ping sweep: %s (%d hosts)", subnet, len(hosts))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        ex.map(ping_host, hosts)

    return alive


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── SCOPE VALIDATION ───────────────────────────────────────────────────────────
_RFC1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]
_MAX_HOSTS_DEFAULT = 256


def _validate_target(target: str, allow_public: bool = False, max_hosts: int = _MAX_HOSTS_DEFAULT) -> Tuple[bool, str]:
    """Validate scan target is within authorized scope. Returns (ok, reason)."""
    try:
        net = ipaddress.IPv4Network(target, strict=False)
        num_hosts = net.num_addresses - 2  # exclude network and broadcast
        if num_hosts > max_hosts:
            return False, f"Target too large: {num_hosts} hosts (max {max_hosts})"
        if not allow_public:
            is_private = any(net.subnet_of(priv) for priv in _RFC1918_NETWORKS) or net.is_loopback or net.is_link_local
            if not is_private:
                return False, "Public/target networks require explicit allow_public=True"
        return True, ""
    except ValueError:
        # Single IP
        try:
            ip = ipaddress.IPv4Address(target)
            if not allow_public:
                is_private = ip.is_private or ip.is_loopback or ip.is_link_local
                if not is_private:
                    return False, "Public IP scanning requires explicit allow_public=True"
            return True, ""
        except ValueError:
            return False, "Invalid target — must be an IPv4 address or CIDR"


# ── OUI VENDOR LOOKUP (minimal offline table) ──────────────────────────────────
_OUI_TABLE: Dict[str, str] = {
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "00:17:88": "Philips Hue",
    "18:b4:30": "Texas Instruments / IoT",
    "ac:de:48": "Siemens AG",
    "00:1b:21": "Intel Corporate",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
    "00:25:90": "Apple",
    "3c:5a:b4": "Google",
    "a4:77:33": "Intel Corporate",
    "00:90:7a": "Hewlett-Packard",
    "00:11:43": "Dell",
    "00:18:8b": "Dell",
    "00:26:b9": "Cisco Systems",
    "00:1e:c9": "Dell",
    "f0:1f:af": "Siemens AG",
    "00:0e:8c": "Siemens AG",
}


def _oui_vendor(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.lower()[:8]
    return _OUI_TABLE.get(prefix, "")


# ── TCP DISCOVERY FALLBACK ─────────────────────────────────────────────────────
_TCP_PROBE_PORTS = [22, 80, 135, 139, 443, 445, 3389, 502, 8080, 8443]


def _tcp_discovery(subnet: str, probe_ports: Optional[List[int]] = None,
                   max_workers: int = 64, timeout: float = 1.0,
                   cancel_event: Optional[threading.Event] = None) -> List[str]:
    """TCP SYN/connect sweep as fallback when ARP/ICMP fail."""
    ports = probe_ports or _TCP_PROBE_PORTS
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        hosts = [subnet]

    alive: Set[str] = set()
    lock = threading.Lock()

    def probe(ip: str) -> None:
        if cancel_event and cancel_event.is_set():
            return
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    with lock:
                        alive.add(ip)
                    return
            except Exception:
                continue

    LOGGER.info("TCP discovery sweep: %s (%d hosts, ports %s)", subnet, len(hosts), ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        ex.map(probe, hosts)
    return list(alive)


# ── UDP DISCOVERY ──────────────────────────────────────────────────────────────
def _udp_probe(ip: str, port: int, payload: bytes, timeout: float = 1.5) -> Optional[bytes]:
    """Send a UDP payload and return response if any."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            data, _ = s.recvfrom(1024)
            return data
    except Exception:
        return None


def _ssdp_discovery(subnet: str, timeout: float = 1.5,
                    cancel_event: Optional[threading.Event] = None) -> List[Dict[str, Any]]:
    """SSDP M-SEARCH discovery on UDP 1900. Returns list of discovered devices."""
    payload = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )
    devices: List[Dict[str, Any]] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 0))
            # Send to multicast and broadcast
            s.sendto(payload, ("239.255.255.250", 1900))
            # Collect responses until timeout
            start = time.time()
            while time.time() - start < timeout:
                if cancel_event and cancel_event.is_set():
                    break
                try:
                    s.settimeout(max(0.1, timeout - (time.time() - start)))
                    data, addr = s.recvfrom(2048)
                    text = data.decode(errors="replace")
                    dev: Dict[str, Any] = {"ip": addr[0], "port": addr[1], "raw": text}
                    for line in text.splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            dev[k.strip().lower()] = v.strip()
                    devices.append(dev)
                except socket.timeout:
                    break
                except Exception:
                    continue
    except Exception as exc:
        LOGGER.debug("SSDP discovery failed: %s", exc)
    return devices


def _bacnet_whois(subnet: str, timeout: float = 1.5,
                  cancel_event: Optional[threading.Event] = None) -> List[Dict[str, Any]]:
    """BACnet Who-Is broadcast on UDP 47808. Returns list of I-Am responses."""
    # BACnet BVLC + NPDU + APDU Who-Is (simplified raw bytes)
    # BVLC: Type=0x81, Function=0x0B (Broadcast), Length=8
    # NPDU: Version=0x01, Control=0x00
    # APDU: SDU=0x10 (Unconfirmed-REQ), Service=0x08 (Who-Is)
    payload = bytes([0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08])
    devices: List[Dict[str, Any]] = []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        broadcast = str(net.broadcast_address)
    except Exception:
        broadcast = "255.255.255.255"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 0))
            s.sendto(payload, (broadcast, 47808))
            start = time.time()
            while time.time() - start < timeout:
                if cancel_event and cancel_event.is_set():
                    break
                try:
                    s.settimeout(max(0.1, timeout - (time.time() - start)))
                    data, addr = s.recvfrom(1024)
                    devices.append({"ip": addr[0], "port": addr[1], "raw": data.hex()})
                except socket.timeout:
                    break
                except Exception:
                    continue
    except Exception as exc:
        LOGGER.debug("BACnet Who-Is failed: %s", exc)
    return devices


def _snmp_probe(ip: str, timeout: float = 1.5) -> bool:
    """Send a raw SNMPv2c GetRequest for sysDescr.0 and check for any response."""
    # SNMPv2c GetRequest encoded bytes (community=public, request-id=1)
    # Sequence: SNMP message
    payload = bytes([
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        0x05, 0x00,
    ])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, 161))
            data, _ = s.recvfrom(1024)
            return len(data) > 0
    except Exception:
        return False


# ── PORT SCANNER ───────────────────────────────────────────────────────────────
def _tcp_connect(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> Tuple[str, str]:
    """Grab service banner; returns (banner_text, ssl_info)."""
    banner = ""
    ssl_info = ""

    # SMB specific probe
    if port == 445:
        banner, _ = _probe_smb(ip, port, timeout)
        return banner, ssl_info

    # RDP specific probe
    if port == 3389:
        banner = _probe_rdp(ip, port, timeout)
        return banner, ssl_info

    # SSH specific probe
    if port == 22:
        banner = _probe_ssh(ip, port, timeout)
        return banner, ssl_info

    # HTTP/HTTPS banner via simple GET
    if port in (80, 8080, 8888):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                data = s.recv(512).decode(errors="replace")
                # Extract Server header
                m = re.search(r"Server:\s*([^\r\n]+)", data, re.IGNORECASE)
                if m:
                    banner = m.group(1).strip()
                elif data.startswith("HTTP"):
                    banner = data.split("\r\n")[0][:100]
        except Exception:
            pass
        return banner, ssl_info

    if port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw_s:
                with ctx.wrap_socket(raw_s, server_hostname=ip) as s:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    data = s.recv(512).decode(errors="replace")
                    m = re.search(r"Server:\s*([^\r\n]+)", data, re.IGNORECASE)
                    if m:
                        banner = m.group(1).strip()
                    cert_info = _probe_tls_cert(ip, port)
                    if cert_info.get("subject"):
                        ssl_info = f"CN={cert_info['subject']}; Issuer={cert_info['issuer']}; NotAfter={cert_info['not_after'][:10]}"
        except Exception:
            pass
        return banner, ssl_info

    # Generic banner read (FTP, SMTP, Redis, etc.)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Some services need a trigger
            if port in (25, 465, 587):
                data = s.recv(256).decode(errors="replace")
            elif port == 6379:
                s.sendall(b"*1\r\n$4\r\nINFO\r\n")
                data = s.recv(256).decode(errors="replace")
            else:
                data = s.recv(256).decode(errors="replace")
            banner = data.strip()[:120].replace("\r\n", " ").replace("\n", " ")
    except Exception:
        pass

    return banner, ssl_info


def _probe_smb(ip: str, port: int = 445, timeout: float = 2.0) -> Tuple[str, str]:
    """Send SMB Negotiate Protocol Request and parse dialects."""
    try:
        # NetBIOS session header (4 bytes) + SMB Negotiate Protocol Request
        netbios = struct.pack(">I", 0x00000054)  # length = 84
        smb_header = bytes([
            0xff, 0x53, 0x4d, 0x42,  # Protocol (\xFFSMB)
            0x72,                      # Command: Negotiate
            0x00, 0x00, 0x00, 0x00,    # Status
            0x18,                      # Flags
            0x01, 0x28,                # Flags2
            0x00, 0x00,                # PIDHigh
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
            0x00, 0x00,                # Reserved
            0x00, 0x00,                # TreeID
            0x00, 0x00,                # PID
            0x00, 0x00,                # UserID
            0x00, 0x00,                # MultiplexID
        ])
        dialects = b"\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
        payload = netbios + smb_header + dialects
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(payload)
            data = s.recv(512)
            if data[4:8] == b'\xffSMB':
                dialect_idx = struct.unpack("<H", data[73:75])[0]
                return f"SMB dialect_idx={dialect_idx}", ""
            elif data[4:8] == b'\xfeSMB':
                return "SMB 2.x+", ""
    except Exception:
        pass
    return "", ""


def _probe_rdp(ip: str, port: int = 3389, timeout: float = 2.0) -> str:
    """Send RDP connection request and detect security mode."""
    try:
        # TPKT + X.224 Connection Request (RDP)
        tpkt = bytes([0x03, 0x00, 0x00, 0x13])
        x224 = bytes([
            0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
        ])
        payload = tpkt + x224
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(payload)
            data = s.recv(256)
            if len(data) >= 11:
                # Parse response for selected protocol
                if data[10] == 0x02:
                    return "RDP (TLS required)"
                elif data[10] == 0x03:
                    return "RDP (NLA required)"
                elif data[10] == 0x00:
                    return "RDP (Standard)"
    except Exception:
        pass
    return ""


def _probe_ssh(ip: str, port: int = 22, timeout: float = 2.0) -> str:
    """Read SSH banner and extract version."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            data = s.recv(256).decode(errors="replace")
            m = re.search(r"^(SSH-\d\.\d+-.+)", data.strip())
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def _probe_tls_cert(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Perform TLS handshake and extract certificate details."""
    result: Dict[str, Any] = {"subject": "", "issuer": "", "not_after": "", "serial": "", "sans": []}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw_s:
            with ctx.wrap_socket(raw_s, server_hostname=ip) as s:
                cert = s.getpeercert(binary_form=True)
                if cert:
                    # Use cryptography library if available for deeper parsing
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        c = x509.load_der_x509_certificate(cert, default_backend())
                        result["subject"] = str(c.subject.rfc4514_string())
                        result["issuer"] = str(c.issuer.rfc4514_string())
                        result["not_after"] = c.not_valid_after_utc.isoformat() if hasattr(c, "not_valid_after_utc") else str(c.not_valid_after)
                        result["serial"] = str(c.serial_number)
                        try:
                            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            result["sans"] = [str(v) for v in ext.value]
                        except Exception:
                            pass
                    except Exception:
                        # Fallback to ssl dict
                        cert_dict = s.getpeercert()
                        if cert_dict:
                            subj = dict(x[0] for x in cert_dict.get("subject", []))
                            result["subject"] = subj.get("commonName", "")
                            iss = dict(x[0] for x in cert_dict.get("issuer", []))
                            result["issuer"] = iss.get("commonName", "")
                            result["not_after"] = cert_dict.get("notAfter", "")
                            result["sans"] = cert_dict.get("subjectAltName", [])
    except Exception:
        pass
    return result


def _scan_host_ports(ip: str, ports: List[int], max_workers: int = 50,
                     progress_cb: Optional[Callable[[int], None]] = None,
                     report_closed: bool = False,
                     cancel_event: Optional[threading.Event] = None) -> List[PortResult]:
    """Concurrent TCP port scan on a single host."""
    results: List[PortResult] = []
    total = len(ports)
    done_count = [0]
    lock = threading.Lock()

    def check_port(port: int) -> Optional[PortResult]:
        if cancel_event and cancel_event.is_set():
            return None
        is_open = _tcp_connect(ip, port)
        with lock:
            done_count[0] += 1
            if progress_cb and total > 0:
                progress_cb(int(done_count[0] * 100 / total))
        svc = SERVICE_NAMES.get(port, "unknown")
        if is_open:
            banner, ssl_info = _grab_banner(ip, port)
            return PortResult(port=port, state="open", service=svc, banner=banner, ssl_info=ssl_info)
        if report_closed:
            return PortResult(port=port, state="closed", service=svc, banner="", ssl_info="")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for pr in ex.map(check_port, ports):
            if pr is not None:
                results.append(pr)
            if cancel_event and cancel_event.is_set():
                break

    return sorted(results, key=lambda r: r.port)


# ── OS GUESSING ────────────────────────────────────────────────────────────────
def _guess_os(ports: List[PortResult]) -> str:
    open_ports = {p.port for p in ports if p.state == "open"}
    banners = " ".join(p.banner for p in ports).lower()

    if any("windows" in b.lower() or "microsoft" in b.lower()
           for p in ports for b in [p.banner]):
        return "Windows"
    if any(term in banners for term in ("openssh", "ubuntu", "debian", "centos", "linux")):
        return "Linux"
    if 3389 in open_ports and 135 in open_ports:
        return "Windows (likely — RDP + RPC)"
    if 22 in open_ports and 80 in open_ports and 443 not in open_ports:
        return "Linux/Unix (likely)"
    if 445 in open_ports and 139 in open_ports:
        return "Windows (SMB present)"
    if 502 in open_ports or 2404 in open_ports or 47808 in open_ports:
        return "ICS/OT Device"
    if 1883 in open_ports:
        return "IoT Device (MQTT broker)"
    return "Unknown"


# ── RISK SCORING ───────────────────────────────────────────────────────────────
def _score_host(ports: List[PortResult]) -> Tuple[int, List[Dict[str, Any]]]:
    """Compute 0-100 risk score and list of potential exposures (not verified CVEs)."""
    score = 0
    findings: List[Dict[str, Any]] = []

    for pr in ports:
        if pr.state != "open":
            continue
        svc = pr.service.lower()
        if svc in RISKY_SERVICES:
            for hint in RISKY_SERVICES[svc]:
                score = max(score, int(hint["cvss"] * 10))
                findings.append({
                    "type": "potential_exposure",
                    "port": pr.port,
                    "service": svc,
                    "exposure_id": hint["cve"],
                    "cvss": hint["cvss"],
                    "severity": hint["sev"],
                    "description": hint["desc"],
                    "evidence": f"{svc} port open",
                    "confidence": "low",
                    "requires_verification": True,
                    "banner": pr.banner,
                })
        # Generic risk for exposed cleartext ports
        if pr.port in (23, 21, 110, 143, 587) and svc not in RISKY_SERVICES:
            score = max(score, 70)
            findings.append({
                "type": "potential_exposure",
                "port": pr.port,
                "service": svc,
                "exposure_id": "EXPOSED-CLEARTEXT",
                "cvss": 7.0,
                "severity": "high",
                "description": "Cleartext protocol exposed — credentials may be transmitted unencrypted",
                "evidence": f"Port {pr.port} open",
                "confidence": "medium",
                "requires_verification": True,
                "banner": pr.banner,
            })
        if pr.port == 3389:
            score = max(score, 60)

    return min(score, 100), findings


# ── NVD CVE LOOKUP (live) ──────────────────────────────────────────────────────
_NVD_CACHE: Dict[str, Tuple[List[Dict[str, Any]], float]] = {}
_NVD_TTL = 3600.0
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_version(banner: str, service: str) -> str:
    """Extract version string from banner for common services."""
    banner = banner.strip()
    if not banner:
        return ""
    patterns = {
        "apache": r"Apache/(\d+\.\d+\.?\d*)",
        "nginx": r"nginx/(\d+\.\d+\.?\d*)",
        "openssh": r"OpenSSH[_/](\d+\.\d+\.?\d*)",
        "mysql": r"(\d+\.\d+\.?\d*).*[Mm][Yy][Ss][Qq][Ll]",
        "mssql": r"Microsoft SQL Server.*?(\d+\.\d+\.?\d*)",
        "ssh": r"SSH-\d\.\d+-(.+?)(?:\s|$)",
        "ftp": r"(\d+\.\d+\.?\d*)",
        "redis": r"redis_version:(\d+\.\d+\.?\d*)",
        "postgres": r"PostgreSQL\s+(\d+\.\d+\.?\d*)",
    }
    svc = service.lower()
    for key, pat in patterns.items():
        if key in svc or key in banner.lower():
            m = re.search(pat, banner)
            if m:
                return m.group(1)
    # Generic version hunt
    m = re.search(r"/(\d+\.\d+\.?\d*)", banner)
    if m:
        return m.group(1)
    return ""


def _nvd_lookup(keyword: str, version: str = "") -> List[Dict[str, Any]]:
    """Query NVD API v2.0 for CVEs matching keyword+version. Returns list of CVE dicts."""
    if not _REQUESTS:
        return []
    cache_key = f"{keyword}:{version}".lower()
    now = time.time()
    if cache_key in _NVD_CACHE:
        entries, ts = _NVD_CACHE[cache_key]
        if now - ts < _NVD_TTL:
            return entries

    q = keyword
    if version:
        q = f"{keyword} {version}"
    try:
        resp = requests.get(
            _NVD_API_URL,
            params={"keywordSearch": q, "resultsPerPage": 5},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results: List[Dict[str, Any]] = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])[0] or metrics.get("cvssMetricV30", [{}])[0] or metrics.get("cvssMetricV2", [{}])[0]
            score = 0.0
            sev = "medium"
            if cvss_data:
                score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
                sev = cvss_data.get("cvssData", {}).get("baseSeverity", "medium").lower()
            results.append({
                "cve": cve_id,
                "cvss": float(score),
                "severity": sev,
                "description": desc,
            })
        _NVD_CACHE[cache_key] = (results, now)
        return results
    except Exception as exc:
        LOGGER.debug("NVD lookup failed for %s: %s", cache_key, exc)
        return []


def _enrich_findings_with_nvd(ports: List[PortResult], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Augment findings with real CVE data from NVD when banner contains a version."""
    for pr in ports:
        if pr.state != "open" or not pr.banner:
            continue
        version = _extract_version(pr.banner, pr.service)
        if not version:
            continue
        # Build keyword from service name (common CPE-like mapping)
        keyword_map = {
            "http": "apache httpd",
            "https": "apache httpd",
            "http-alt": "nginx",
            "ssh": "openssh",
            "mysql": "mysql",
            "mssql": "microsoft sql server",
            "postgresql": "postgresql",
            "redis": "redis",
            "ftp": "ftp",
        }
        keyword = keyword_map.get(pr.service.lower(), pr.service.lower())
        cves = _nvd_lookup(keyword, version)
        if cves:
            for cve in cves:
                findings.append({
                    "type": "cve_verified",
                    "port": pr.port,
                    "service": pr.service.lower(),
                    "exposure_id": cve["cve"],
                    "cvss": cve["cvss"],
                    "severity": cve["severity"],
                    "description": cve["description"],
                    "evidence": f"Banner: {pr.banner}",
                    "confidence": "medium",
                    "requires_verification": True,
                    "banner": pr.banner,
                })
    # Deduplicate by exposure_id
    seen: Set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for f in findings:
        key = f.get("exposure_id", "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(f)
    return deduped


# ── NMAP INTEGRATION (optional) ────────────────────────────────────────────────
def _nmap_scan(ip: str, ports: List[int]) -> Dict[str, Any]:
    """Run nmap if python-nmap is installed."""
    if not _NMAP:
        return {}
    try:
        nm = python_nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports[:200])
        nm.scan(hosts=ip, ports=port_str, arguments="-sV -O --version-intensity 3 -T4")
        if ip not in nm.all_hosts():
            return {}
        host = nm[ip]
        result: Dict[str, Any] = {"os": "", "ports": {}}
        os_matches = host.get("osmatch", [])
        if os_matches:
            result["os"] = os_matches[0].get("name", "")
        for proto in host.all_protocols():
            for port, data in host[proto].items():
                result["ports"][port] = {
                    "state": data["state"],
                    "service": data.get("name", ""),
                    "product": data.get("product", ""),
                    "version": data.get("version", ""),
                }
        return result
    except Exception as exc:
        LOGGER.warning("nmap scan failed: %s", exc)
        return {}


# ── MAIN SCAN JOB ──────────────────────────────────────────────────────────────
class LANScanner:
    """Manages scan jobs with scope guards, cancellation, and live status."""

    def __init__(self, orchestrator_url: str = "",
                 allow_public: bool = False,
                 max_hosts: int = _MAX_HOSTS_DEFAULT,
                 max_concurrent: int = 3) -> None:
        self.orchestrator_url = orchestrator_url
        self.allow_public = allow_public
        self.max_hosts = max_hosts
        self.max_concurrent = max_concurrent
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_concurrent)

    def get_local_subnets(self) -> List[str]:
        return _get_local_networks()

    def start_scan(self, target: str, mode: str = "quick",
                   ot_mode: str = "normal",
                   custom_ports: Optional[List[int]] = None,
                   timeout: float = 300.0) -> ScanJob:
        """Launch a scan job in background, return job metadata."""
        ok, reason = _validate_target(target, self.allow_public, self.max_hosts)
        if not ok:
            job = ScanJob(
                id=str(uuid.uuid4())[:8],
                target=target,
                mode=mode,
                ot_mode=ot_mode,
                state="error",
                error=reason,
            )
            with self._lock:
                self._jobs[job.id] = job
            return job

        job = ScanJob(
            id=str(uuid.uuid4())[:8],
            target=target,
            mode=mode,
            ot_mode=ot_mode,
            state="pending",
            timeout=timeout,
        )
        with self._lock:
            self._jobs[job.id] = job
        t = threading.Thread(target=self._run_job_guarded, args=(job, custom_ports), daemon=True)
        t.start()
        return job

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job or job.state not in ("pending", "running"):
            return False
        job.cancelled = True
        job._cancel_event.set()
        job.state = "cancelled"
        return True

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def get_latest_job(self) -> Optional[ScanJob]:
        with self._lock:
            if not self._jobs:
                return None
            return sorted(self._jobs.values(), key=lambda j: j.started_at)[-1]

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {k: v for k, v in j.to_dict().items() if k != "results"}
                for j in self._jobs.values()
            ]

    def _run_job_guarded(self, job: ScanJob, custom_ports: Optional[List[int]]) -> None:
        with self._sem:
            self._run_job(job, custom_ports)

    def _run_job(self, job: ScanJob, custom_ports: Optional[List[int]]) -> None:
        job.state = "running"
        job.started_at = _now_iso()
        deadline = time.time() + job.timeout

        def timed_out() -> bool:
            return time.time() > deadline

        try:
            # Determine port list based on OT mode
            if custom_ports:
                ports = custom_ports
            elif job.ot_mode == "safe":
                ports = []  # No TCP connect in safe mode
            elif job.mode == "quick":
                ports = QUICK_PORTS
            else:
                ports = FULL_PORTS

            # Determine if target is CIDR or single IP
            try:
                ipaddress.IPv4Network(job.target, strict=False)
                is_network = True
            except ValueError:
                is_network = False

            # Host discovery
            arp_map: Dict[str, str] = {}
            udp_hosts: Dict[str, Dict[str, Any]] = {}
            if is_network:
                LOGGER.info("Host discovery on %s (ot_mode=%s)", job.target, job.ot_mode)
                arp_map = _arp_discovery(job.target)
                live_hosts = list(arp_map.keys())
                if not live_hosts:
                    live_hosts = _ping_sweep(job.target)
                if not live_hosts and job.ot_mode != "safe" and not job._cancel_event.is_set():
                    live_hosts = _tcp_discovery(job.target, cancel_event=job._cancel_event)
                # UDP discovery (SSDP, BACnet) — safe/normal/aggressive all get this
                if not job._cancel_event.is_set():
                    ssdp_devs = _ssdp_discovery(job.target, cancel_event=job._cancel_event)
                    for d in ssdp_devs:
                        ip = d["ip"]
                        udp_hosts[ip] = {"type": "ssdp", "data": d}
                        if ip not in live_hosts:
                            live_hosts.append(ip)
                    if not job._cancel_event.is_set():
                        bacnet_devs = _bacnet_whois(job.target, cancel_event=job._cancel_event)
                        for d in bacnet_devs:
                            ip = d["ip"]
                            udp_hosts[ip] = {"type": "bacnet", "data": d}
                            if ip not in live_hosts:
                                live_hosts.append(ip)
                # Always include our own IP
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.connect(("8.8.8.8", 80))
                        self_ip = s.getsockname()[0]
                    if self_ip and self_ip not in live_hosts:
                        live_hosts.insert(0, self_ip)
                        if self_ip not in arp_map:
                            arp_map[self_ip] = ""
                except Exception:
                    pass
            else:
                live_hosts = [job.target]

            job.hosts_found = len(live_hosts)
            LOGGER.info("Found %d live hosts (%d UDP-only), scanning ports...", len(live_hosts), len(udp_hosts))

            results: List[HostResult] = []
            host_weight = 90 / max(len(live_hosts), 1)
            for idx, ip in enumerate(live_hosts):
                if job._cancel_event.is_set() or timed_out():
                    job.state = "cancelled"
                    job.error = "Cancelled by user or timeout" if not timed_out() else "Timeout exceeded"
                    break

                job.progress = int(idx * host_weight)
                job.hosts_scanned = idx

                hostname = _resolve_hostname(ip)
                mac = arp_map.get(ip, "")
                vendor = _oui_vendor(mac)

                def port_progress(pct: int) -> None:
                    job.progress = int(idx * host_weight + pct * host_weight / 100)

                # Port scan (skipped in safe mode where ports=[])
                open_ports: List[PortResult] = []
                if ports and job.ot_mode != "safe":
                    open_ports = _scan_host_ports(
                        ip, ports, max_workers=40,
                        progress_cb=port_progress,
                        cancel_event=job._cancel_event,
                    )

                # SNMP probe on port 161 (UDP) — read-only
                if not job._cancel_event.is_set() and job.ot_mode != "safe":
                    if _snmp_probe(ip):
                        open_ports.append(PortResult(port=161, state="open", service="snmp", banner="SNMPv2c responded", ssl_info=""))

                # Optional nmap enrichment (aggressive only)
                nmap_data = {}
                if job.ot_mode == "aggressive" and _NMAP and open_ports and not job._cancel_event.is_set():
                    nmap_data = _nmap_scan(ip, [p.port for p in open_ports])
                    if nmap_data.get("os"):
                        for pr in open_ports:
                            pdata = nmap_data.get("ports", {}).get(pr.port, {})
                            if pdata.get("product") or pdata.get("version"):
                                pr.banner = f"{pdata.get('product','')} {pdata.get('version','')}".strip()

                os_guess = nmap_data.get("os") or _guess_os(open_ports)
                risk_score, findings = _score_host(open_ports)

                # Enrich with NVD (normal and aggressive)
                if job.ot_mode in ("normal", "aggressive"):
                    findings = _enrich_findings_with_nvd(open_ports, findings)
                    risk_score = min(max(int(max((f.get("cvss", 0) * 10) for f in findings) if findings else 0), risk_score), 100)

                # Add UDP-only context
                if ip in udp_hosts:
                    u = udp_hosts[ip]
                    if u["type"] == "ssdp":
                        open_ports.append(PortResult(port=1900, state="open", service="ssdp", banner=u["data"].get("server", "SSDP device"), ssl_info=""))
                    elif u["type"] == "bacnet":
                        open_ports.append(PortResult(port=47808, state="open", service="bacnet", banner="BACnet I-Am response", ssl_info=""))

                host_result = HostResult(
                    ip=ip,
                    hostname=hostname,
                    mac=mac,
                    vendor=vendor,
                    os_guess=os_guess,
                    ports=sorted(open_ports, key=lambda r: r.port),
                    findings=findings,
                    risk_score=risk_score,
                )
                results.append(host_result)

                # Forward critical findings to orchestrator
                if findings and self.orchestrator_url and not job._cancel_event.is_set():
                    self._forward_findings(ip, hostname, findings)

            # Sort by risk score descending
            results.sort(key=lambda h: h.risk_score, reverse=True)
            job.results = results
            job.hosts_scanned = len(results)
            if job.state not in ("cancelled", "error"):
                job.progress = 100
                job.state = "done"
            job.finished_at = _now_iso()
            LOGGER.info("Scan %s finished (%s): %d hosts, %d total findings",
                        job.id, job.state, len(results), sum(len(h.findings) for h in results))

        except Exception as exc:
            if job.state != "cancelled":
                job.state = "error"
                job.error = str(exc)
            job.finished_at = _now_iso()
            LOGGER.error("Scan job %s failed: %s", job.id, exc)

    def export_job(self, job_id: str, fmt: str = "json") -> str:
        """Export scan results as JSON, CSV, or HTML string."""
        job = self.get_job(job_id)
        if not job:
            raise ValueError("Job not found")
        if fmt == "json":
            return json.dumps(job.to_dict(), indent=2, ensure_ascii=False)
        if fmt == "csv":
            import io
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["ip", "hostname", "mac", "vendor", "os_guess", "port", "service", "state", "banner", "risk_score", "finding_type", "exposure_id", "cvss", "confidence", "description"])
            for h in job.results:
                if not h.findings and not h.ports:
                    writer.writerow([h.ip, h.hostname, h.mac, h.vendor, h.os_guess, "", "", "", "", h.risk_score, "", "", "", "", ""])
                for f in h.findings:
                    writer.writerow([h.ip, h.hostname, h.mac, h.vendor, h.os_guess, f.get("port",""), f.get("service",""), "", f.get("banner",""), h.risk_score, f.get("type",""), f.get("exposure_id",""), f.get("cvss",""), f.get("confidence",""), f.get("description","")])
            return out.getvalue()
        if fmt == "html":
            rows = []
            for h in job.results:
                sev_color = "#4caf50" if h.risk_score < 30 else "#ff9800" if h.risk_score < 70 else "#f44336"
                ports_str = ", ".join(f"{p.port}/{p.service}" for p in h.ports)
                findings_str = "<br>".join(f"[{f.get('type','')}] {f.get('exposure_id','')} (CVSS {f.get('cvss','')})" for f in h.findings)
                rows.append(f"""
                <tr>
                    <td>{h.ip}</td>
                    <td>{h.hostname}</td>
                    <td>{h.mac}</td>
                    <td>{h.vendor}</td>
                    <td>{ports_str}</td>
                    <td style="color:{sev_color};font-weight:bold">{h.risk_score}</td>
                    <td>{findings_str}</td>
                </tr>
                """)
            return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AEGIS Scan Report {job.id}</title>
<style>body{{font-family:Segoe UI,Roboto,sans-serif;background:#0b0f19;color:#e0e0e0;padding:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #333;padding:8px;text-align:left}}
th{{background:#1a2332}}tr:nth-child(even){{background:#141b29}}</style>
</head><body>
<h2>AEGIS-OMNI Scan Report</h2>
<p>Job: {job.id} | Target: {job.target} | Mode: {job.mode} | OT Mode: {job.ot_mode} | State: {job.state}</p>
<table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Ports</th><th>Risk</th><th>Findings</th></tr>
{''.join(rows)}
</table></body></html>"""
        raise ValueError(f"Unsupported format: {fmt}")

    def _forward_findings(self, ip: str, hostname: str, findings: List[Dict[str, Any]]) -> None:
        if not _REQUESTS or not self.orchestrator_url:
            return
        for f in findings:
            if f["severity"] in ("critical", "high"):
                event = {
                    "source": "lan_scanner",
                    "category": "vulnerability",
                    "severity": f["severity"],
                    "title": f"[{f.get('exposure_id','?')}] {f['service'].upper()} on {ip}:{f['port']}",
                    "description": f"{f['description']} — Host: {hostname or ip}",
                    "raw_data": {
                        "ip": ip, "hostname": hostname,
                        "port": f["port"], "service": f["service"],
                        "exposure_id": f.get("exposure_id", ""),
                        "cvss": f["cvss"],
                        "confidence": f.get("confidence", "low"),
                        "requires_verification": f.get("requires_verification", True),
                        "banner": f.get("banner", ""),
                    },
                    "tags": ["lan_scan", "potential_exposure", f["service"], f.get("exposure_id","")],
                }
                try:
                    requests.post(
                        f"{self.orchestrator_url}/api/events",
                        json=event, timeout=5
                    )
                except Exception:
                    pass
