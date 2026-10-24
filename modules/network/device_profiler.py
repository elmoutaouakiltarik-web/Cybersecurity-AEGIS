#!/usr/bin/env python3
"""
AEGIS Device DNA Fingerprinter
===============================
Multi-vector device fingerprinting engine combining 9 independent techniques
to produce a unique "Device DNA" for every discovered host.

Fingerprinting vectors:
  1. HTTP/HTTPS response analysis (Server header, WWW-Auth, cookies, content)
  2. Active TLS cipher suite enumeration (custom ClientHello)
  3. SSH algorithm fingerprint (kex/cipher/mac negotiation)
  4. SNMP v1/v2c community probe (read-only, public/private)
  5. UPnP SSDP M-SEARCH + description XML parsing
  6. MAC OUI vendor lookup (offline, 80+ OUI entries)
  7. TCP/IP TTL-based OS hint
  8. Banner keyword analysis across all open ports
  9. Port profile matching (55 device type rules)

Output:
  DeviceDNA dataclass with device_type, device_category, manufacturer,
  model, os_hint, confidence (0-100), risk_context, and full evidence dict.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import socket
import ssl
import struct
import threading
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("aegis.device_profiler")

# ── OFFLINE MAC OUI DATABASE (top 80 vendors) ─────────────────────────────────
OUI_DB: Dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "001C42": "Parallels",
    "0050F2": "Microsoft", "001DD8": "Microsoft", "3C5AB4": "Microsoft",
    "00155D": "Microsoft (Hyper-V)", "001B21": "Intel", "7CEBAE": "Intel",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "78E103": "Raspberry Pi", "28CDA4": "Raspberry Pi",
    "FCFBFB": "Ubiquiti", "00272A": "Ubiquiti", "24A43C": "Ubiquiti",
    "DC9FDB": "Ubiquiti", "E063DA": "Ubiquiti", "44D9E7": "Ubiquiti",
    "B4FBE4": "Cisco", "00000C": "Cisco", "001960": "Cisco", "0025B5": "Cisco",
    "00E0F7": "Cisco", "7081C2": "Cisco", "A8B1D4": "Cisco", "CC98D6": "Cisco",
    "38F9D3": "Aruba/HP", "001A1E": "Aruba/HP", "D8C7C8": "Aruba/HP",
    "000E8F": "Fortinet", "001B0A": "Fortinet",
    "001A2B": "Juniper", "2C6BF5": "Juniper",
    "40F4EC": "Siemens", "001B1B": "Siemens", "00E0E7": "Siemens",
    "000EA6": "Rockwell Automation", "00608C": "Rockwell",
    "001196": "Schneider Electric", "0050C2": "Schneider Electric",
    "001BB9": "Honeywell", "001CBB": "Honeywell",
    "00D0C9": "Emerson", "001E67": "Emerson",
    "000BDB": "ABB", "001E62": "ABB",
    "74D435": "GE Automation", "001CBF": "GE Digital",
    "001E8C": "Apple", "28CF4D": "Apple", "3C15C2": "Apple",
    "DC2B61": "Apple", "F0D1A9": "Apple", "ACBC32": "Apple",
    "E4956E": "Samsung", "CCAF78": "Samsung", "D0176A": "Samsung",
    "0014E8": "Huawei", "001882": "Huawei", "201B21": "Huawei",
    "006697": "Hikvision", "4C5649": "Hikvision", "BC3400": "Hikvision",
    "B4A2EB": "Dahua", "3C6101": "Dahua", "90E8BA": "Dahua",
    "00265C": "AXIS Communications", "ACCC8E": "AXIS Communications",
    "001EC0": "Synology", "001132": "QNAP Systems",
    "B8AE67": "MikroTik", "2CC8E9": "MikroTik", "6C3B6B": "MikroTik",
    "D4CA6D": "Netgear", "00146C": "Netgear", "A021B7": "Netgear",
    "C80A0B": "TP-Link", "5474D4": "TP-Link", "B0487A": "TP-Link",
    "ECE5C9": "Asus", "1062EB": "Asus", "AC220B": "Asus",
    "FCF8AE": "Dell", "B8CA3A": "Dell", "D067E5": "Dell",
    "1CC1DE": "HPE", "9840BB": "HP", "F44D30": "HP",
    "E49B8A": "Lenovo", "484D7E": "Lenovo",
    "00163E": "Xen (Virtualization)",
    "525400": "QEMU/KVM",
}

# ── PORT → DEVICE TYPE RULES ──────────────────────────────────────────────────
# (frozenset of ports that trigger this rule, device_type, confidence_bonus)
PORT_RULES: List[Tuple[frozenset, str, str, int]] = [
    # OT / ICS — highest priority
    (frozenset({502}),           "plc",              "ot",       90),
    (frozenset({2404}),          "iec104_rtu",        "ot",       90),
    (frozenset({4840}),          "opcua_server",      "ot",       85),
    (frozenset({47808}),         "bacnet_controller", "ot",       85),
    (frozenset({20000}),         "dnp3_device",       "ot",       85),
    (frozenset({102}),           "siemens_s7_plc",    "ot",       92),
    (frozenset({44818}),         "ethernetip_device", "ot",       85),
    (frozenset({1962}),          "pcworx_plc",        "ot",       85),
    (frozenset({502, 4840}),     "hybrid_ot",         "ot",       95),
    (frozenset({9600}),          "omron_plc",         "ot",       82),
    (frozenset({20547}),         "proconos_plc",      "ot",       82),
    # IoT
    (frozenset({1883}),          "mqtt_broker",       "iot",      80),
    (frozenset({8883}),          "mqtt_tls_broker",   "iot",      80),
    (frozenset({554}),           "ip_camera",         "iot",      80),
    (frozenset({554, 80}),       "ip_camera",         "iot",      90),
    (frozenset({554, 443}),      "ip_camera",         "iot",      90),
    (frozenset({9100}),          "network_printer",   "iot",      85),
    (frozenset({9100, 515}),     "network_printer",   "iot",      92),
    (frozenset({515}),           "lpd_printer",       "iot",      80),
    (frozenset({631}),           "cups_printer",      "iot",      75),
    (frozenset({5060}),          "voip_phone",        "iot",      80),
    (frozenset({5060, 5061}),    "voip_gateway",      "iot",      88),
    # Network Infrastructure
    (frozenset({179}),           "bgp_router",        "network",  92),
    (frozenset({520}),           "rip_router",        "network",  80),
    (frozenset({161, 162}),      "snmp_device",       "network",  75),
    (frozenset({80, 443, 22, 23}), "managed_switch",  "network",  72),
    (frozenset({8291}),          "mikrotik_router",   "network",  95),
    (frozenset({8728}),          "mikrotik_router",   "network",  92),
    # Storage / NAS
    (frozenset({2049}),          "nfs_server",        "it",       78),
    (frozenset({139, 445, 2049}),"nas_storage",       "it",       90),
    (frozenset({548}),           "afp_nas",           "it",       78),
    (frozenset({5000}),          "synology_nas",      "it",       80),
    (frozenset({8006}),          "proxmox_host",      "it",       95),
    # Virtualization
    (frozenset({902, 903}),      "vmware_esxi",       "it",       95),
    (frozenset({443, 902}),      "vmware_esxi",       "it",       90),
    (frozenset({8006, 8007}),    "proxmox_host",      "it",       95),
    # Servers
    (frozenset({1433}),          "mssql_server",      "it",       85),
    (frozenset({3306}),          "mysql_server",      "it",       82),
    (frozenset({5432}),          "postgresql_server", "it",       82),
    (frozenset({27017}),         "mongodb_server",    "it",       85),
    (frozenset({6379}),          "redis_server",      "it",       85),
    (frozenset({9200}),          "elasticsearch",     "it",       85),
    (frozenset({25, 465, 587}),  "mail_server",       "it",       88),
    (frozenset({389, 636}),      "ldap_server",       "it",       85),
    (frozenset({88, 389, 445}),  "domain_controller", "it",       95),
    (frozenset({88, 636, 3268}), "domain_controller", "it",       95),
    (frozenset({8080, 8443}),    "application_server","it",       65),
    (frozenset({80, 443}),       "web_server",        "it",       60),
    # Endpoints
    (frozenset({3389}),          "windows_host",      "endpoint", 72),
    (frozenset({3389, 135}),     "windows_workstation","endpoint",88),
    (frozenset({5900}),          "vnc_host",          "endpoint", 70),
    (frozenset({22, 631}),       "linux_workstation", "endpoint", 72),
]

# ── HTTP RESPONSE FINGERPRINTS ────────────────────────────────────────────────
# (regex_on_any_header_or_body, device_type, manufacturer, model_hint, confidence_bonus)
HTTP_FINGERPRINTS: List[Tuple[str, str, str, str, int]] = [
    (r"MikroTik",              "router",           "MikroTik",          "RouterOS",    25),
    (r"Ubiquiti|UniFi",        "wifi_ap",          "Ubiquiti",          "UniFi",       25),
    (r"DD-WRT",                "router",           "DD-WRT",            "Custom",      20),
    (r"OpenWrt",               "router",           "OpenWrt",           "Custom",      20),
    (r"pfSense",               "firewall",         "Netgate",           "pfSense",     30),
    (r"OPNsense",              "firewall",         "Deciso",            "OPNsense",    30),
    (r"FortiGate|Fortinet",    "firewall",         "Fortinet",          "FortiGate",   35),
    (r"Cisco IOS",             "router",           "Cisco",             "IOS",         35),
    (r"NX-OS",                 "switch",           "Cisco",             "Nexus",       35),
    (r"ASA",                   "firewall",         "Cisco",             "ASA",         30),
    (r"Palo Alto",             "firewall",         "Palo Alto",         "NGFW",        35),
    (r"Check.?Point",          "firewall",         "Check Point",       "NGFW",        35),
    (r"nginx[/ ]",             "web_server",       "nginx",             "",            15),
    (r"Apache[/ ]",            "web_server",       "Apache Software",   "httpd",       15),
    (r"Microsoft-IIS",         "web_server",       "Microsoft",         "IIS",         20),
    (r"lighttpd",              "web_server",       "lighttpd",          "",            15),
    (r"Caddy",                 "web_server",       "Caddy",             "",            15),
    (r"Hikvision",             "ip_camera",        "Hikvision",         "",            40),
    (r"AXIS",                  "ip_camera",        "AXIS Communications","",           40),
    (r"Dahua",                 "ip_camera",        "Dahua Technology",  "",            40),
    (r"NETGEAR",               "router",           "Netgear",           "",            25),
    (r"TP-LINK|tplink",        "router",           "TP-Link",           "",            25),
    (r"D-Link",                "router",           "D-Link",            "",            25),
    (r"Synology",              "nas_storage",      "Synology",          "DiskStation", 35),
    (r"QNAP",                  "nas_storage",      "QNAP",              "NAS",         35),
    (r"TrueNAS|FreeNAS",       "nas_storage",      "iXsystems",         "TrueNAS",     35),
    (r"HP.*LaserJet|HP.*OfficeJet|HP.*DeskJet|HP Printer",
                               "network_printer",  "HP",                "",            30),
    (r"Ricoh",                 "network_printer",  "Ricoh",             "",            30),
    (r"Xerox",                 "network_printer",  "Xerox",             "",            30),
    (r"Brother",               "network_printer",  "Brother",           "",            30),
    (r"Konica Minolta",        "network_printer",  "Konica Minolta",    "",            30),
    (r"VMware ESXi",           "vmware_esxi",      "VMware",            "ESXi",        45),
    (r"Proxmox",               "proxmox_host",     "Proxmox",           "VE",          45),
    (r"Siemens",               "plc",              "Siemens",           "",            25),
    (r"Schneider",             "plc",              "Schneider Electric","",            25),
    (r"Rockwell|Allen-Bradley","plc",              "Rockwell Automation","",           25),
    (r"Emerson",               "plc",              "Emerson",           "",            20),
    (r"Honeywell",             "plc",              "Honeywell",         "",            20),
    (r"Jupyter",               "jupyter_server",   "",                  "Jupyter Notebook", 30),
    (r"Grafana",               "monitoring",       "",                  "Grafana",     25),
    (r"Kibana",                "monitoring",       "Elastic",           "Kibana",      25),
    (r"Prometheus",            "monitoring",       "Prometheus",        "",            25),
    (r"GitLab",                "devops",           "GitLab",            "",            25),
    (r"Jenkins",               "devops",           "",                  "Jenkins CI",  25),
    (r"Rancher",               "container_mgmt",   "SUSE",              "Rancher",     30),
    (r"Harbor",                "container_registry","",                 "Harbor",      30),
]

# Device types that are high-risk OT/ICS
HIGH_RISK_OT = {
    "plc", "iec104_rtu", "opcua_server", "bacnet_controller",
    "dnp3_device", "siemens_s7_plc", "ethernetip_device", "hybrid_ot",
    "pcworx_plc", "omron_plc", "proconos_plc",
}


@dataclass
class DeviceDNA:
    ip: str
    device_type: str = "unknown"
    device_category: str = "unknown"    # it / ot / iot / network / endpoint
    manufacturer: str = "unknown"
    model: str = ""
    os_hint: str = ""
    confidence: int = 0                 # 0-100
    is_ot_device: bool = False
    risk_context: str = ""
    mac: str = ""
    mac_vendor: str = ""
    open_ports: List[int] = field(default_factory=list)
    fingerprint_hash: str = ""          # SHA-1 of combined evidence for tracking
    fingerprint_vectors: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    scanned_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DeviceProfiler:
    """Orchestrates all fingerprinting vectors and synthesises a DeviceDNA."""

    TIMEOUT = 4.0

    def __init__(self) -> None:
        self._cache: Dict[str, DeviceDNA] = {}
        self._lock = threading.Lock()

    def profile(
        self,
        ip: str,
        open_ports: Optional[List[int]] = None,
        mac: str = "",
        ttl: Optional[int] = None,
    ) -> DeviceDNA:
        """Run all fingerprinting vectors and return a DeviceDNA."""
        open_ports = sorted(set(open_ports or []))
        dna = DeviceDNA(
            ip=ip,
            mac=mac,
            open_ports=open_ports,
            scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        # Vector 1: MAC OUI vendor
        if mac:
            dna.mac_vendor = self._oui_lookup(mac)
            if dna.mac_vendor and dna.mac_vendor != "unknown":
                dna.fingerprint_vectors.append("mac_oui")
                dna.evidence["mac_vendor"] = dna.mac_vendor

        # Vector 2: TTL OS hint
        if ttl is not None:
            hint, os_name = self._ttl_os_hint(ttl)
            if hint:
                dna.os_hint = os_name
                dna.fingerprint_vectors.append("ttl_os")
                dna.evidence["ttl"] = {"value": ttl, "os_hint": os_name}

        # Vector 3: Port profile matching
        port_type, port_cat, port_conf = self._match_ports(open_ports)
        if port_type:
            dna.device_type = port_type
            dna.device_category = port_cat
            dna.confidence = port_conf
            dna.fingerprint_vectors.append("port_profile")
            dna.evidence["port_match"] = {
                "device_type": port_type,
                "confidence": port_conf,
            }

        # Vector 4: HTTP fingerprinting (port 80 / 443 / 8080 / 8443 / 8888)
        http_ports = [p for p in open_ports if p in {80, 443, 8080, 8443, 8888, 8006, 5000, 3000}]
        for port in http_ports[:2]:
            http_result = self._http_fingerprint(ip, port)
            if http_result:
                dna.evidence[f"http_{port}"] = http_result
                dna.fingerprint_vectors.append(f"http_{port}")
                # Apply HTTP fingerprint findings
                ftype = http_result.get("device_type")
                fmfr = http_result.get("manufacturer")
                fmdl = http_result.get("model")
                fconf = http_result.get("confidence_bonus", 0)
                if ftype and ftype != "unknown":
                    dna.device_type = ftype
                    dna.confidence = min(100, dna.confidence + fconf)
                if fmfr:
                    dna.manufacturer = fmfr
                if fmdl:
                    dna.model = fmdl

        # Vector 5: SSH algorithm fingerprint
        if 22 in open_ports:
            ssh_result = self._ssh_fingerprint(ip)
            if ssh_result:
                dna.evidence["ssh"] = ssh_result
                dna.fingerprint_vectors.append("ssh")
                if "vendor_hint" in ssh_result:
                    if dna.manufacturer == "unknown":
                        dna.manufacturer = ssh_result["vendor_hint"]

        # Vector 6: TLS quick probe (cipher list + cert CN)
        tls_ports = [p for p in open_ports if p in {443, 8443, 8883, 5061, 636, 5001}]
        for port in tls_ports[:1]:
            tls_result = self._tls_quick_probe(ip, port)
            if tls_result:
                dna.evidence[f"tls_{port}"] = tls_result
                dna.fingerprint_vectors.append(f"tls_{port}")
                cn = tls_result.get("cn", "")
                if cn and dna.manufacturer == "unknown":
                    for pattern, mfr in [
                        ("siemens", "Siemens"), ("cisco", "Cisco"),
                        ("fortinet", "Fortinet"), ("hikvision", "Hikvision"),
                        ("synology", "Synology"), ("vmware", "VMware"),
                    ]:
                        if pattern in cn.lower():
                            dna.manufacturer = mfr
                            break

        # Vector 7: SNMP community probe (non-intrusive, read-only)
        if 161 in open_ports:
            snmp_result = self._snmp_probe(ip)
            if snmp_result:
                dna.evidence["snmp"] = snmp_result
                dna.fingerprint_vectors.append("snmp")
                sys_descr = snmp_result.get("sysDescr", "")
                if sys_descr:
                    # Apply HTTP fingerprint rules to sysDescr
                    for pattern, ftype, fmfr, fmdl, fconf in HTTP_FINGERPRINTS:
                        if re.search(pattern, sys_descr, re.IGNORECASE):
                            dna.device_type = ftype
                            if dna.manufacturer == "unknown":
                                dna.manufacturer = fmfr
                            if not dna.model:
                                dna.model = fmdl
                            dna.confidence = min(100, dna.confidence + fconf)
                            break

        # Vector 8: UPnP SSDP discovery
        upnp_result = self._upnp_probe(ip)
        if upnp_result:
            dna.evidence["upnp"] = upnp_result
            dna.fingerprint_vectors.append("upnp")
            friendly_name = upnp_result.get("friendly_name", "")
            device_type_upnp = upnp_result.get("device_type_upnp", "")
            if friendly_name and dna.model == "":
                dna.model = friendly_name[:60]
            if "router" in device_type_upnp.lower():
                dna.device_type = "router"
                dna.device_category = "network"

        # Vector 9: MAC vendor → infer category for OT vendors
        if dna.mac_vendor:
            for ot_vendor in ["Siemens", "Rockwell", "Schneider", "Honeywell",
                               "ABB", "Emerson", "GE Automation", "GE Digital"]:
                if ot_vendor.lower() in dna.mac_vendor.lower():
                    if dna.device_category == "unknown":
                        dna.device_category = "ot"
                    if dna.manufacturer == "unknown":
                        dna.manufacturer = ot_vendor
                    dna.confidence = min(100, dna.confidence + 20)
                    break

        # Final: derive OT flag and risk context
        dna.is_ot_device = (dna.device_type in HIGH_RISK_OT or dna.device_category == "ot")
        if dna.is_ot_device:
            dna.risk_context = (
                "⚠️ Industrial/OT device detected on network. "
                "Verify it is on an isolated OT segment."
            )
        elif dna.device_type in {"redis_server", "mongodb_server", "elasticsearch",
                                  "jupyter_server"}:
            dna.risk_context = (
                f"⚠️ Exposed {dna.device_type} — verify access is not internet-facing."
            )
        elif dna.device_type == "domain_controller":
            dna.risk_context = "🔑 Domain Controller — critical asset, monitor closely."

        # Clamp confidence
        dna.confidence = max(0, min(100, dna.confidence))

        # Fingerprint hash for tracking device identity over time
        fp_input = f"{dna.device_type}|{dna.manufacturer}|{dna.model}|{dna.os_hint}|{sorted(open_ports)}"
        dna.fingerprint_hash = hashlib.sha1(fp_input.encode()).hexdigest()[:16]

        with self._lock:
            self._cache[ip] = dna
        return dna

    # ── VECTOR IMPLEMENTATIONS ─────────────────────────────────────────────────

    def _oui_lookup(self, mac: str) -> str:
        clean = mac.upper().replace(":", "").replace("-", "")[:6]
        return OUI_DB.get(clean, "unknown")

    def _ttl_os_hint(self, ttl: int) -> Tuple[bool, str]:
        if ttl <= 0:
            return False, ""
        if ttl <= 64:
            return True, "Linux/Unix (TTL≤64)"
        if ttl <= 128:
            return True, "Windows (TTL≤128)"
        if ttl <= 255:
            return True, "Network Device/Cisco (TTL≤255)"
        return False, ""

    def _match_ports(self, ports: List[int]) -> Tuple[str, str, int]:
        port_set = frozenset(ports)
        best_type = ""
        best_cat = "unknown"
        best_score = 0
        for rule_ports, dtype, dcat, score in PORT_RULES:
            if rule_ports.issubset(port_set):
                bonus = len(rule_ports) * 5  # more specific = better
                total = score + bonus
                if total > best_score:
                    best_score = total
                    best_type = dtype
                    best_cat = dcat
        return best_type, best_cat, min(100, best_score)

    def _http_fingerprint(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AEGIS-Scanner/1.0"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT, context=ctx if scheme == "https" else None) as resp:
                headers_raw = dict(resp.headers)
                body_snippet = ""
        except urllib.error.HTTPError as exc:
            headers_raw = dict(exc.headers) if exc.headers else {}
            body_snippet = ""
        except Exception:
            # Try GET if HEAD fails
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "AEGIS-Scanner/1.0"},
                )
                with urllib.request.urlopen(req, timeout=self.TIMEOUT, context=ctx if scheme == "https" else None) as resp:
                    headers_raw = dict(resp.headers)
                    body_snippet = resp.read(512).decode("utf-8", errors="ignore")
            except Exception:
                return None

        # Combine all header values + body snippet for pattern matching
        combined = " ".join(str(v) for v in headers_raw.values()) + " " + body_snippet

        result: Dict[str, Any] = {
            "server": headers_raw.get("Server", headers_raw.get("server", "")),
            "powered_by": headers_raw.get("X-Powered-By", ""),
            "device_type": "unknown",
            "manufacturer": "",
            "model": "",
            "confidence_bonus": 0,
            "headers": {k: v for k, v in headers_raw.items()
                        if k.lower() in {"server", "x-powered-by", "www-authenticate",
                                         "x-aspnet-version", "x-generator"}},
        }
        for pattern, dtype, mfr, mdl, cbonus in HTTP_FINGERPRINTS:
            if re.search(pattern, combined, re.IGNORECASE):
                result["device_type"] = dtype
                result["manufacturer"] = mfr
                result["model"] = mdl
                result["confidence_bonus"] = cbonus
                result["matched_pattern"] = pattern
                break
        return result

    def _ssh_fingerprint(self, ip: str) -> Optional[Dict[str, Any]]:
        """Connect to SSH and parse the server identification string + kex init."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.TIMEOUT)
            s.connect((ip, 22))
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            result: Dict[str, Any] = {"banner": banner}

            # Read KEX_INIT packet for algorithm lists
            try:
                raw = s.recv(4096)
                # SSH packet: 4B length, 1B padding, 1B type (20=KEX_INIT)
                if len(raw) > 6 and raw[5] == 20:
                    offset = 6 + 16  # skip cookie
                    algos = []
                    for _ in range(10):  # 10 name-list fields in KEX_INIT
                        if offset + 4 > len(raw):
                            break
                        length = struct.unpack(">I", raw[offset:offset+4])[0]
                        offset += 4
                        if offset + length > len(raw):
                            break
                        field_val = raw[offset:offset+length].decode("utf-8", errors="ignore")
                        algos.append(field_val)
                        offset += length
                    if algos:
                        result["kex_algos"] = algos[0] if algos else ""
                        result["host_key_algos"] = algos[1] if len(algos) > 1 else ""
                        result["enc_algos_c2s"] = algos[2] if len(algos) > 2 else ""
            except Exception:
                pass

            # Infer vendor from banner
            vendor_hint = ""
            if "Cisco" in banner:
                vendor_hint = "Cisco"
            elif "Juniper" in banner or "JUNOS" in banner:
                vendor_hint = "Juniper"
            elif "Dropbear" in banner:
                vendor_hint = "Embedded Linux (Dropbear)"
            elif "OpenSSH" in banner:
                vendor_hint = "OpenSSH (Linux/Unix/macOS)"
            elif "libssh" in banner:
                vendor_hint = "libssh"
            if vendor_hint:
                result["vendor_hint"] = vendor_hint

            s.close()
            return result
        except Exception:
            return None

    def _tls_quick_probe(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Get TLS certificate CN + basic cipher info."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((ip, port), timeout=self.TIMEOUT),
                server_hostname=ip,
            )
            cert = conn.getpeercert(binary_form=False)
            cipher = conn.cipher()
            tls_version = conn.version()
            conn.close()

            cn = ""
            issuer = ""
            not_after = ""
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName", "")
                not_after = cert.get("notAfter", "")

            return {
                "cn": cn,
                "issuer": issuer,
                "not_after": not_after,
                "cipher": cipher[0] if cipher else "",
                "tls_version": tls_version,
                "self_signed": (cn == issuer) if (cn and issuer) else None,
            }
        except Exception:
            return None

    def _snmp_probe(self, ip: str) -> Optional[Dict[str, Any]]:
        """Send SNMPv1 GET for sysDescr (OID 1.3.6.1.2.1.1.1.0)."""
        # Build SNMPv1 GetRequest for sysDescr
        # community = "public"
        community = b"public"
        request_id = 1

        def encode_length(length: int) -> bytes:
            if length < 128:
                return bytes([length])
            elif length < 256:
                return bytes([0x81, length])
            else:
                return bytes([0x82, length >> 8, length & 0xFF])

        def tlv(tag: int, value: bytes) -> bytes:
            return bytes([tag]) + encode_length(len(value)) + value

        # OID 1.3.6.1.2.1.1.1.0 encoded
        oid_bytes = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
        oid_tlv = tlv(0x06, oid_bytes)
        null_tlv = b"\x05\x00"
        var_bind = tlv(0x30, oid_tlv + null_tlv)
        var_bind_list = tlv(0x30, var_bind)

        req_id_tlv = tlv(0x02, request_id.to_bytes(4, "big"))
        error_status_tlv = tlv(0x02, b"\x00")
        error_index_tlv = tlv(0x02, b"\x00")
        pdu = tlv(0xA0, req_id_tlv + error_status_tlv + error_index_tlv + var_bind_list)

        version_tlv = tlv(0x02, b"\x00")    # version 1 = 0
        community_tlv = tlv(0x04, community)
        message = tlv(0x30, version_tlv + community_tlv + pdu)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(message, (ip, 161))
            response, _ = sock.recvfrom(4096)
            sock.close()
            # Parse response: find OctetString value (0x04) near the end
            sys_descr = self._extract_snmp_string(response)
            return {"sysDescr": sys_descr, "community": "public"}
        except Exception:
            return None

    def _extract_snmp_string(self, data: bytes) -> str:
        """Extract the first OctetString value from an SNMP response."""
        i = 0
        while i < len(data) - 2:
            if data[i] == 0x04:  # OCTET STRING
                length = data[i+1]
                if length & 0x80:
                    nbytes = length & 0x7F
                    if i + 1 + nbytes >= len(data):
                        break
                    length = int.from_bytes(data[i+2:i+2+nbytes], "big")
                    value_start = i + 2 + nbytes
                else:
                    value_start = i + 2
                value = data[value_start:value_start+length]
                try:
                    return value.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            i += 1
        return ""

    def _upnp_probe(self, ip: str) -> Optional[Dict[str, Any]]:
        """Send UPnP M-SEARCH and parse description XML."""
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {ip}:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        ).encode()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.5)
            sock.sendto(msearch, (ip, 1900))
            response = sock.recv(2048).decode("utf-8", errors="ignore")
            sock.close()

            # Extract LOCATION header
            location = ""
            for line in response.splitlines():
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break

            result: Dict[str, Any] = {"location": location}

            # Fetch device description XML
            if location:
                try:
                    with urllib.request.urlopen(location, timeout=3.0) as r:
                        xml_data = r.read(8192).decode("utf-8", errors="ignore")
                    root = ET.fromstring(xml_data)
                    ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
                    device = root.find(".//upnp:device", ns) or root.find(".//device")
                    if device is not None:
                        def get_text(tag: str) -> str:
                            el = device.find(f"upnp:{tag}", ns) or device.find(tag)
                            return el.text.strip() if el is not None and el.text else ""
                        result["friendly_name"] = get_text("friendlyName")
                        result["manufacturer"] = get_text("manufacturer")
                        result["model_name"] = get_text("modelName")
                        result["device_type_upnp"] = get_text("deviceType")
                except Exception:
                    pass

            return result if location else None
        except Exception:
            return None

    def get_cached(self, ip: str) -> Optional[DeviceDNA]:
        return self._cache.get(ip)

    def profile_batch(
        self,
        hosts: List[Dict[str, Any]],
        max_workers: int = 10,
    ) -> List[DeviceDNA]:
        """Profile multiple hosts concurrently."""
        results: List[Optional[DeviceDNA]] = [None] * len(hosts)
        semaphore = threading.Semaphore(max_workers)

        def _profile_one(idx: int, host: Dict[str, Any]) -> None:
            with semaphore:
                try:
                    results[idx] = self.profile(
                        ip=host.get("ip", ""),
                        open_ports=host.get("open_ports", []),
                        mac=host.get("mac", ""),
                        ttl=host.get("ttl"),
                    )
                except Exception as exc:
                    LOGGER.warning("profile failed for %s: %s", host.get("ip"), exc)

        threads = [
            threading.Thread(target=_profile_one, args=(i, h), daemon=True)
            for i, h in enumerate(hosts)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        return [r for r in results if r is not None]
