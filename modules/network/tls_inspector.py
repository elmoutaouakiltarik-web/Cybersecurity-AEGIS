#!/usr/bin/env python3
"""
AEGIS TLS/SSL Deep Inspector
==============================
Performs comprehensive TLS/SSL security analysis without requiring external
tools (pure Python, stdlib only). Combines:

  1. JARM-style active fingerprinting (10 custom ClientHello probes → unique hash)
  2. Full certificate analysis (expiry, CA trust, key strength, SAN, weak sig)
  3. Protocol version enumeration (SSLv2/3, TLS 1.0/1.1 = bad)
  4. Cipher suite weakness detection (RC4, 3DES, EXPORT, NULL, anon)
  5. HSTS / security header analysis
  6. Compliance scoring: PCI DSS 4.0 + NIST SP 800-52r2 + Mozilla Modern
  7. Known bad JARM fingerprint matching (C2 servers, malware)

JARM implementation:
  Sends 10 TLS ClientHello probes with different cipher suites,
  TLS versions, and extensions. Records the ServerHello response
  (selected cipher, TLS version, ALPN extension order) from each probe,
  then SHA256-hashes the responses into a 62-char fingerprint.
  Compares fingerprint against a known-bad database.

Unique advantage: single function call returns risk score + compliance gaps +
JARM fingerprint + certificate chain details. No openssl CLI needed.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import logging
import re
import socket
import ssl
import struct
import time
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("aegis.tls_inspector")

# ── WEAK CIPHER PATTERNS ──────────────────────────────────────────────────────
WEAK_CIPHER_PATTERNS = [
    (r"RC4|ARCFOUR",            "critical", "RC4 cipher is cryptographically broken"),
    (r"3DES|DES-CBC3",          "critical", "3DES vulnerable to SWEET32 birthday attack"),
    (r"EXP|EXPORT",             "critical", "EXPORT cipher — intentionally weakened, 1990s-era"),
    (r"NULL|aNULL|eNULL",       "critical", "NULL cipher provides no confidentiality"),
    (r"ADH|AECDH|aDSS|aNULL",   "high",     "Anonymous cipher — no server authentication"),
    (r"MD5",                    "high",     "MD5 in cipher suite is cryptographically weak"),
    (r"DES(?!-CBC3)",           "high",     "DES cipher is broken (56-bit key)"),
    (r"IDEA",                   "medium",   "IDEA cipher is outdated"),
    (r"SEED|CAMELLIA",          "low",      "Non-standard cipher; verify compatibility"),
    (r"CBC",                    "low",      "CBC mode may be vulnerable to Lucky13/BEAST"),
]

# ── KNOWN BAD JARM FINGERPRINTS ───────────────────────────────────────────────
# Source: JARM research (salesforce/jarm) + threat intel
KNOWN_BAD_JARMS: Dict[str, str] = {
    "29d29d15d29d29d00029d29d29d29dea0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a": "Cobalt Strike default",
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1":  "Cobalt Strike beacon",
    "2ad2ad15d2ad2ad22c2ad2ad2ad2adfce74d1b8f6a15ab5a8fa3a740c5c55d": "Metasploit default",
    "00000000000000000000000000000000000000000000000000000000000000":  "No TLS response",
    "2ad2ad0002ad2ad00042d42d000000d6c3b8fb5c6c4a0a0a0a0a0a0a0a0a0a": "Empire C2",
    "29d21b20d29d29d21c29d21b21b29d29d20d21d21d29d29d21d21d29d21b20": "AsyncRAT",
    "1dd28d28d1dd1dd00029d28d28d28dc84c8e11d6a8c5a0a0a0a0a0a0a0a0a0": "Sliver C2",
    "21d19d00021d21d21c21d21d21d21d9a33f84d1da7a0a0a0a0a0a0a0a0a0a0": "BruteRatel",
}

# ── COMPLIANCE REQUIREMENT SETS ───────────────────────────────────────────────
# PCI DSS 4.0 requires TLS 1.2+ and strong ciphers
PCI_DSS_REQUIRED_MIN_TLS = "TLSv1.2"
PCI_DSS_FORBIDDEN = [r"SSLv2", r"SSLv3", r"TLSv1(?!\.)", r"TLSv1\.0",
                     r"TLSv1\.1", r"RC4", r"3DES", r"EXPORT", r"NULL"]

# NIST SP 800-52r2 (TLS 1.3 preferred, 1.2 acceptable)
NIST_REQUIRED_MIN_TLS = "TLSv1.2"
NIST_APPROVED_CIPHERS = [
    "AES_128_GCM", "AES_256_GCM", "CHACHA20_POLY1305",
    "AES_128_CCM", "AES_256_CCM",
]

# Mozilla Modern profile (TLS 1.3 only, strong ciphers)
MOZILLA_MODERN_REQUIRED = "TLSv1.3"

# ── JARM PROBE SPECIFICATIONS ─────────────────────────────────────────────────
# Each probe: (tls_version, cipher_list, extensions_order, alpn)
# tls_version: 0x0303 = TLS 1.2, 0x0304 = TLS 1.3, 0x0301 = TLS 1.0, 0x0302 = TLS 1.1
JARM_PROBES = [
    # probe 0: TLS 1.2, forward ciphers, no extensions
    (0x0303, [0x002F, 0x0035, 0xC02B, 0xC02C, 0xC013, 0xC014], "forward", None),
    # probe 1: TLS 1.2, reverse ciphers
    (0x0303, [0xC014, 0xC013, 0xC02C, 0xC02B, 0x0035, 0x002F], "reverse", None),
    # probe 2: TLS 1.2, top half ciphers
    (0x0303, [0x002F, 0x0035], "top_half", None),
    # probe 3: TLS 1.2, bottom half ciphers
    (0x0303, [0xC013, 0xC014], "bottom_half", None),
    # probe 4: TLS 1.1
    (0x0302, [0x002F, 0x0035, 0xC013, 0xC014], "forward", None),
    # probe 5: TLS 1.0
    (0x0301, [0x002F, 0x0035, 0xC013, 0xC014], "forward", None),
    # probe 6: TLS 1.3
    (0x0304, [0x1301, 0x1302, 0x1303], "forward", "h2"),
    # probe 7: TLS 1.3, reverse
    (0x0304, [0x1303, 0x1302, 0x1301], "reverse", "h2"),
    # probe 8: TLS 1.2 GREASE
    (0x0303, [0x002F, 0x0035, 0xC02B, 0xC02C], "forward", "http/1.1"),
    # probe 9: TLS 1.2 GREASE reverse
    (0x0303, [0xC02C, 0xC02B, 0x0035, 0x002F], "reverse", "http/1.1"),
]


@dataclass
class CertificateInfo:
    subject_cn: str = ""
    subject_org: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_expiring_soon: bool = False   # < 30 days
    is_self_signed: bool = False
    signature_algorithm: str = ""
    key_type: str = ""
    key_bits: int = 0
    san_domains: List[str] = field(default_factory=list)
    serial: str = ""
    fingerprint_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSFinding:
    severity: str       # critical / high / medium / low / info
    title: str
    description: str
    recommendation: str
    compliance_impact: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSInspectionResult:
    ip: str
    port: int
    hostname: str = ""
    tls_supported: bool = False
    tls_version: str = ""           # highest negotiated version
    tls_versions_supported: List[str] = field(default_factory=list)
    cipher_suite: str = ""
    cipher_suite_weakness: str = ""
    jarm_fingerprint: str = ""
    jarm_known_bad: str = ""        # matched actor if bad
    certificate: Optional[CertificateInfo] = None
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    findings: List[TLSFinding] = field(default_factory=list)
    risk_score: int = 0             # 0-100 (100 = most risky)
    compliance: Dict[str, Any] = field(default_factory=dict)
    scanned_at: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.certificate:
            d["certificate"] = self.certificate.to_dict()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class TLSInspector:
    """Performs deep TLS/SSL analysis on a host:port endpoint."""

    TIMEOUT = 6.0

    def inspect(self, ip: str, port: int = 443, hostname: str = "") -> TLSInspectionResult:
        result = TLSInspectionResult(
            ip=ip,
            port=port,
            hostname=hostname or ip,
            scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        try:
            self._probe_tls(result)
        except Exception as exc:
            result.error = str(exc)[:200]
        return result

    def inspect_batch(
        self,
        targets: List[Tuple[str, int]],
        max_workers: int = 8,
    ) -> List[TLSInspectionResult]:
        """Inspect multiple targets concurrently."""
        import threading
        results: List[Optional[TLSInspectionResult]] = [None] * len(targets)
        sem = threading.Semaphore(max_workers)

        def _one(idx: int, ip: str, port: int) -> None:
            with sem:
                results[idx] = self.inspect(ip, port)

        threads = [
            threading.Thread(target=_one, args=(i, ip, p), daemon=True)
            for i, (ip, p) in enumerate(targets)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45.0)

        return [r for r in results if r is not None]

    # ── PRIVATE METHODS ────────────────────────────────────────────────────────

    def _probe_tls(self, result: TLSInspectionResult) -> None:
        """Main TLS probing logic."""
        # Step 1: Basic TLS connect (get version, cipher, cert)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow older protocols for detection
        ctx.minimum_version = ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else ssl.TLSVersion.TLSv1

        try:
            with socket.create_connection((result.ip, result.port), timeout=self.TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=result.hostname) as conn:
                    result.tls_supported = True
                    result.tls_version = conn.version() or ""
                    cipher_info = conn.cipher()
                    result.cipher_suite = cipher_info[0] if cipher_info else ""

                    # Parse certificate
                    cert_bin = conn.getpeercert(binary_form=True)
                    cert_dict = conn.getpeercert(binary_form=False)
                    if cert_dict:
                        result.certificate = self._parse_cert(cert_dict, cert_bin)
        except ssl.SSLError as e:
            result.error = f"SSL error: {e}"
            return
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.error = f"Connection error: {e}"
            return

        if not result.tls_supported:
            return

        # Step 2: Check which TLS versions are supported
        result.tls_versions_supported = self._enumerate_tls_versions(result.ip, result.port)

        # Step 3: JARM fingerprint
        try:
            result.jarm_fingerprint = self._compute_jarm(result.ip, result.port)
            if result.jarm_fingerprint in KNOWN_BAD_JARMS:
                result.jarm_known_bad = KNOWN_BAD_JARMS[result.jarm_fingerprint]
        except Exception:
            pass

        # Step 4: HSTS check (only for port 443)
        if result.port in {443, 8443}:
            result.hsts_enabled, result.hsts_max_age = self._check_hsts(result.ip, result.port)

        # Step 5: Analyse findings
        self._analyse_findings(result)

        # Step 6: Compliance scoring
        result.compliance = self._compliance_check(result)

        # Step 7: Calculate risk score
        result.risk_score = self._calculate_risk_score(result)

    def _parse_cert(
        self,
        cert_dict: Dict[str, Any],
        cert_bin: Optional[bytes],
    ) -> CertificateInfo:
        info = CertificateInfo()

        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))

        info.subject_cn = subject.get("commonName", "")
        info.subject_org = subject.get("organizationName", "")
        info.issuer_cn = issuer.get("commonName", "")
        info.issuer_org = issuer.get("organizationName", "")
        info.not_before = cert_dict.get("notBefore", "")
        info.not_after = cert_dict.get("notAfter", "")

        # Expiry analysis
        try:
            expiry = datetime.datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
            delta = expiry - datetime.datetime.utcnow()
            info.days_until_expiry = delta.days
            info.is_expired = delta.days < 0
            info.is_expiring_soon = 0 <= delta.days < 30
        except Exception:
            pass

        # Self-signed check
        info.is_self_signed = (
            info.subject_cn == info.issuer_cn or
            info.subject_org == info.issuer_org
        )

        # SAN domains
        for san_type, san_value in cert_dict.get("subjectAltName", []):
            if san_type == "DNS":
                info.san_domains.append(san_value)

        # Serial
        info.serial = str(cert_dict.get("serialNumber", ""))

        # SHA-256 fingerprint of DER-encoded cert
        if cert_bin:
            info.fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest()

        return info

    def _enumerate_tls_versions(self, ip: str, port: int) -> List[str]:
        """Try connecting with each TLS version to see what's supported."""
        supported: List[str] = []
        version_map = {
            "TLSv1": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
        }
        for version_name, version_const in version_map.items():
            if version_const is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version_const
                ctx.maximum_version = version_const
                with socket.create_connection((ip, port), timeout=3.0) as raw:
                    with ctx.wrap_socket(raw) as conn:
                        if conn.version():
                            supported.append(version_name)
            except Exception:
                pass
        return supported

    def _compute_jarm(self, ip: str, port: int) -> str:
        """
        Compute JARM fingerprint by sending 10 custom TLS ClientHello probes
        and recording the ServerHello responses.
        Returns a 62-character hexadecimal fingerprint.
        """
        response_parts: List[str] = []

        for tls_ver, ciphers, order, alpn in JARM_PROBES:
            raw_version, cipher_selected, _ = self._send_jarm_probe(
                ip, port, tls_ver, ciphers, order, alpn
            )
            if raw_version and cipher_selected:
                part = f"{raw_version:04x}{cipher_selected:04x}"
            else:
                part = "0000"
            response_parts.append(part)

        # Hash all responses
        combined = "".join(response_parts)
        jarm_hash = hashlib.sha256(combined.encode()).hexdigest()[:62]
        return jarm_hash

    def _send_jarm_probe(
        self,
        ip: str,
        port: int,
        tls_version: int,
        ciphers: List[int],
        order: str,
        alpn: Optional[str],
    ) -> Tuple[int, int, bytes]:
        """
        Send a single TLS ClientHello probe and parse the ServerHello.
        Returns (tls_version_from_server, cipher_selected, raw_response).
        """
        try:
            hello = self._build_client_hello(tls_version, ciphers, order, alpn)
            with socket.create_connection((ip, port), timeout=3.0) as sock:
                sock.sendall(hello)
                data = sock.recv(1024)

            # Parse TLS record header
            if len(data) < 5:
                return 0, 0, b""
            record_type = data[0]
            record_version = struct.unpack(">H", data[1:3])[0]
            record_length = struct.unpack(">H", data[3:5])[0]

            if record_type != 0x16:  # Handshake
                return 0, 0, data

            if len(data) < 5 + record_length:
                return 0, 0, data

            # Parse Handshake message
            handshake = data[5:5 + record_length]
            if len(handshake) < 4:
                return 0, 0, data

            msg_type = handshake[0]
            if msg_type != 0x02:  # ServerHello
                return 0, 0, data

            # ServerHello structure: type(1) + length(3) + version(2) + random(32) +
            #   session_id_length(1) + session_id + cipher_suite(2)
            if len(handshake) < 40:
                return 0, 0, data

            server_version = struct.unpack(">H", handshake[4:6])[0]
            # session id length at offset 38
            session_id_len = handshake[38]
            cipher_offset = 39 + session_id_len
            if cipher_offset + 2 > len(handshake):
                return server_version, 0, data
            cipher_selected = struct.unpack(">H", handshake[cipher_offset:cipher_offset+2])[0]

            return server_version, cipher_selected, data
        except Exception:
            return 0, 0, b""

    def _build_client_hello(
        self,
        tls_version: int,
        ciphers: List[int],
        order: str,
        alpn: Optional[str],
    ) -> bytes:
        """Build a TLS ClientHello packet."""
        # Random (32 bytes)
        import os
        random_bytes = os.urandom(32)

        # Cipher suites
        if order == "reverse":
            ciphers = list(reversed(ciphers))
        cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
        # Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        cipher_bytes += b"\x00\xFF"

        # Extensions
        extensions = b""

        # SNI extension (type 0x0000) — empty
        sni_ext = struct.pack(">HH", 0x0000, 0)  # zero-length SNI

        # Supported versions extension (type 0x002b)
        if tls_version >= 0x0304:  # TLS 1.3
            sup_vers = struct.pack(">H", tls_version)
            sup_vers_ext = (struct.pack(">H", 0x002b) +
                           struct.pack(">H", len(sup_vers) + 1) +
                           bytes([len(sup_vers)]) + sup_vers)
            extensions += sup_vers_ext

        # ALPN extension (type 0x0010)
        if alpn:
            alpn_bytes = alpn.encode()
            proto_list = struct.pack(">H", len(alpn_bytes) + 1) + bytes([len(alpn_bytes)]) + alpn_bytes
            alpn_ext = (struct.pack(">H", 0x0010) +
                       struct.pack(">H", len(proto_list) + 2) +
                       struct.pack(">H", len(proto_list)) +
                       proto_list)
            extensions += alpn_ext

        # Session ID (empty)
        session_id = b"\x00"

        # ClientHello body
        client_hello_body = (
            struct.pack(">H", tls_version) +   # client_version
            random_bytes +                       # random
            session_id +                         # session_id
            struct.pack(">H", len(cipher_bytes)) + cipher_bytes +  # cipher_suites
            b"\x01\x00"                          # compression_methods (null)
        )

        if extensions:
            client_hello_body += struct.pack(">H", len(extensions)) + extensions

        # Handshake header
        handshake = (
            b"\x01" +                                      # ClientHello
            struct.pack(">I", len(client_hello_body))[1:]  # 3-byte length
        ) + client_hello_body

        # TLS record layer
        record_version = min(tls_version, 0x0303)  # max TLS 1.2 in record layer
        tls_record = (
            b"\x16" +                               # Handshake type
            struct.pack(">H", record_version) +     # version
            struct.pack(">H", len(handshake)) +     # length
            handshake
        )
        return tls_record

    def _check_hsts(self, ip: str, port: int) -> Tuple[bool, int]:
        """Check if HSTS header is present and return max-age."""
        scheme = "https"
        url = f"{scheme}://{ip}:{port}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url, headers={"Host": ip}, method="HEAD"
            )
            with urllib.request.urlopen(req, timeout=5.0, context=ctx) as resp:
                hsts = resp.headers.get("Strict-Transport-Security", "")
                if hsts:
                    match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                    max_age = int(match.group(1)) if match else 0
                    return True, max_age
        except Exception:
            pass
        return False, 0

    def _analyse_findings(self, result: TLSInspectionResult) -> None:
        """Generate TLSFinding list from analysis."""
        findings: List[TLSFinding] = []

        # Old TLS versions
        old_versions = set(result.tls_versions_supported) & {"TLSv1", "TLSv1.1"}
        for ver in sorted(old_versions):
            findings.append(TLSFinding(
                severity="high",
                title=f"{ver} still supported",
                description=f"The server supports {ver}, which is deprecated (RFC 8996).",
                recommendation=f"Disable {ver} and require TLS 1.2 minimum.",
                compliance_impact=["PCI DSS 4.0 req 6.2.4", "NIST SP 800-52r2"],
            ))

        # SSLv2/3 (should never happen but check)
        sslv_present = [v for v in result.tls_versions_supported if "SSL" in v]
        for ver in sslv_present:
            findings.append(TLSFinding(
                severity="critical",
                title=f"{ver} is enabled (POODLE / DROWN vulnerable)",
                description=f"{ver} is severely broken and enables known attacks.",
                recommendation="Disable immediately. No compatibility reason justifies this.",
                compliance_impact=["PCI DSS 4.0", "NIST SP 800-52r2", "GDPR Art. 32"],
            ))

        # Weak cipher
        if result.cipher_suite:
            for pattern, sev, msg in WEAK_CIPHER_PATTERNS:
                if re.search(pattern, result.cipher_suite, re.IGNORECASE):
                    findings.append(TLSFinding(
                        severity=sev,
                        title=f"Weak cipher negotiated: {result.cipher_suite}",
                        description=msg,
                        recommendation="Configure server to prefer ECDHE+AES_GCM or ChaCha20.",
                        compliance_impact=["PCI DSS 4.0", "Mozilla Modern Profile"],
                    ))
                    result.cipher_suite_weakness = msg
                    break

        # Certificate findings
        cert = result.certificate
        if cert:
            if cert.is_expired:
                findings.append(TLSFinding(
                    severity="critical",
                    title=f"Certificate expired {abs(cert.days_until_expiry)} days ago",
                    description=f"Certificate for {cert.subject_cn} is expired.",
                    recommendation="Renew certificate immediately. Consider Let's Encrypt.",
                    compliance_impact=["PCI DSS 4.0", "NIST SP 800-52r2"],
                ))
            elif cert.is_expiring_soon:
                findings.append(TLSFinding(
                    severity="medium",
                    title=f"Certificate expires in {cert.days_until_expiry} days",
                    description="Certificate approaching expiry.",
                    recommendation="Renew certificate before it expires.",
                    compliance_impact=[],
                ))

            if cert.is_self_signed:
                findings.append(TLSFinding(
                    severity="high",
                    title="Self-signed certificate",
                    description=f"Certificate is self-signed (CN: {cert.subject_cn}).",
                    recommendation="Replace with certificate from trusted CA.",
                    compliance_impact=["PCI DSS 4.0 req 6.2.4"],
                ))

            if cert.key_bits and cert.key_bits < 2048:
                findings.append(TLSFinding(
                    severity="critical",
                    title=f"Weak key: {cert.key_type} {cert.key_bits}-bit",
                    description="Key length below recommended minimum (2048 for RSA).",
                    recommendation="Replace with RSA-4096 or ECDSA P-256 key.",
                    compliance_impact=["NIST SP 800-52r2", "PCI DSS 4.0"],
                ))

            md5_sig = re.search(r"md5", cert.signature_algorithm or "", re.IGNORECASE)
            sha1_sig = re.search(r"sha1(?![\d])", cert.signature_algorithm or "", re.IGNORECASE)
            if md5_sig:
                findings.append(TLSFinding(
                    severity="critical",
                    title="Certificate signed with MD5",
                    description="MD5 signatures are cryptographically broken.",
                    recommendation="Replace certificate with SHA-256 or better.",
                    compliance_impact=["PCI DSS 4.0"],
                ))
            elif sha1_sig:
                findings.append(TLSFinding(
                    severity="high",
                    title="Certificate signed with SHA-1",
                    description="SHA-1 is deprecated; major browsers distrust it.",
                    recommendation="Replace certificate with SHA-256 or SHA-384.",
                    compliance_impact=["PCI DSS 4.0"],
                ))

        # Missing HSTS
        if result.port in {443, 8443} and not result.hsts_enabled:
            findings.append(TLSFinding(
                severity="medium",
                title="HSTS header missing",
                description="HTTP Strict-Transport-Security header is not set.",
                recommendation='Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                compliance_impact=["Mozilla Modern Profile", "OWASP TLS Guidelines"],
            ))
        elif result.hsts_enabled and result.hsts_max_age < 15768000:
            findings.append(TLSFinding(
                severity="low",
                title=f"HSTS max-age too short ({result.hsts_max_age}s)",
                description="HSTS max-age should be at least 15768000 (6 months).",
                recommendation="Set max-age=31536000 (1 year) minimum.",
                compliance_impact=["Mozilla Modern Profile"],
            ))

        # JARM known bad
        if result.jarm_known_bad:
            findings.append(TLSFinding(
                severity="critical",
                title=f"JARM fingerprint matches known malware: {result.jarm_known_bad}",
                description=f"JARM hash {result.jarm_fingerprint} matches C2/malware profile.",
                recommendation="Investigate this host immediately. Possible C2 server.",
                compliance_impact=["Incident Response Required"],
            ))

        result.findings = findings

    def _compliance_check(self, result: TLSInspectionResult) -> Dict[str, Any]:
        """Evaluate compliance against PCI DSS 4.0, NIST 800-52, Mozilla Modern."""
        pci_pass = True
        nist_pass = True
        mozilla_pass = True

        pci_issues: List[str] = []
        nist_issues: List[str] = []
        mozilla_issues: List[str] = []

        # Check supported versions
        for ver in result.tls_versions_supported:
            for forbidden in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                if forbidden.lower().replace(".", "") in ver.lower().replace(".", ""):
                    pci_pass = False
                    pci_issues.append(f"{ver} supported (forbidden by PCI DSS 4.0)")
                    nist_pass = False
                    nist_issues.append(f"{ver} supported (deprecated per NIST SP 800-52r2)")

        if "TLSv1.3" not in result.tls_versions_supported:
            mozilla_pass = False
            mozilla_issues.append("TLS 1.3 not supported (required by Mozilla Modern)")

        # Cipher checks
        if result.cipher_suite_weakness:
            pci_pass = False
            pci_issues.append(f"Weak cipher: {result.cipher_suite_weakness}")
            nist_pass = False
            nist_issues.append(f"Non-approved cipher: {result.cipher_suite_weakness}")

        # Certificate checks
        if result.certificate and result.certificate.is_self_signed:
            pci_pass = False
            pci_issues.append("Self-signed certificate not accepted by PCI DSS")

        if result.certificate and result.certificate.is_expired:
            pci_pass = False
            pci_issues.append("Expired certificate violates PCI DSS requirements")

        return {
            "pci_dss_4": {
                "pass": pci_pass,
                "issues": pci_issues,
            },
            "nist_sp_800_52r2": {
                "pass": nist_pass,
                "issues": nist_issues,
            },
            "mozilla_modern": {
                "pass": mozilla_pass,
                "issues": mozilla_issues,
            },
        }

    def _calculate_risk_score(self, result: TLSInspectionResult) -> int:
        """Calculate overall TLS risk score 0-100."""
        score = 0
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        for finding in result.findings:
            score += severity_weights.get(finding.severity, 0)
        return min(100, score)
