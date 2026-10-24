"""Tests for Cybersecurity-AEGIS LAN Scanner."""
import time
from unittest.mock import patch

import pytest

from lan_scanner import (
    LANScanner,
    PortResult,
    _enrich_findings_with_nvd,
    _extract_version,
    _guess_os,
    _score_host,
    _tcp_connect,
    _validate_target,
)


# ── Scope Validation ───────────────────────────────────────────────────────────
def test_validate_target_private_ok():
    ok, reason = _validate_target("192.168.1.0/24")
    assert ok is True
    assert reason == ""


def test_validate_target_single_ip_private():
    ok, reason = _validate_target("10.0.0.1")
    assert ok is True
    assert reason == ""


def test_validate_target_public_rejected():
    ok, reason = _validate_target("8.8.8.8")
    assert ok is False
    assert "public" in reason.lower()


def test_validate_target_public_allowed():
    ok, reason = _validate_target("8.8.8.8", allow_public=True)
    assert ok is True
    assert reason == ""


def test_validate_target_too_large():
    ok, reason = _validate_target("0.0.0.0/0")
    assert ok is False
    assert "too large" in reason.lower()


# ── OS Guessing ────────────────────────────────────────────────────────────────
def test_guess_os_windows():
    ports = [PortResult(3389, "open", "rdp"), PortResult(135, "open", "msrpc")]
    assert "Windows" in _guess_os(ports)


def test_guess_os_linux():
    ports = [PortResult(22, "open", "ssh", banner="OpenSSH_8.9p1")]
    assert "Linux" in _guess_os(ports)


def test_guess_os_ot():
    ports = [PortResult(502, "open", "modbus")]
    assert "ICS/OT" in _guess_os(ports)


# ── Risk Scoring ───────────────────────────────────────────────────────────────
def test_score_host_potential_exposure():
    ports = [PortResult(445, "open", "smb", banner="")]
    score, findings = _score_host(ports)
    assert score == 100
    assert any(f["exposure_id"] == "CVE-2017-0144" for f in findings)
    assert findings[0]["type"] == "potential_exposure"
    assert findings[0]["confidence"] == "low"


def test_score_host_cleartext():
    # Port 110 (pop3) is not in RISKY_SERVICES but is a cleartext protocol
    ports = [PortResult(110, "open", "pop3", banner="")]
    score, findings = _score_host(ports)
    assert score == 70
    assert any(f["exposure_id"] == "EXPOSED-CLEARTEXT" for f in findings)


# ── TCP Connect (real localhost) ───────────────────────────────────────────────
def test_tcp_connect_localhost_refused():
    # Port 1 is almost never open
    assert _tcp_connect("127.0.0.1", 1, timeout=0.5) is False


def test_tcp_connect_localhost_open():
    # Start a temporary server on a free port
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert _tcp_connect("127.0.0.1", port, timeout=1.0) is True
    finally:
        s.close()


# ── Version Extraction ─────────────────────────────────────────────────────────
def test_extract_version_apache():
    assert _extract_version("Apache/2.4.41", "http") == "2.4.41"


def test_extract_version_openssh():
    # _extract_version returns the numeric version for NVD lookup, not the full banner
    assert _extract_version("SSH-2.0-OpenSSH_8.9p1", "ssh") == "8.9"


def test_extract_version_none():
    assert _extract_version("", "http") == ""


# ── NVD Enrichment (mocked) ────────────────────────────────────────────────────
def test_enrich_findings_with_nvd_mocked():
    ports = [PortResult(80, "open", "http", banner="Apache/2.4.41")]
    findings = []
    with patch("lan_scanner._nvd_lookup") as mock_lookup:
        mock_lookup.return_value = [
            {
                "cve": "CVE-2021-44790",
                "cvss": 9.8,
                "severity": "critical",
                "description": "Apache mod_lua RCE",
            }
        ]
        enriched = _enrich_findings_with_nvd(ports, findings)
        assert any(f["type"] == "cve_verified" for f in enriched)
        assert any(f["exposure_id"] == "CVE-2021-44790" for f in enriched)


# ── Scan Job Lifecycle ─────────────────────────────────────────────────────────
def test_scan_job_cancel():
    scanner = LANScanner(allow_public=True)
    job = scanner.start_scan("127.0.0.1", mode="quick", ot_mode="safe", timeout=60)
    assert job.state in ("pending", "running")
    ok = scanner.cancel_job(job.id)
    assert ok is True
    assert job.cancelled is True
    assert job.state == "cancelled"


# ── Export Formats ─────────────────────────────────────────────────────────────
def test_export_json():
    scanner = LANScanner(allow_public=True)
    job = scanner.start_scan("127.0.0.1", mode="quick", ot_mode="safe", timeout=5)
    time.sleep(6)
    data = scanner.export_job(job.id, "json")
    assert '"id":' in data
    assert job.target in data


def test_export_csv():
    scanner = LANScanner(allow_public=True)
    job = scanner.start_scan("127.0.0.1", mode="quick", ot_mode="safe", timeout=5)
    time.sleep(6)
    data = scanner.export_job(job.id, "csv")
    assert "ip,hostname,mac" in data
    lines = data.strip().splitlines()
    assert len(lines) >= 1


def test_export_html():
    scanner = LANScanner(allow_public=True)
    job = scanner.start_scan("127.0.0.1", mode="quick", ot_mode="safe", timeout=5)
    time.sleep(6)
    data = scanner.export_job(job.id, "html")
    assert "<!DOCTYPE html>" in data
    assert "AEGIS-OMNI Scan Report" in data


# ── UDP Probes (basic smoke) ───────────────────────────────────────────────────
def test_snmp_probe_localhost():
    from lan_scanner import _snmp_probe

    # SNMP is unlikely to respond on localhost without agent
    result = _snmp_probe("127.0.0.1", timeout=0.5)
    assert result is False or result is True  # deterministic not required


# ── Scope Guard Integration ────────────────────────────────────────────────────
def test_scanner_rejects_public_by_default():
    scanner = LANScanner()
    job = scanner.start_scan("8.8.8.8", mode="quick")
    assert job.state == "error"
    assert "public" in job.error.lower()
