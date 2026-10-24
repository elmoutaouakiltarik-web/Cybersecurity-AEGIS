"""Test del modulo Industrial Site Assessment.

Nessun test tocca una rete reale: i pacchetti sono costruiti in memoria, le
sonde vengono verificate contro piccoli server locali usa-e-getta.
"""
from __future__ import annotations

import json
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from site_assessment import baseline, demo, dissect, fingerprint, pcap, report, scan
from site_assessment.assessor import SiteAssessor
from site_assessment.models import AssessmentResult, Asset, Finding, PortObservation
from site_assessment.passive import PassiveAnalyzer
from site_assessment.risk import RiskEngine
from site_assessment.safety import (
    Engagement,
    RateLimiter,
    SafetyGuard,
    ScopeViolation,
    UnsafeOperationError,
)


# ── fixture ──────────────────────────────────────────────────────────────────
@pytest.fixture()
def engagement() -> Engagement:
    return demo.demo_engagement()


@pytest.fixture()
def analyzed(engagement):
    analyzer = PassiveAnalyzer(None, engagement)
    for ts, frame in demo.demo_frames():
        analyzer.feed(frame, ts)
    return analyzer.finalize()


def _guard(engagement: Engagement, mode: str = "readonly") -> SafetyGuard:
    engagement.mode = mode
    return SafetyGuard(engagement)


class FakeServer:
    """Server TCP locale che risponde una volta con un payload fisso."""

    def __init__(self, response: bytes, family: int = socket.AF_INET,
                 sock_type: int = socket.SOCK_STREAM):
        self.sock = socket.socket(family, sock_type)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        if sock_type == socket.SOCK_STREAM:
            self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.response = response
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            while True:
                if self.sock.type == socket.SOCK_STREAM:
                    conn, _ = self.sock.accept()
                    try:
                        conn.recv(1024)
                        conn.sendall(self.response)
                    finally:
                        conn.close()
                else:
                    _, addr = self.sock.recvfrom(2048)
                    self.sock.sendto(self.response, addr)
        except OSError:
            return

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture()
def loopback_engagement() -> Engagement:
    return Engagement(
        client="test", site="loopback", operator="pytest",
        authorization_ref="TEST-ONLY", mode="readonly",
        allowed_cidrs=["127.0.0.0/8"],
    )


# ── dissector ────────────────────────────────────────────────────────────────
def _frame(payload: bytes, proto: int = 6, sport: int = 50000, dport: int = 502,
           src: str = demo.OFFICE_PC, dst: str = demo.PLC) -> dissect.Frame:
    l4 = demo.tcp(sport, dport, payload) if proto == 6 else demo.udp(sport, dport, payload)
    raw = demo.eth("00:0e:8c:11:22:33", "02:00:00:00:00:01", 0x0800,
                   demo.ipv4(src, dst, proto, l4))
    frame = dissect.parse_ethernet(raw, 1.0)
    assert frame is not None
    return frame


def test_dissect_modbus_write_is_flagged():
    frame = _frame(demo.modbus(6, address=10, value=1))
    proto, detail = dissect.classify(frame)
    assert proto == "modbus"
    assert detail["function_code"] == 6
    assert detail["is_write"] is True


def test_dissect_modbus_read_is_not_write():
    frame = _frame(demo.modbus(3, address=100, value=5))
    proto, detail = dissect.classify(frame)
    assert proto == "modbus"
    assert detail["is_write"] is False


def test_dissect_s7_write_detected():
    frame = _frame(demo.s7_write(), dport=102)
    proto, detail = dissect.classify(frame)
    assert proto == "s7comm"
    assert detail["is_write"] is True
    assert detail["function_code"] == 0x05


def test_dissect_dnp3_operate_detected():
    frame = _frame(demo.dnp3_operate(), dport=20000)
    proto, detail = dissect.classify(frame)
    assert proto == "dnp3"
    assert detail["is_write"] is True


def test_dissect_iec104_command():
    frame = _frame(demo.iec104_command(), dport=2404)
    proto, detail = dissect.classify(frame)
    assert proto == "iec104"
    assert detail["type_id"] == 45
    assert detail["is_write"] is True


def test_dissect_bacnet_write():
    frame = _frame(demo.bacnet_write(), proto=17, dport=47808)
    proto, detail = dissect.classify(frame)
    assert proto == "bacnet"
    assert detail["is_write"] is True


def test_dissect_lldp_neighbor():
    raw = demo.lldp_frame(demo.SWITCH_MAC, demo.SWITCH, "SW-LINEA-2")
    frame = dissect.parse_ethernet(raw, 2.0)
    assert frame is not None
    proto, detail = dissect.classify(frame)
    assert proto == "lldp"
    assert detail["system_name"] == "SW-LINEA-2"
    assert detail["management_ip"] == demo.SWITCH
    assert "bridge" in detail["capabilities"]


def test_dissect_enip_listidentity():
    raw = demo.eth("02:00:00:00:00:01", "00:11:43:00:00:01", 0x0800,
                   demo.ipv4(demo.EWS, "10.10.0.80", 17,
                             demo.udp(50001, 44818, demo.enip_listidentity_response())))
    frame = dissect.parse_ethernet(raw, 3.0)
    assert frame is not None
    proto, detail = dissect.classify(frame)
    assert proto == "enip"
    assert detail["command"] == 0x0063


def test_dissect_opcua_unencrypted():
    frame = _frame(demo.opcua_unencrypted_msg(), dport=4840)
    proto, detail = dissect.classify(frame)
    assert proto == "opcua"
    assert detail["unencrypted"] is True


# ── analisi passiva ──────────────────────────────────────────────────────────
def test_passive_inventory_is_built(analyzed):
    ips = {a.ip for a in analyzed.assets}
    assert demo.PLC in ips
    assert demo.OFFICE_PC in ips
    assert demo.SWITCH in ips
    assert analyzed.packets >= 10
    plc = next(a for a in analyzed.assets if a.ip == demo.PLC)
    assert plc.vendor == "Siemens"
    assert plc.is_ot is True
    assert "modbus" in plc.protocols
    assert plc.purdue_level == 1


def test_passive_does_not_inventory_internet_endpoints(analyzed):
    assert "8.8.8.8" not in {a.ip for a in analyzed.assets}


def test_passive_zone_lookup(analyzed):
    office = next(a for a in analyzed.assets if a.ip == demo.OFFICE_PC)
    assert office.zone == "Office"
    assert office.purdue_level == 3


def test_passive_detects_modbus_write(analyzed):
    writes = [a for a in analyzed.anomalies if a.kind == "ot_write_command"]
    assert writes, "atteso un comando di scrittura OT"
    assert any(a.severity == "critical" for a in writes)
    assert any("Modbus" in a.title for a in writes)


def test_passive_detects_arp_spoofing(analyzed):
    conflicts = [a for a in analyzed.anomalies if a.kind == "arp_conflict"]
    assert conflicts, "atteso un conflitto ARP"
    assert conflicts[0].severity == "high"


def test_passive_detects_internet_egress(analyzed):
    egress = [a for a in analyzed.anomalies if a.kind == "ot_internet_egress"]
    assert egress and egress[0].severity == "critical"


def test_passive_detects_zone_violation(analyzed):
    violations = [a for a in analyzed.anomalies if a.kind == "zone_violation"]
    assert violations, "atteso un flusso IT -> OT"


def test_passive_counts_protocols(analyzed):
    assert analyzed.protocol_counts.get("modbus", 0) >= 2
    assert analyzed.protocol_counts.get("arp", 0) >= 3


def test_passive_conversations_have_ot_protocol(analyzed):
    modbus_convs = [c for c in analyzed.conversations if c.ot_protocol == "modbus"]
    assert modbus_convs
    assert modbus_convs[0].packets >= 1


# ── safety gate ──────────────────────────────────────────────────────────────
def test_engagement_requires_authorization_reference():
    problems = Engagement(site="x", allowed_cidrs=["10.0.0.0/24"]).validate()
    assert any("authorization_ref" in p for p in problems)


def test_engagement_rejects_public_targets():
    eng = Engagement(site="x", authorization_ref="R", allowed_cidrs=["8.8.8.0/24"])
    ok, reason = eng.check_target("8.8.8.0/24")
    assert ok is False
    assert "pubblica" in reason or "public" in reason


def test_engagement_rejects_target_outside_scope(engagement):
    ok, reason = engagement.check_target("192.168.99.0/24")
    assert ok is False
    assert "autorizzate" in reason


def test_engagement_exclusion(engagement):
    engagement.excluded_ips = [demo.PLC]
    ok, _ = engagement.check_target(demo.PLC)
    assert ok is False


def test_guard_blocks_modbus_write(loopback_engagement):
    guard = _guard(loopback_engagement)
    with pytest.raises(UnsafeOperationError):
        guard.assert_readonly("modbus", 6)
    assert guard.blocked_attempts


def test_guard_allows_modbus_device_identification(loopback_engagement):
    guard = _guard(loopback_engagement)
    guard.assert_readonly("modbus", 0x2B)  # Read Device Identification


def test_guard_blocks_s7_stop(loopback_engagement):
    guard = _guard(loopback_engagement)
    with pytest.raises(UnsafeOperationError):
        guard.assert_readonly("s7", 0x29)


def test_passive_mode_sends_nothing(loopback_engagement):
    guard = _guard(loopback_engagement, mode="passive")
    with pytest.raises(ScopeViolation):
        guard.require_network_actions()


def test_rate_limiter_is_bounded():
    limiter = RateLimiter(max_pps=50, per_host_interval_s=0.01)
    started = time.time()
    for _ in range(10):
        limiter.acquire("10.0.0.1")
    assert time.time() - started >= 0.05


# ── scansione ────────────────────────────────────────────────────────────────
def test_scan_profile_contains_ot_ports():
    ports = scan.ports_for_profile("ot")
    assert 502 in ports and 102 in ports and 44818 in ports and 2404 in ports
    assert scan.safety_class(502) == "control"
    assert scan.safety_class(22) == "management"


def test_scan_expands_only_authorized_hosts(engagement):
    guard = SafetyGuard(engagement)
    hosts = scan.expand_targets("10.10.0.0/29", guard)
    assert hosts and all(h.startswith("10.10.0.") for h in hosts)


def test_scan_detects_open_port_locally(loopback_engagement):
    server = FakeServer(b"SSH-2.0-OpenSSH_8.9\r\n")
    try:
        guard = _guard(loopback_engagement)
        observations = scan.scan_host("127.0.0.1", [server.port], guard, timeout=0.5)
        assert any(o.port == server.port and o.state == "open" for o in observations)
    finally:
        server.close()


# ── fingerprint ──────────────────────────────────────────────────────────────
def _modbus_devid_response() -> bytes:
    objects = [(0, b"ACME Controls"), (2, b"V3.1.4"), (4, b"PumpMaster 2000")]
    body = bytes([0x2B, 0x0E, 0x01, 0x83, 0x00, 0x00, len(objects)])
    for obj_id, value in objects:
        body += bytes([obj_id, len(value)]) + value
    return struct.pack(">HHHB", 1, 0, len(body) + 1, 1) + body


def test_fingerprint_modbus_identity(loopback_engagement):
    server = FakeServer(_modbus_devid_response())
    try:
        guard = _guard(loopback_engagement)
        result = fingerprint.probe_modbus_identity("127.0.0.1", guard, port=server.port)
        assert result["success"] is True
        assert result["identity"]["vendor_name"] == "ACME Controls"
        assert result["identity"]["product_name"] == "PumpMaster 2000"
    finally:
        server.close()


def test_fingerprint_http_hmi_detection(loopback_engagement):
    response = (b"HTTP/1.1 200 OK\r\nServer: SIMATIC\r\nContent-Type: text/html\r\n\r\n"
                b"<html><head><title>SIMATIC HMI</title></head><body>login</body></html>")
    server = FakeServer(response)
    try:
        guard = _guard(loopback_engagement)
        result = fingerprint.probe_http_identity("127.0.0.1", guard, port=server.port)
        assert result["success"] is True
        assert "Siemens" in result["identity"]["product"]
        assert result["identity"]["login_page"] is True
    finally:
        server.close()


def test_fingerprint_asset_enriches_asset(loopback_engagement):
    server = FakeServer(_modbus_devid_response())
    try:
        asset = Asset(ip="127.0.0.1")
        asset.add_port(PortObservation(port=server.port, service="modbus", safety_class="control"))
        guard = _guard(loopback_engagement)
        info = fingerprint.fingerprint_asset(asset, guard)
        assert info["attempted"] >= 1
        assert asset.vendor == "ACME Controls"
        assert asset.is_ot is True
    finally:
        server.close()


# ── rischio ──────────────────────────────────────────────────────────────────
@pytest.fixture()
def findings(analyzed, engagement) -> list[Finding]:
    return RiskEngine(engagement).evaluate(
        list(analyzed.assets), analyzed.conversations, analyzed.anomalies,
        broadcast_ratio=analyzed.broadcast_ratio, protocols=analyzed.protocol_counts,
    )


def test_risk_finds_critical_issues(findings):
    assert findings
    severities = {f.severity for f in findings}
    assert "critical" in severities


def test_risk_splits_production_safe(findings):
    assert any(f.production_safe for f in findings)
    assert any(not f.production_safe for f in findings)


def test_risk_detects_observed_write(findings):
    write_findings = [f for f in findings if f.title.startswith("Comando di scrittura")]
    assert write_findings
    assert write_findings[0].mitre_ics.startswith("T0855")


def test_risk_detects_ot_exposure(findings):
    assert any("esposto senza autenticazione" in f.title for f in findings)


def test_risk_detects_it_services(findings):
    assert any("Servizi IT" in f.title for f in findings)


def test_risk_detects_flat_network(findings):
    assert any("Rete piatta" in f.title for f in findings)


def test_risk_scores_assets(analyzed, engagement):
    engine = RiskEngine(engagement)
    engine.evaluate(list(analyzed.assets), analyzed.conversations, analyzed.anomalies)
    plc = next(a for a in analyzed.assets if a.ip == demo.PLC)
    assert 0 <= plc.risk_score <= 100
    assert plc.risk_score > 0


def test_risk_is_deterministic(analyzed, engagement):
    engine = RiskEngine(engagement)
    first = [f.id for f in engine.evaluate(list(analyzed.assets), analyzed.anomalies)]
    second = [f.id for f in engine.evaluate(list(analyzed.assets), analyzed.anomalies)]
    assert first == second


# ── baseline ─────────────────────────────────────────────────────────────────
def _result_with(ips_with_ports) -> AssessmentResult:
    result = AssessmentResult(id="t", site="demo", status="done")
    for ip, ports in ips_with_ports.items():
        asset = Asset(ip=ip, hostname=f"host-{ip}", vendor="ACME", model="M1")
        for port in ports:
            asset.add_port(PortObservation(port=port, service=scan.service_name(port)))
        result.assets.append(asset)
    return result


def test_baseline_detects_new_asset_and_port(tmp_path):
    base = baseline.snapshot(_result_with({"10.0.0.1": [502]}))
    current = baseline.snapshot(_result_with({"10.0.0.1": [502, 80], "10.0.0.2": [22]}))
    diff = baseline.diff(base, current)
    assert diff["has_drift"] is True
    assert diff["new_assets"][0]["ip"] == "10.0.0.2"
    assert diff["new_ports"][0]["port"] == 80
    assert "Drift" in diff["summary"]


def test_baseline_roundtrip(tmp_path):
    result = _result_with({"10.0.0.5": [502]})
    path = baseline.save(result, str(tmp_path / "base.json"))
    diff = baseline.diff_with_file(result, path)
    assert diff["has_drift"] is False


# ── report ───────────────────────────────────────────────────────────────────
def _full_result(analyzed, engagement) -> AssessmentResult:
    result = AssessmentResult(
        id="rep1", site="Linea <script>2</script>", client="ACME", operator="pytest",
        authorization_ref="WO-1", mode="passive", status="done",
        assets=list(analyzed.assets), conversations=analyzed.conversations,
        anomalies=analyzed.anomalies,
    )
    result.findings = RiskEngine(engagement).evaluate(
        list(analyzed.assets), analyzed.conversations, analyzed.anomalies)
    result.coverage.packets_analyzed = analyzed.packets
    result.site_score = result.compute_site_score()
    return result


def test_report_markdown_sections(analyzed, engagement):
    text = report.build_markdown(_full_result(analyzed, engagement))
    assert "Sintesi esecutiva" in text
    assert "Cosa fare subito" in text
    assert "Inventario asset" in text
    assert "Copertura e limiti" in text


def test_report_html_escapes_content(analyzed, engagement):
    html = report.build_html(_full_result(analyzed, engagement))
    assert html.startswith("<!DOCTYPE html>")
    assert "<script>2</script>" not in html
    assert "&lt;script&gt;" in html


def test_report_write_files(analyzed, engagement, tmp_path):
    paths = report.write_reports(_full_result(analyzed, engagement), str(tmp_path / "out"))
    for kind in ("json", "md", "html"):
        assert Path(paths[kind]).is_file()
    assert json.loads(Path(paths["json"]).read_text(encoding="utf-8"))["site"].startswith("Linea")


def test_report_handles_empty_result():
    empty = AssessmentResult(id="empty", site="vuoto", status="done")
    assert "Sintesi esecutiva" in report.build_markdown(empty)
    assert "<!DOCTYPE html>" in report.build_html(empty)


# ── pcap e assessment end-to-end ─────────────────────────────────────────────
def test_pcap_write_and_read(tmp_path):
    path = tmp_path / "demo.pcap"
    frames = demo.demo_frames()
    pcap.write_pcap(path, frames)
    assert pcap.count_packets(path) == len(frames)
    first = next(pcap.iter_packets(path))
    assert first[1] == frames[0][1]


def test_assessor_passive_end_to_end(tmp_path):
    pcap_path = tmp_path / "demo.pcap"
    pcap.write_pcap(pcap_path, demo.demo_frames())

    assessor = SiteAssessor(data_dir=str(tmp_path / "data"))
    job = assessor.start(
        demo.demo_engagement(), targets=[], pcap=str(pcap_path), profile="ot",
    )
    deadline = time.time() + 30
    while job.status in ("pending", "running") and time.time() < deadline:
        time.sleep(0.05)
        job = assessor.get(job.id) or job

    assert job.status == "done", job.error
    result = job.result
    assert result is not None
    assert len(result.assets) >= 4
    assert result.coverage.packets_analyzed == len(demo.demo_frames())
    assert result.site_score < 100
    assert any(f.severity == "critical" for f in result.findings)
    # Il risultato deve essere ricaricabile da disco.
    loaded = assessor.load_result(job.id)
    assert loaded is not None and loaded.id == job.id


def test_assessor_rejects_unauthorized(tmp_path):
    assessor = SiteAssessor(data_dir=str(tmp_path / "data"))
    eng = demo.demo_engagement()
    eng.authorization_ref = ""
    with pytest.raises(ScopeViolation):
        assessor.start(eng, targets=[], pcap="x.pcap")


def test_cli_selftest_passes(tmp_path):
    from site_assessment.cli import main

    code = main(["selftest", "--out", str(tmp_path / "reports")])
    assert code == 0
    assert any((tmp_path / "reports").iterdir())
