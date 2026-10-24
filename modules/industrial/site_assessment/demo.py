"""Traffico sintetico per self-test e dimostrazioni.

Nessun pacchetto viene inviato in rete: i frame sono costruiti in memoria e
passati all'analizzatore passivo. Serve a verificare che installazione,
dissector e regole funzionino anche su un portatile senza rete industriale.
"""
from __future__ import annotations

import ipaddress
import struct
from typing import List, Tuple


def mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def ip(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return mac(dst) + mac(src) + struct.pack(">H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, ttl, proto, 0, ip(src), ip(dst))
    return header + payload


def tcp(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    header = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 8192, 0, 0)
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return (struct.pack(">HHBBH", 1, 0x0800, 6, 4, op)
            + mac(sha) + ip(spa) + mac(tha) + ip(tpa))


# ── protocolli ───────────────────────────────────────────────────────────────
def modbus(fc: int, unit: int = 1, address: int = 0, value: int = 0,
           transaction: int = 1) -> bytes:
    """Frame Modbus/TCP completo di MBAP (7 byte) + PDU."""
    pdu = struct.pack(">BHH", fc, address, value)
    return struct.pack(">HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


def s7_write() -> bytes:
    params = bytes([0x05, 0x01, 0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00])
    header = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, len(params), 0x00, 0x00])
    cotp = bytes([0x02, 0xF0, 0x80])
    total = 4 + len(cotp) + len(header) + len(params)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + cotp + header + params


def dnp3_operate() -> bytes:
    link = bytes([0x05, 0x64, 0x0B, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00])
    transport = bytes([0xC0])
    app = bytes([0xC4, 0x05]) + b"\x0c\x01\x28\x01\x00\x00\x00\x00\x00"
    return link + transport + app


def enip_listidentity_response() -> bytes:
    product = b"1756-L61/B LOGIX5561"
    identity = (struct.pack("<H", 1) + b"\x00" * 16
                + struct.pack("<HHH", 1, 0x0E, 51)
                + bytes([32, 11]) + struct.pack("<H", 0)
                + struct.pack("<I", 0xDEADBEEF) + bytes([len(product)]) + product + b"\x03")
    item = struct.pack("<HH", 0x000C, len(identity)) + identity
    body = struct.pack("<H", 1) + item
    return struct.pack("<HHII8sI", 0x0063, len(body), 0, 0, b"\x00" * 8, 0) + body


def bacnet_write() -> bytes:
    apdu = bytes([0x00, 0x05, 0x01, 0x0F, 0x0C, 0x02, 0x00, 0x00, 0x05, 0x19, 0x55])
    npdu = bytes([0x01, 0x00])
    body = npdu + apdu
    return bytes([0x81, 0x0A, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body


def iec104_command() -> bytes:
    asdu = bytes([45, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01])
    ctrl = bytes([0x00, 0x00, 0x00, 0x00])
    return bytes([0x68, len(asdu) + 4]) + ctrl + asdu


def profinet_dcp_set() -> bytes:
    blocks = bytes([0x02, 0x02, 0x00, 0x0B]) + b"linea-2-plc" + b"\x00"
    header = struct.pack(">HBB", 0xFEFE, 0x00, 0x03) + struct.pack("<I", 0x1234) + b"\x00\x01"
    header += struct.pack(">H", len(blocks))
    return header + blocks


def lldp_frame(switch_mac: str, ip_addr: str, name: str) -> bytes:
    def tlv(kind: int, value: bytes) -> bytes:
        return struct.pack(">H", (kind << 9) | len(value)) + value

    body = tlv(1, b"\x04" + mac(switch_mac))
    body += tlv(2, b"\x05" + b"Gi1/0/12")
    body += tlv(3, struct.pack(">H", 120))
    body += tlv(5, name.encode())
    body += tlv(6, b"Industrial Ethernet Switch, firmware 09.10")
    body += tlv(7, struct.pack(">HH", 0x0014, 0x0014))
    body += tlv(8, bytes([5, 1]) + ip(ip_addr) + struct.pack(">I", 12) + b"\x00")
    return eth("01:80:c2:00:00:0e", switch_mac, 0x88CC, body)


def opcua_unencrypted_msg() -> bytes:
    # MSG/F con token id 0 = nessuna sicurezza sul canale.
    return b"MSGF" + struct.pack("<I", 64) + struct.pack("<II", 1, 0) + b"\x00" * 48


# ── scenario completo ────────────────────────────────────────────────────────
PLC = "10.10.0.5"
PLC_MAC = "00:0e:8c:11:22:33"
EWS = "10.10.0.10"
HMI = "10.10.0.20"
SWITCH = "10.10.0.2"
SWITCH_MAC = "00:80:63:aa:bb:cc"
OFFICE_PC = "10.10.0.130"
# Il PC office sta nella stessa /24 dei PLC: e' il caso classico di rete
# piatta che l'assessment deve far emergere.


def demo_frames() -> List[Tuple[float, bytes]]:
    """Scenario realistico: impianto sano + scritture sospette + egress."""
    frames: List[Tuple[float, bytes]] = []
    t = 1_700_000_000.0

    frames.append((t, eth("ff:ff:ff:ff:ff:ff", PLC_MAC, 0x0806,
                          arp(1, PLC_MAC, PLC, "00:00:00:00:00:00", "10.10.0.1"))))
    frames.append((t + 1, lldp_frame(SWITCH_MAC, SWITCH, "SW-LINEA-2")))

    # Telemetria Modbus legittima (FC3) dal SCADA al PLC.
    frames.append((t + 2, eth(PLC_MAC, "00:11:43:00:00:01", 0x0800,
                              ipv4(EWS, PLC, 6, tcp(51000, 502, modbus(3, unit=1, address=100, value=10))))))
    # Comando di scrittura Modbus dal PC office: anomalia critica.
    frames.append((t + 3, eth(PLC_MAC, "00:11:43:00:00:50", 0x0800,
                              ipv4(OFFICE_PC, PLC, 6, tcp(52000, 502, modbus(6, unit=1, address=10, value=1, transaction=7))))))
    # Scrittura S7 (download/var) dallo stesso host.
    frames.append((t + 4, eth(PLC_MAC, "00:11:43:00:00:50", 0x0800,
                              ipv4(OFFICE_PC, PLC, 6, tcp(52001, 102, s7_write())))))
    # Comando DNP3 operate verso RTU.
    frames.append((t + 5, eth("00:00:bc:01:02:03", "00:11:43:00:00:50", 0x0800,
                              ipv4(OFFICE_PC, "10.10.0.30", 6, tcp(52002, 20000, dnp3_operate())))))
    # BACnet WriteProperty e IEC104 command.
    frames.append((t + 6, eth("00:00:00:00:00:00", "00:11:43:00:00:50", 0x0800,
                              ipv4(OFFICE_PC, "10.10.0.40", 17, udp(50000, 47808, bacnet_write())))))
    frames.append((t + 7, eth("00:00:00:00:00:00", "00:11:43:00:00:50", 0x0800,
                              ipv4(OFFICE_PC, "10.10.0.60", 6, tcp(52003, 2404, iec104_command())))))
    # PROFINET DCP Set: rinomina di un device.
    frames.append((t + 8, eth("01:0e:cf:00:00:00", "00:11:43:00:00:50", 0x8892, profinet_dcp_set())))
    # OPC UA in chiaro.
    frames.append((t + 9, eth("00:00:00:00:00:00", "00:1b:1b:20:00:01", 0x0800,
                              ipv4(HMI, "10.10.0.70", 6, tcp(52004, 4840, opcua_unencrypted_msg())))))
    # HMI che espone SMB (fingerprint di servizio osservato nel traffico).
    frames.append((t + 9.5, eth("00:11:43:00:00:50", "00:1b:1b:20:00:01", 0x0800,
                                ipv4(HMI, OFFICE_PC, 6, tcp(445, 49001, b"\xffSMB\x72")))))
    # Egress verso Internet da un asset di processo.
    frames.append((t + 10, eth("00:00:00:00:00:00", PLC_MAC, 0x0800,
                               ipv4(PLC, "8.8.8.8", 6, tcp(49700, 443, b"\x16\x03\x01")))))
    # ARP spoofing: l'attaccante annuncia l'IP del gateway.
    frames.append((t + 11, eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:66", 0x0806,
                               arp(2, "02:00:00:00:00:66", "10.10.0.1", PLC_MAC, PLC))))
    frames.append((t + 12, eth("ff:ff:ff:ff:ff:ff", SWITCH_MAC, 0x0806,
                               arp(2, SWITCH_MAC, "10.10.0.1", PLC_MAC, PLC))))
    frames.append((t + 12.5, eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:66", 0x0806,
                                 arp(1, "02:00:00:00:00:66", "10.10.0.1" , "00:00:00:00:00:00", "10.10.0.9"))))
    frames.append((t + 13.5, eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:66", 0x0806,
                                 arp(1, "02:00:00:00:00:66", "10.10.0.1", "00:00:00:00:00:00", "10.10.0.11"))))
    # EtherNet/IP ListIdentity (device Rockwell).
    frames.append((t + 13, eth("01:00:5e:00:00:01", "00:11:43:00:00:01", 0x0800,
                               ipv4(EWS, "10.10.0.80", 17, udp(50001, 44818, enip_listidentity_response())))))
    # SMB dal PC office verso l'HMI: propagazione laterale tipica di ransomware.
    frames.append((t + 14, eth("00:1b:1b:20:00:01", "00:11:43:00:00:50", 0x0800,
                               ipv4(OFFICE_PC, HMI, 6, tcp(49000, 445, b"", flags=0x02)))))
    frames.append((t + 14.2, eth("00:1b:1b:20:00:01", "00:11:43:00:00:50", 0x0800,
                                 ipv4(OFFICE_PC, HMI, 6, tcp(49000, 445, b"\xffSMB\x72")))))
    return frames


def demo_engagement():
    from .safety import Engagement

    return Engagement(
        client="Demo Industria S.p.A.",
        site="Stabilimento demo — Linea 2",
        operator="AEGIS self-test",
        authorization_ref="SELFTEST-LOCAL-ONLY",
        mode="passive",
        allowed_cidrs=["10.10.0.0/24"],
        zones=[
            {"name": "Controllo Linea 2", "purdue_level": 1, "cidrs": ["10.10.0.0/25"],
             "description": "PLC, RTU e I/O di linea"},
            {"name": "Office", "purdue_level": 3, "cidrs": ["10.10.0.128/26"],
             "description": "Postazioni ufficio e MES (stessa L2 del controllo)"},
        ],
    )
