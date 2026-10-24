"""Dissector minimale, senza dipendenze, per traffico industriale.

Perche' non usare direttamente Scapy per il parsing?

* l'analisi deve funzionare anche su un portatile Windows senza Npcap;
* un file ``.pcap``/``.pcapng`` esportato da Wireshark deve poter essere
  analizzato offline, senza privilegi di amministratore;
* i test devono poter costruire frame sintetici e verificarne il significato.

Il decoder copre: Ethernet/VLAN, ARP, IPv4/IPv6, TCP/UDP, LLDP, CDP,
PROFINET DCP/RT, Modbus/TCP, S7comm (TPKT/COTP), DNP3, EtherNet/IP,
BACnet/IP, IEC 60870-5-104, OPC UA binary, DHCP, DNS/mDNS/NBNS, SNMP.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .safety import DANGEROUS_OPERATIONS

# ── Porte note ────────────────────────────────────────────────────────────────
OT_TCP_PORTS: Dict[int, str] = {
    102: "s7comm",          # Siemens S7 / ISO-on-TCP (anche IEC 61850 MMS)
    502: "modbus",
    789: "redlion",
    1911: "niagara-fox",
    1962: "pcworx",
    2222: "enip-io",        # EtherNet/IP implicit I/O
    2404: "iec104",
    2455: "codesys",
    4000: "emerson",
    4840: "opcua",
    5006: "melsec",
    5007: "melsec",
    5094: "hart-ip",
    9600: "omron-fins",
    11740: "codesys",
    20000: "dnp3",
    34962: "profinet-rt",
    34963: "profinet-rt",
    34964: "profinet-ctx",
    44818: "enip",
    47808: "bacnet",
    55000: "bacnet-sc",
}

OT_UDP_PORTS: Dict[int, str] = {
    161: "snmp",
    502: "modbus",
    2222: "enip-io",
    47808: "bacnet",
    5094: "hart-ip",
    9600: "omron-fins",
    34964: "profinet-ctx",
    44818: "enip",
    20000: "dnp3",
}

IT_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Protocolli capaci di comandare il processo (canale di controllo).
CONTROL_PROTOCOLS = {"modbus", "s7comm", "dnp3", "iec104", "enip", "enip-io",
                     "bacnet", "profinet-rt", "melsec", "omron-fins", "codesys",
                     "niagara-fox", "redlion", "hart-ip", "pcworx"}

# Protocolli di management IT che in una zona OT sono un rischio.
IT_RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900, 5985, 6379, 1433, 3306, 27017}


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip4_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def ip6_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except OSError:
        return ""


TCP_FLAG_NAMES = [(0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")]


def tcp_flags_str(flags: int) -> str:
    return "".join(name for bit, name in TCP_FLAG_NAMES if flags & bit) or "-"


@dataclass
class Frame:
    """Frame decodificato: solo i campi che servono all'analisi."""

    ts: float = 0.0
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0
    vlan: Optional[int] = None
    src_ip: str = ""
    dst_ip: str = ""
    ttl: int = 0
    ip_proto: int = 0
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: str = ""
    payload: bytes = b""
    frame_len: int = 0
    llc_payload: bytes = b""

    def is_ip(self) -> bool:
        return bool(self.src_ip and self.dst_ip)


# ── Parsing L2/L3 ─────────────────────────────────────────────────────────────
def parse_ethernet(data: bytes, ts: float = 0.0) -> Optional[Frame]:
    if len(data) < 14:
        return None
    frame = Frame(ts=ts, frame_len=len(data))
    frame.dst_mac = mac_str(data[0:6])
    frame.src_mac = mac_str(data[6:12])
    ethertype = struct.unpack(">H", data[12:14])[0]
    offset = 14

    # VLAN (802.1Q / QinQ)
    while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:
        vlan, ethertype = struct.unpack(">HH", data[offset:offset + 4])
        frame.vlan = vlan & 0x0FFF
        offset += 4

    frame.ethertype = ethertype

    # 802.3 + LLC/SNAP (CDP usa questo incapsulamento)
    if ethertype <= 1500:
        frame.llc_payload = data[offset + 3:]
        if len(data) >= offset + 8 and data[offset:offset + 3] == b"\xaa\xaa\x03":
            frame.ethertype = 0
        return frame

    if ethertype == 0x0806 and len(data) >= offset + 28:      # ARP
        sha = mac_str(data[offset + 8:offset + 14])
        spa = ip4_str(data[offset + 14:offset + 18])
        tpa = ip4_str(data[offset + 24:offset + 28])
        frame.src_mac = sha
        frame.src_ip = spa
        frame.dst_ip = tpa
        frame.payload = data[offset:offset + 28]
        return frame

    if ethertype == 0x0800:                                   # IPv4
        return _parse_ipv4(frame, data[offset:])

    if ethertype == 0x86DD:                                   # IPv6
        return _parse_ipv6(frame, data[offset:])

    # LLDP / PROFINET / EtherCAT restano a livello 2
    frame.payload = data[offset:]
    frame.llc_payload = data[offset:]
    return frame


def _parse_ipv4(frame: Frame, data: bytes) -> Optional[Frame]:
    if len(data) < 20:
        return None
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack(">H", data[2:4])[0]
    frame.ttl = data[8]
    frame.ip_proto = data[9]
    frame.src_ip = ip4_str(data[12:16])
    frame.dst_ip = ip4_str(data[16:20])
    frag = struct.unpack(">H", data[6:8])[0]
    end = min(len(data), total_len) if total_len >= ihl else len(data)
    l4 = data[ihl:end]
    if frag & 0x1FFF:
        # Frammento non iniziale: nessun header di trasporto.
        frame.payload = l4
        return frame
    return _parse_l4(frame, l4)


def _parse_ipv6(frame: Frame, data: bytes) -> Optional[Frame]:
    if len(data) < 40:
        return None
    frame.ip_proto = data[6]
    frame.ttl = data[7]
    frame.src_ip = ip6_str(data[8:24])
    frame.dst_ip = ip6_str(data[24:40])
    return _parse_l4(frame, data[40:])


def _parse_l4(frame: Frame, data: bytes) -> Frame:
    if frame.ip_proto == 6 and len(data) >= 20:               # TCP
        frame.src_port, frame.dst_port = struct.unpack(">HH", data[0:4])
        offset = (data[12] >> 4) * 4
        frame.tcp_flags = tcp_flags_str(data[13])
        frame.payload = data[offset:] if offset >= 20 else b""
        return frame
    if frame.ip_proto == 17 and len(data) >= 8:               # UDP
        frame.src_port, frame.dst_port = struct.unpack(">HH", data[0:4])
        length = struct.unpack(">H", data[4:6])[0]
        frame.payload = data[8:length] if 8 <= length <= len(data) else data[8:]
        return frame
    frame.payload = data
    return frame


# ── Classificazione protocollo ────────────────────────────────────────────────
def classify(frame: Frame) -> Tuple[str, Dict[str, Any]]:
    """Riconosce il protocollo applicativo dal payload, non solo dalla porta.

    Il riconoscimento a livello di payload e' importante: nelle reti OT i
    protocolli vengono spesso spostati su porte non standard da NAT, gateway
    o "tunnel" fatti in casa.
    """
    p = frame.payload or b""

    if frame.ethertype == 0x88CC:
        return "lldp", lldp_detail(p)
    if frame.ethertype == 0x88A4:
        return "ethercat", {"note": "traffico EtherCAT"}
    if frame.ethertype == 0x8892:
        return profinet_detail(p)
    if frame.ethertype == 0 and frame.llc_payload[:3] == b"\xaa\xaa\x03" and len(frame.llc_payload) >= 8:
        oui = frame.llc_payload[3:6]
        pid = struct.unpack(">H", frame.llc_payload[6:8])[0]
        if oui == b"\x00\x00\x0c" and pid == 0x2000:
            return "cdp", cdp_detail(frame.llc_payload[8:])
    if frame.ethertype == 0x0806:
        return "arp", {"op": struct.unpack(">H", p[6:8])[0] if len(p) >= 8 else 0}

    # OPC UA binary (magic ASCII)
    if len(p) >= 8 and p[0:3] in (b"HEL", b"ACK", b"ERR", b"OPN", b"MSG", b"CLO"):
        return "opcua", opcua_detail(p)

    # S7comm / MMS su TPKT
    if len(p) >= 8 and p[0:2] == b"\x03\x00":
        if p[7:8] == b"\x32":
            return "s7comm", s7_detail(p)
        if frame.dst_port == 102 or frame.src_port == 102:
            return "iec61850-mms", {"note": "ISO-on-TCP senza header S7 (MMS/ACSE)"}

    # Modbus/TCP: transaction, protocol id 0, length coerente
    if len(p) >= 8:
        proto_id = struct.unpack(">H", p[2:4])[0]
        length = struct.unpack(">H", p[4:6])[0]
        fc = p[7]
        if proto_id == 0 and 2 <= length <= 260 and 1 <= fc <= 127:
            if frame.dst_port == 502 or frame.src_port == 502 or length == len(p) - 6:
                return "modbus", modbus_detail(p)

    # DNP3 link header
    if len(p) >= 10 and p[0:2] == b"\x05\x64":
        return "dnp3", dnp3_detail(p)

    # BACnet/IP
    if len(p) >= 6 and p[0] == 0x81 and p[1] in (0x04, 0x0A, 0x0B, 0x0C):
        return "bacnet", bacnet_detail(p)

    # IEC 60870-5-104
    if len(p) >= 6 and p[0] == 0x68 and p[1] == len(p) - 2:
        return "iec104", iec104_detail(p)

    # EtherNet/IP encapsulation
    if len(p) >= 24:
        command = struct.unpack("<H", p[0:2])[0]
        if command in (0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070, 0x0072, 0x0073):
            length = struct.unpack("<H", p[2:4])[0]
            if length + 24 <= len(p) + 16:
                return "enip", enip_detail(p, command)

    # MQTT CONNECT
    if len(p) >= 2 and p[0] == 0x10 and 2 < p[1] < 200:
        return "mqtt", {"type": "CONNECT"}

    # Niagara Fox handshake
    if p[:4] in (b"fox ", b"Fox "):
        return "niagara-fox", {"note": "handshake Niagara Fox"}

    # Fallback su porta
    port = frame.dst_port or frame.src_port
    if port in OT_TCP_PORTS:
        return OT_TCP_PORTS[port], {}
    if port in OT_UDP_PORTS:
        return OT_UDP_PORTS[port], {}
    if port in IT_PORTS:
        return IT_PORTS[port], {}
    if port in (53, 5353) and frame.ip_proto == 17:
        return "dns", dns_detail(p)
    return "unknown", {}


# ── Decoder di protocollo ────────────────────────────────────────────────────
def _is_write(protocol: str, code: int) -> bool:
    table = DANGEROUS_OPERATIONS.get(protocol, {})
    return code in table


def modbus_detail(p: bytes) -> Dict[str, Any]:
    """Modbus/TCP: header MBAP + function code.

    Riconosce le funzioni di scrittura: sono l'indicatore piu' diretto di un
    comando malevolo (o di un operatore che ha sbagliato HMI).
    """
    detail: Dict[str, Any] = {}
    try:
        trans_id, proto_id, length, unit_id, fc = struct.unpack(">HHHBB", p[:8])
    except struct.error:
        return detail
    detail.update({
        "transaction_id": trans_id, "unit_id": unit_id, "function_code": fc,
        "exception": bool(fc & 0x80),
        "is_write": _is_write("modbus", fc & 0x7F),
    })
    base_fc = fc & 0x7F
    if base_fc in (1, 2, 3, 4) and len(p) >= 12:
        addr, qty = struct.unpack(">HH", p[8:12])
        detail.update({"address": addr, "quantity": qty})
    elif base_fc in (5, 6) and len(p) >= 12:
        addr, value = struct.unpack(">HH", p[8:12])
        detail.update({"address": addr, "value": value})
    elif base_fc in (15, 16) and len(p) >= 13:
        addr, qty = struct.unpack(">HH", p[8:12])
        detail.update({"address": addr, "quantity": qty})
    elif base_fc == 0x2B and len(p) > 8:
        detail["mei_type"] = p[8] if len(p) > 8 else 0
    return detail


def s7_detail(p: bytes) -> Dict[str, Any]:
    """S7comm: header S7 dopo TPKT+COTP."""
    detail: Dict[str, Any] = {}
    try:
        cotp_len = p[4]
        s7_off = 5 + cotp_len
        if p[s7_off] != 0x32:
            return detail
        rosctr = p[s7_off + 1]
        param_len = struct.unpack(">H", p[s7_off + 6:s7_off + 8])[0]
        func = p[s7_off + 10] if len(p) > s7_off + 10 else 0
    except (IndexError, struct.error):
        return detail
    names = {
        0x04: "Read Var", 0x05: "Write Var", 0x1A: "Request Download",
        0x1B: "Download Block", 0x1C: "Download Ended", 0x1D: "Start Upload",
        0x1E: "Upload", 0x1F: "End Upload", 0x28: "PLC Control", 0x29: "PLC Stop",
        0xF0: "Setup Communication",
    }
    detail.update({
        "rosctr": rosctr, "function_code": func,
        "function": names.get(func, f"0x{func:02X}"),
        "is_write": _is_write("s7", func),
        "param_len": param_len,
    })
    return detail


def dnp3_detail(p: bytes) -> Dict[str, Any]:
    detail: Dict[str, Any] = {}
    try:
        length = p[2]
        dest = struct.unpack("<H", p[4:6])[0]
        src = struct.unpack("<H", p[6:8])[0]
        app_off = 10
        if len(p) <= app_off + 2:
            return detail
        func = p[app_off + 2]
    except (IndexError, struct.error):
        return detail
    names = {
        0x01: "Read", 0x02: "Write", 0x03: "Select", 0x04: "Operate",
        0x05: "Direct Operate", 0x06: "Direct Operate No Ack",
        0x0D: "Cold Restart", 0x0E: "Warm Restart",
        0x12: "Stop Application", 0x20: "Response",
    }
    detail.update({
        "length": length, "dest": dest, "src": src,
        "function_code": func, "function": names.get(func, f"0x{func:02X}"),
        "is_write": _is_write("dnp3", func),
    })
    return detail


def enip_detail(p: bytes, command: int) -> Dict[str, Any]:
    names = {
        0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces",
        0x0065: "RegisterSession", 0x0066: "UnRegisterSession",
        0x006F: "SendRRData", 0x0070: "SendUnitData",
        0x0072: "IndicateStatus", 0x0073: "Cancel",
    }
    detail: Dict[str, Any] = {
        "command": command, "command_name": names.get(command, f"0x{command:04X}"),
        "session": struct.unpack("<I", p[4:8])[0] if len(p) >= 8 else 0,
    }
    # SendRRData contiene un CIP service: 0x4D/0x4E sono scritture di tag.
    if command == 0x006F:
        for svc in (0x4D, 0x4E, 0x52, 0x53):
            if svc in p[24:]:
                detail.update({"cip_service": svc, "is_write": True})
                break
    return detail


def bacnet_detail(p: bytes) -> Dict[str, Any]:
    detail: Dict[str, Any] = {"bvlc_function": p[1] if len(p) > 1 else 0}
    try:
        npdu_ctrl = p[5]
        off = 6
        if npdu_ctrl & 0x20:                     # DNET/DADR
            dlen = p[off + 2]
            off += 3 + dlen
        if npdu_ctrl & 0x08:                     # SNET/SADR
            slen = p[off + 2]
            off += 3 + slen
        if npdu_ctrl & 0x20:
            off += 1                             # hop count
        apdu_type = p[off] >> 4
        detail["apdu_type"] = apdu_type
        if apdu_type == 0:                       # Confirmed-Request
            service = p[off + 3]
            detail.update({"service": service, "is_write": _is_write("bacnet", service)})
        elif apdu_type == 1:                     # Unconfirmed-Request
            service = p[off + 1]
            detail.update({"unconfirmed_service": service})
    except (IndexError, struct.error):
        pass
    return detail


def iec104_detail(p: bytes) -> Dict[str, Any]:
    detail: Dict[str, Any] = {}
    try:
        ctrl = p[2:6]
        if ctrl[0] & 0x01:
            detail["frame"] = "S" if ctrl[0] & 0x02 else "U"
            return detail
        type_id = p[6]
        detail.update({
            "frame": "I", "type_id": type_id,
            "is_write": _is_write("iec104", type_id),
            "cot": struct.unpack("<H", p[8:10])[0] if len(p) >= 10 else 0,
        })
    except IndexError:
        pass
    return detail


def opcua_detail(p: bytes) -> Dict[str, Any]:
    detail: Dict[str, Any] = {"message_type": p[0:3].decode("ascii", errors="replace")}
    detail["chunk_type"] = chr(p[3]) if len(p) > 3 else ""
    if p[0:3] == b"MSG" and len(p) >= 20:
        # Header(8) + SecureChannelId(4) + TokenId(4): token 0 == nessuna sicurezza.
        token_id = struct.unpack("<I", p[12:16])[0]
        detail["security_token_id"] = token_id
        detail["unencrypted"] = token_id == 0
    if p[0:3] == b"ACK":
        try:
            detail["server_protocol_version"] = struct.unpack("<I", p[8:12])[0]
        except struct.error:
            pass
    return detail


def profinet_detail(p: bytes) -> Tuple[str, Dict[str, Any]]:
    detail: Dict[str, Any] = {}
    try:
        frame_id = struct.unpack(">H", p[0:2])[0]
        detail["frame_id"] = frame_id
        if frame_id in (0xFEFE, 0xFEFF):
            service_type = p[2]
            service_id = p[3]
            detail.update({
                "dcp_service": {0x01: "Get", 0x03: "Set", 0x04: "Identify",
                                0x05: "Hello"}.get(service_id, f"0x{service_id:02X}"),
                "dcp_response": service_type == 0x01,
                "is_write": service_id == 0x03,
            })
            detail.update(_profinet_dcp_blocks(p[12:]))
            return "profinet-dcp", detail
        if 0x8000 <= frame_id <= 0xBFFF:
            return "profinet-rt", detail
        if 0xC000 <= frame_id <= 0xFBFF:
            return "profinet-alarm", detail
    except (IndexError, struct.error):
        pass
    return "profinet", detail


def _profinet_dcp_blocks(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    i = 0
    while i + 4 <= len(data):
        option, suboption, blen = data[i], data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
        block = data[i + 4:i + 4 + blen]
        i += 4 + blen
        if len(block) < blen:
            break
        if option == 0x02 and suboption == 0x02:
            out["station_name"] = block.decode("ascii", errors="replace").strip("\x00")
        elif option == 0x02 and suboption == 0x03 and len(block) >= 4:
            vendor, device = struct.unpack(">HH", block[0:4])
            out.update({"vendor_id": vendor, "device_id": device})
        elif option == 0x02 and suboption == 0x04 and block:
            out["device_role"] = {0x01: "io-device", 0x02: "io-controller",
                                  0x04: "io-supervisor"}.get(block[0], str(block[0]))
        elif option == 0x01 and suboption == 0x02 and len(block) >= 12:
            out["ip"] = ip4_str(block[0:4])
            out["netmask"] = ip4_str(block[4:8])
            out["gateway"] = ip4_str(block[8:12])
        elif option == 0x02 and suboption == 0x01:
            out["device_type"] = block.decode("ascii", errors="replace").strip("\x00")
    return out


def lldp_detail(p: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    i = 0
    while i + 2 <= len(p):
        header = struct.unpack(">H", p[i:i + 2])[0]
        tlv_type = header >> 9
        tlv_len = header & 0x01FF
        i += 2
        if tlv_type == 0:
            break
        value = p[i:i + tlv_len]
        i += tlv_len
        if tlv_type == 1 and value:
            out["chassis_id"] = _chassis_id(value)
        elif tlv_type == 2 and value:
            out["port_id"] = value[1:].decode("ascii", errors="replace") if value[0] == 5 else value[1:].hex()
        elif tlv_type == 3 and len(value) >= 2:
            out["ttl"] = struct.unpack(">H", value[:2])[0]
        elif tlv_type == 5:
            out["system_name"] = value.decode("ascii", errors="replace").strip("\x00")
        elif tlv_type == 6:
            out["system_description"] = value.decode("ascii", errors="replace").strip("\x00")
        elif tlv_type == 7 and len(value) >= 4:
            caps = struct.unpack(">H", value[0:2])[0]
            out["capabilities"] = _lldp_caps(caps)
        elif tlv_type == 8 and len(value) >= 2:
            # LLDP management address: len(1) = subtype + indirizzo
            addr_len = value[0]
            if len(value) >= 1 + addr_len:
                subtype = value[1]
                raw = value[2:1 + addr_len]
                if subtype == 1 and len(raw) == 4:
                    out["management_ip"] = ip4_str(raw)
    return out


def _chassis_id(value: bytes) -> str:
    if not value:
        return ""
    subtype = value[0]
    raw = value[1:]
    if subtype == 4 and len(raw) == 6:
        return mac_str(raw)
    if subtype == 7:
        return raw.decode("ascii", errors="replace")
    return raw.hex()


def _lldp_caps(caps: int) -> List[str]:
    mapping = {0x01: "other", 0x02: "repeater", 0x04: "bridge", 0x08: "wlan-ap",
               0x10: "router", 0x20: "telephone", 0x40: "docsis", 0x80: "station"}
    return [name for bit, name in mapping.items() if caps & bit]


def cdp_detail(p: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    i = 0
    while i + 4 <= len(p):
        tlv_type, tlv_len = struct.unpack(">HH", p[i:i + 4])
        if tlv_len < 4:
            break
        value = p[i + 4:i + tlv_len]
        i += tlv_len
        if tlv_type == 0x0001:
            out["device_id"] = value.decode("ascii", errors="replace")
        elif tlv_type == 0x0003:
            out["port_id"] = value.decode("ascii", errors="replace")
        elif tlv_type == 0x0005:
            out["software_version"] = value.decode("ascii", errors="replace")
        elif tlv_type == 0x0006:
            out["platform"] = value.decode("ascii", errors="replace")
        elif tlv_type == 0x0002 and len(value) >= 13:
            # Indirizzo IPv4: protocol type 1, protocol length 1, protocol 0xCC, addr len 4
            addr_len = struct.unpack(">H", value[0:2])[0]
            proto = value[2:2 + addr_len]
            if proto.endswith(b"\xcc") and len(value) >= 2 + addr_len + 2 + 4:
                out["management_ip"] = ip4_str(value[2 + addr_len + 2:2 + addr_len + 6])
        elif tlv_type == 0x000A and len(value) >= 2:
            out["native_vlan"] = struct.unpack(">H", value[0:2])[0]
    return out


def dhcp_detail(p: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if len(p) < 240:
        return out
    magic = p[236:240]
    if magic != b"\x63\x82\x53\x63":
        return out
    i = 240
    while i < len(p):
        code = p[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(p):
            break
        length = p[i + 1]
        value = p[i + 2:i + 2 + length]
        if code == 12:
            out["hostname"] = value.decode("ascii", errors="replace").strip("\x00")
        elif code == 60:
            out["vendor_class"] = value.decode("ascii", errors="replace").strip("\x00")
        elif code == 53 and value:
            out["message_type"] = value[0]
        i += 2 + length
    return out


def dns_detail(p: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        if len(p) < 12:
            return out
        qdcount = struct.unpack(">H", p[4:6])[0]
        if qdcount == 0:
            return out
        i = 12
        labels: List[str] = []
        while i < len(p) and len(labels) < 20:
            ln = p[i]
            if ln == 0:
                i += 1
                break
            if ln & 0xC0:
                break
            labels.append(p[i + 1:i + 1 + ln].decode("ascii", errors="replace"))
            i += 1 + ln
        out["qname"] = ".".join(labels)
    except Exception:
        pass
    return out


def netbios_name(p: bytes) -> str:
    """Nome NetBIOS codificato (32 byte 'half-ASCII') nei pacchetti NBNS."""
    if len(p) < 45:
        return ""
    raw = p[13:45]
    out = []
    for i in range(0, 32, 2):
        hi, lo = raw[i] - 0x41, raw[i + 1] - 0x41
        out.append(chr((hi << 4) | lo))
    return "".join(out).strip()


def snmp_sysdescr(p: bytes) -> str:
    """Estrae sysDescr da una risposta SNMPv2c (OID 1.3.6.1.2.1.1.1.0)."""
    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
    idx = p.find(oid)
    if idx < 0:
        return ""
    tag = idx + len(oid)
    if tag + 2 > len(p) or p[tag] != 0x04:
        return ""
    length = p[tag + 1]
    return p[tag + 2:tag + 2 + length].decode("utf-8", errors="replace").strip("\x00")


def summarize(frame: Frame) -> Dict[str, Any]:
    proto, detail = classify(frame)
    return {
        "ts": frame.ts,
        "src": frame.src_ip or frame.src_mac,
        "dst": frame.dst_ip or frame.dst_mac,
        "sport": frame.src_port,
        "dport": frame.dst_port,
        "protocol": proto,
        "detail": detail,
        "length": frame.frame_len,
    }
