"""Fingerprinting read-only dei device industriali.

Ogni sonda qui dentro invia **solo** richieste di identificazione previste dallo
standard e non modificabili:

============================  ==============================================
Protocollo                    PDU inviata
============================  ==============================================
Modbus/TCP                    FC 0x2B / MEI 0x0E Read Device Identification
S7comm                        COTP CR + Setup Communication + Read SZL
EtherNet/IP                   ListIdentity (UDP 44818, nessuna sessione CIP)
BACnet/IP                     Who-Is + ReadProperty (vendor/model/firmware)
SNMP v2c                      GET sysDescr/sysName/sysObjectID
OPC UA                        Hello/Acknowledge (+ GetEndpoints se asyncua c'e')
HTTP (HMI/web server)         GET / e header, sola lettura
============================  ==============================================

DNP3, IEC 60870-5-104, PROFINET I/O, EtherCAT e CIP implicito **non** vengono
sollecitati: una singola PDU puo' avere effetti sul processo, quindi vengono
solo classificati dal traffico passivo.
"""
from __future__ import annotations

import logging
import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from .models import Asset
from .safety import SafetyGuard, UnsafeOperationError

LOGGER = logging.getLogger("aegis.site.fingerprint")

MAX_RESPONSE = 4096

# ── utility di rete ───────────────────────────────────────────────────────────
def _tcp_exchange(ip: str, port: int, payload: bytes, timeout: float,
                  read_bytes: int = MAX_RESPONSE) -> bytes:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            chunks: List[bytes] = []
            total = 0
            deadline = time.time() + timeout
            while time.time() < deadline and total < read_bytes:
                try:
                    chunk = sock.recv(min(1024, read_bytes - total))
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                # Le risposte industriali sono piccole: una lettura basta.
                if total >= 512:
                    break
            return b"".join(chunks)
    except OSError:
        return b""


def _udp_exchange(ip: str, port: int, payload: bytes, timeout: float) -> bytes:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(MAX_RESPONSE)
            return data
    except OSError:
        return b""


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Sequenze stampabili: utile per estrarre MLFB e firmware da record binari."""
    out: List[str] = []
    current: List[str] = []
    for byte in data:
        char = chr(byte)
        if 32 <= byte < 127:
            current.append(char)
        else:
            if len(current) >= min_len:
                out.append("".join(current))
            current = []
    if len(current) >= min_len:
        out.append("".join(current))
    return out


def _result(protocol: str, success: bool, identity: Optional[Dict[str, Any]] = None,
            evidence: str = "", error: str = "") -> Dict[str, Any]:
    return {
        "protocol": protocol,
        "success": bool(success),
        "identity": identity or {},
        "evidence": evidence,
        "error": error,
        "safe": True,
        "read_only": True,
    }


# ── Modbus ───────────────────────────────────────────────────────────────────
MODBUS_OBJECTS = {
    0: "vendor_name",
    1: "product_code",
    2: "revision",
    3: "vendor_url",
    4: "product_name",
    5: "model_name",
    6: "user_application",
}


def probe_modbus_identity(ip: str, guard: SafetyGuard, port: int = 502, unit: int = 1,
                          timeout: float = 2.0) -> Dict[str, Any]:
    """Read Device Identification (FC 0x2B / MEI 0x0E), codice 0x01."""
    guard.authorize_ip(ip, purpose="modbus-identify")
    guard.assert_readonly("modbus", 0x2B)   # esplicitamente in allow-list
    guard.pace(ip)

    request = struct.pack(">HHHBBBBB", 1, 0, 5, unit, 0x2B, 0x0E, 0x01, 0x00)
    response = _tcp_exchange(ip, port, request, timeout)
    if len(response) < 9:
        return _result("modbus", False, error="nessuna risposta")

    fc = response[7]
    if fc & 0x80:
        return _result("modbus", False, error=f"eccezione Modbus 0x{response[8]:02X}")

    identity: Dict[str, Any] = {"unit_id": unit}
    try:
        count = response[13]
        offset = 14
        for _ in range(min(count, 8)):
            obj_id, obj_len = response[offset], response[offset + 1]
            value = response[offset + 2:offset + 2 + obj_len].decode("latin-1", errors="replace").strip("\x00")
            identity[MODBUS_OBJECTS.get(obj_id, f"object_{obj_id}")] = value
            offset += 2 + obj_len
    except (IndexError, struct.error):
        pass

    if identity.get("vendor_name") or identity.get("product_name"):
        return _result("modbus", True, identity,
                       evidence=f"FC43 Read Device ID unit={unit}: {identity.get('vendor_name','?')} {identity.get('product_name','')}".strip())
    # Device Modbus che risponde ma non supporta FC43: lo dichiariamo, senza inventare.
    return _result("modbus", True, identity, evidence="device Modbus raggiungibile (FC43 non supportato)")


# ── EtherNet/IP ──────────────────────────────────────────────────────────────
ENIP_VENDORS = {1: "Rockwell Automation/Allen-Bradley", 2: "Namco Controls", 3: "Rockwell Automation",
                5: "Siemens", 16: "ABB", 25: "Honeywell", 47: "Phoenix Contact", 90: "Mitsubishi Electric",
                117: "Omron", 137: "WAGO", 161: "Beckhoff"}
ENIP_DEVICE_TYPES = {0x00: "generic", 0x0C: "communications-adapter", 0x0E: "plc",
                     0x24: "hmi", 0x2B: "drive", 0x2C: "motion-drive"}


def probe_enip_identity(ip: str, guard: SafetyGuard, port: int = 44818,
                        timeout: float = 2.0) -> Dict[str, Any]:
    """ListIdentity: 24 byte di header, nessuna sessione CIP aperta."""
    guard.authorize_ip(ip, purpose="enip-listidentity")
    guard.pace(ip)

    # command=0x0063, length=0, session=0, status=0, context, options
    request = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    response = _udp_exchange(ip, port, request, timeout)
    if len(response) < 30:
        return _result("enip", False, error="nessuna risposta ListIdentity")

    try:
        offset = 24
        item_count = struct.unpack("<H", response[offset:offset + 2])[0]
        offset += 2
        identity: Dict[str, Any] = {"items": item_count}
        for _ in range(min(item_count, 4)):
            item_type, item_len = struct.unpack("<HH", response[offset:offset + 4])
            offset += 4
            if item_type == 0x000C and item_len >= 33:      # CIP Identity
                data = response[offset:offset + item_len]
                vendor_id = struct.unpack("<H", data[18:20])[0]
                device_type = struct.unpack("<H", data[20:22])[0]
                product_code = struct.unpack("<H", data[22:24])[0]
                major, minor = data[24], data[25]
                serial = struct.unpack("<I", data[28:32])[0]
                name_len = data[32]
                product_name = data[33:33 + min(name_len, 32)].decode("latin-1", errors="replace").strip("\x00")
                identity.update({
                    "vendor_id": vendor_id,
                    "vendor": ENIP_VENDORS.get(vendor_id, f"vendor-{vendor_id}"),
                    "device_type_code": device_type,
                    "device_type": ENIP_DEVICE_TYPES.get(device_type, f"type-{device_type}"),
                    "product_code": product_code,
                    "product_name": product_name,
                    "revision": f"{major}.{minor}",
                    "serial": f"{serial:08X}",
                })
            offset += item_len
        if identity.get("product_name") or identity.get("vendor_id"):
            return _result("enip", True, identity,
                           evidence=f"CIP Identity: {identity.get('vendor','?')} {identity.get('product_name','')} v{identity.get('revision','?')}")
        return _result("enip", True, identity, evidence="ListIdentity risposto")
    except (IndexError, struct.error) as exc:
        return _result("enip", False, error=f"risposta non valida: {exc}")


# ── S7comm ───────────────────────────────────────────────────────────────────
def _cotp_cr(rack: int, slot: int) -> bytes:
    dst_tsap = 0x0100 | ((rack & 0x07) << 5) | (slot & 0x1F)
    cotp = bytes([0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                  0xC1, 0x02, 0x01, 0x00,
                  0xC2, 0x02, (dst_tsap >> 8) & 0xFF, dst_tsap & 0xFF,
                  0xC0, 0x01, 0x0A])
    return bytes([0x03, 0x00, 0x00, len(cotp) + 4]) + cotp


def _s7_setup() -> bytes:
    params = bytes([0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0])
    header = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01,
                    0x00, len(params), 0x00, 0x00])
    cotp = bytes([0x02, 0xF0, 0x80])
    total = 4 + len(cotp) + len(header) + len(params)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + cotp + header + params


def _s7_read_szl(szl_id: int, index: int = 1) -> bytes:
    params = bytes([0x04, 0x01, 0x12, 0x04, 0x11, 0x44,
                    (szl_id >> 8) & 0xFF, szl_id & 0xFF,
                    (index >> 8) & 0xFF, index & 0xFF])
    header = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01,
                    0x00, len(params), 0x00, 0x00])
    cotp = bytes([0x02, 0xF0, 0x80])
    total = 4 + len(cotp) + len(header) + len(params)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + cotp + header + params


MLFB_RE = re.compile(r"6(?:ES|AG|GK|AV|NH|SL)\d[\w\s\-\.]{4,}")
FW_RE = re.compile(r"V\d+\.\d+(?:\.\d+)?")


def probe_s7_identity(ip: str, guard: SafetyGuard, port: int = 102,
                      timeout: float = 3.0) -> Dict[str, Any]:
    """S7: COTP CR, Setup Communication, Read SZL 0x0011 e 0x001C."""
    guard.authorize_ip(ip, purpose="s7-identify")
    guard.assert_readonly("s7", 0x04)        # Read Var / Read SZL
    guard.pace(ip)

    for rack, slot in ((0, 0), (0, 1), (0, 2)):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(_cotp_cr(rack, slot))
                cc = sock.recv(256)
                if not cc or len(cc) < 6 or cc[5] != 0xD0:
                    continue
                sock.sendall(_s7_setup())
                setup = sock.recv(256)
                if not setup or len(setup) < 8:
                    continue

                strings: List[str] = []
                for szl in (0x0011, 0x001C, 0x0001):
                    guard.pace(ip)
                    sock.sendall(_s7_read_szl(szl, 1))
                    data = sock.recv(2048)
                    strings.extend(ascii_strings(data))
                    if szl == 0x0011 and strings:
                        break

                identity: Dict[str, Any] = {"rack": rack, "slot": slot}
                mlfb = ""
                for text in strings:
                    match = MLFB_RE.search(text)
                    if match and not mlfb:
                        mlfb = match.group(0).strip()
                firmware = ""
                for text in strings:
                    match = FW_RE.search(text)
                    if match:
                        firmware = match.group(0)
                        break
                if mlfb:
                    identity["mlfb"] = mlfb
                if firmware:
                    identity["firmware"] = firmware
                interesting = [s for s in strings if len(s) >= 6][:12]
                if interesting:
                    identity["records"] = interesting

                if mlfb or firmware:
                    return _result(
                        "s7comm", True, identity,
                        evidence=f"S7 rack {rack} slot {slot}: {mlfb or 'MLFB non letto'} {firmware}".strip(),
                    )
                return _result("s7comm", True, identity,
                               evidence=f"S7 raggiungibile (rack {rack} slot {slot}), SZL senza record leggibili")
        except OSError:
            continue
    return _result("s7comm", False, error="connessione S7 non stabilita")


# ── BACnet ───────────────────────────────────────────────────────────────────
BACNET_VENDORS = {0: "ASHAE", 2: "Siemens", 5: "Johnson Controls", 7: "Honeywell",
                  8: "Trane", 24: "Distech", 36: "ABB", 67: "Schneider Electric",
                  86: "Sauter", 99: "Delta Controls"}


def _bacnet_whois() -> bytes:
    return bytes([0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08])


def _bacnet_read_property(instance: int, prop: int) -> bytes:
    apdu = bytes([0x00, 0x05, 0x01, 0x0C,
                  0x0C, 0x02,
                  (instance >> 16) & 0xFF, (instance >> 8) & 0xFF, instance & 0xFF,
                  0x19, prop & 0xFF])
    npdu = bytes([0x01, 0x00])
    body = npdu + apdu
    return bytes([0x81, 0x0A, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body


def probe_bacnet_identity(ip: str, guard: SafetyGuard, port: int = 47808,
                          timeout: float = 2.5) -> Dict[str, Any]:
    """Who-Is unicast + ReadProperty su device object."""
    guard.authorize_ip(ip, purpose="bacnet-whois")
    guard.assert_readonly("bacnet", 0x0C)   # ReadProperty (non in blacklist)
    guard.pace(ip)

    response = _udp_exchange(ip, port, _bacnet_whois(), timeout)
    if len(response) < 18:
        return _result("bacnet", False, error="nessuna risposta Who-Is")

    identity: Dict[str, Any] = {}
    try:
        obj_id = struct.unpack(">I", response[8:12])[0]
        instance = obj_id & 0x3FFFFF
        vendor_id = struct.unpack(">H", response[16:18])[0]
        identity.update({"device_instance": instance, "vendor_id": vendor_id,
                         "vendor": BACNET_VENDORS.get(vendor_id, f"vendor-{vendor_id}")})
    except (IndexError, struct.error):
        return _result("bacnet", False, error="risposta I-Am malformata")

    # ReadProperty vendor-name (121) e model-name (70): sola lettura.
    for prop, key in ((121, "vendor_name"), (70, "model_name"), (44, "firmware")):
        guard.pace(ip)
        ack = _udp_exchange(ip, port, _bacnet_read_property(identity["device_instance"], prop), timeout)
        if not ack:
            continue
        strings = [s for s in ascii_strings(ack, 3) if s not in ("$",)]
        if strings:
            identity[key] = strings[-1]

    return _result("bacnet", True, identity,
                   evidence=f"BACnet device {identity.get('device_instance')} "
                            f"{identity.get('vendor_name', identity.get('vendor',''))}".strip())


# ── SNMP ─────────────────────────────────────────────────────────────────────
def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        payload = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return _ber_tlv(0x02, payload)


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            encoded += bytes([part])
        else:
            chunk = []
            while part:
                chunk.insert(0, part & 0x7F)
                part >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            encoded += bytes(chunk)
    return _ber_tlv(0x06, encoded)


def _snmp_get(oid: str, community: str) -> bytes:
    varbind = _ber_tlv(0x30, _ber_oid(oid) + _ber_tlv(0x05, b""))
    pdu = _ber_tlv(0xA0, _ber_int(1) + _ber_int(0) + _ber_int(0) + _ber_tlv(0x30, varbind))
    message = _ber_tlv(0x30, _ber_int(1) + _ber_tlv(0x04, community.encode()) + pdu)
    return message


def _ber_octet_strings(data: bytes) -> List[bytes]:
    """Estrae tutti gli OCTET STRING da una risposta BER (parser ricorsivo minimo)."""
    out: List[bytes] = []

    def walk(buf: bytes, depth: int = 0) -> None:
        i = 0
        while i < len(buf) and depth < 12:
            tag = buf[i]
            i += 1
            if i >= len(buf):
                return
            length = buf[i]
            i += 1
            if length & 0x80:
                n = length & 0x7F
                if n == 0 or i + n > len(buf):
                    return
                length = int.from_bytes(buf[i:i + n], "big")
                i += n
            value = buf[i:i + length]
            i += length
            if tag in (0x30, 0xA2, 0xA1):
                walk(value, depth + 1)
            elif tag == 0x04:
                out.append(value)

    walk(data)
    return out


def probe_snmp_identity(ip: str, guard: SafetyGuard, port: int = 161,
                        timeout: float = 2.0,
                        communities: Tuple[str, ...] = ("public", "private")) -> Dict[str, Any]:
    """GET su sysDescr/sysName/sysObjectID. Nessun walk: traffico minimo."""
    guard.authorize_ip(ip, purpose="snmp-get")
    guard.pace(ip)

    for community in communities:
        guard.pace(ip)
        response = _udp_exchange(ip, port, _snmp_get("1.3.6.1.2.1.1.1.0", community), timeout)
        if not response:
            continue
        strings = _ber_octet_strings(response)
        # Il primo OCTET STRING e' la community, il secondo sysDescr.
        values = [s for s in strings[1:] if s]
        sysdescr = values[0].decode("latin-1", errors="replace") if values else ""
        identity: Dict[str, Any] = {"community": community, "sys_descr": sysdescr}

        for oid, key in (("1.3.6.1.2.1.1.5.0", "sys_name"), ("1.3.6.1.2.1.1.2.0", "sys_object_id")):
            guard.pace(ip)
            extra = _udp_exchange(ip, port, _snmp_get(oid, community), timeout)
            if extra:
                found = _ber_octet_strings(extra)
                if len(found) > 1:
                    identity[key] = found[1].decode("latin-1", errors="replace")
                elif found:
                    identity[key] = found[0].decode("latin-1", errors="replace")

        vulnerability = community in ("public", "private")
        return _result("snmp", True, identity,
                       evidence=f"SNMP community '{community}' accettata"
                                + (" (default!)" if vulnerability else ""))
    return _result("snmp", False, error="nessuna community SNMP ha risposto")


# ── OPC UA ───────────────────────────────────────────────────────────────────
def _opcua_hello(url: str) -> bytes:
    body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0)
    endpoint = url.encode()
    payload = struct.pack("<I", len(endpoint)) + endpoint
    message = b"HELF" + struct.pack("<I", 8 + len(body) + len(payload)) + body + payload
    return message


def probe_opcua_identity(ip: str, guard: SafetyGuard, port: int = 4840,
                         timeout: float = 3.0) -> Dict[str, Any]:
    """Hello/Acknowledge: conferma un endpoint OPC UA senza aprire sessione."""
    guard.authorize_ip(ip, purpose="opcua-hello")
    guard.pace(ip)

    url = f"opc.tcp://{ip}:{port}"
    response = _tcp_exchange(ip, port, _opcua_hello(url), timeout, read_bytes=512)
    if len(response) < 8 or response[0:3] != b"ACK":
        if response[0:3] == b"ERR":
            code = struct.unpack("<I", response[8:12])[0] if len(response) >= 12 else 0
            return _result("opcua", False, error=f"server OPC UA ha risposto con errore 0x{code:08X}")
        return _result("opcua", False, error="nessun Acknowledge OPC UA")

    identity: Dict[str, Any] = {"endpoint": url}
    try:
        recv_buf, send_buf = struct.unpack("<II", response[16:24])
        identity["receive_buffer"] = recv_buf
        identity["send_buffer"] = send_buf
    except struct.error:
        pass

    # Se asyncua e' installato, enumera gli endpoint e le security policy.
    try:
        from asyncua import Client  # type: ignore

        with Client(url, timeout=timeout) as client:
            endpoints = client.connect_socket  # placeholder per type checker
            del endpoints
        identity["enumerated"] = False
    except Exception:
        identity["enumerated"] = False

    return _result("opcua", True, identity, evidence=f"OPC UA server su {url}")


# ── HTTP / HMI ───────────────────────────────────────────────────────────────
HMI_SIGNATURES: List[Tuple[str, str]] = [
    ("siemens", "Siemens (SIMATIC/WinCC)"),
    ("simatic", "Siemens SIMATIC"),
    ("wincc", "Siemens WinCC"),
    ("sinema", "Siemens SINEMA"),
    ("ignition", "Inductive Automation Ignition"),
    ("inductive automation", "Inductive Automation Ignition"),
    ("wonderware", "AVEVA/Wonderware"),
    ("aveva", "AVEVA"),
    ("factorytalk", "Rockwell FactoryTalk"),
    ("rockwell", "Rockwell Automation"),
    ("codesys", "CODESYS WebVisu"),
    ("webvisu", "CODESYS WebVisu"),
    ("twincat", "Beckhoff TwinCAT"),
    ("beckhoff", "Beckhoff"),
    ("wago", "WAGO Web-Based Management"),
    ("moxa", "Moxa"),
    ("nport", "Moxa NPort"),
    ("hirschmann", "Hirschmann"),
    ("hivision", "Hirschmann HiVision"),
    ("schneider", "Schneider Electric"),
    ("modicon", "Schneider Modicon"),
    ("magelis", "Schneider Magelis"),
    ("omron", "Omron"),
    ("melsec", "Mitsubishi MELSEC"),
    ("phoenix contact", "Phoenix Contact"),
    ("sauter", "Sauter"),
    ("carel", "Carel"),
    ("delta controls", "Delta Controls"),
]

LOGIN_HINTS = ("password", "login", "signin", "sign-in", "utente", "accedi")


def probe_http_identity(ip: str, guard: SafetyGuard, port: int = 80,
                        timeout: float = 2.5) -> Dict[str, Any]:
    """GET / su HMI o web server industriale: titolo, server, indizi di login."""
    guard.authorize_ip(ip, purpose="http-banner")
    guard.pace(ip)

    scheme = "https" if port in (443, 8443) else "http"
    request = (
        f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\n"
        f"User-Agent: AEGIS-Assess/1.0 (read-only)\r\n"
        f"Accept: text/html,*/*\r\nConnection: close\r\n\r\n"
    ).encode()

    if scheme == "https":
        import ssl
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=ip) as tls:
                    tls.settimeout(timeout)
                    tls.sendall(request)
                    data = tls.recv(4096)
        except OSError:
            return _result("http", False, error="TLS handshake fallito")
    else:
        data = _tcp_exchange(ip, port, request, timeout, read_bytes=4096)

    if not data:
        return _result("http", False, error="nessuna risposta HTTP")

    text = data.decode("latin-1", errors="replace")
    header_blob, _, body = text.partition("\r\n\r\n")
    headers = header_blob.splitlines()
    status_line = headers[0] if headers else ""
    server = ""
    for line in headers[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""

    haystack = (text[:6000]).lower()
    detected = ""
    for needle, label in HMI_SIGNATURES:
        if needle in haystack:
            detected = label
            break

    identity: Dict[str, Any] = {
        "status_line": status_line,
        "server": server,
        "title": title[:120],
        "product": detected,
        "login_page": any(hint in haystack for hint in LOGIN_HINTS),
        "auth_required": status_line.startswith("HTTP/1.1 401") or status_line.startswith("HTTP/1.0 401"),
    }
    return _result("http", True, identity,
                   evidence=f"{status_line} server={server or '?'} title={title[:60] or '?'}")


# ── orchestrazione ───────────────────────────────────────────────────────────
PROBE_BY_PORT: Dict[int, str] = {
    502: "modbus", 102: "s7comm", 44818: "enip", 47808: "bacnet",
    161: "snmp", 4840: "opcua", 80: "http", 443: "http", 8080: "http", 8443: "http",
}

# Protocolli volutamente non sollecitati.
NO_PROBE_PROTOCOLS = {
    "dnp3": "DNP3 non viene interrogato: anche una lettura puo' alterare lo stato di un RTU",
    "iec104": "IEC 104 non viene interrogato: le PDU di comando condividono lo stesso canale",
    "enip-io": "EtherNet/IP implicito (2222) e' traffico di processo: solo osservazione",
    "profinet-rt": "PROFINET RT e' isocrono: nessun pacchetto generato",
    "profinet-dcp": "PROFINET DCP viene letto solo passivamente dal traffico del controllore",
    "ethercat": "EtherCAT e' deterministico a livello L2: solo osservazione",
    "melsec": "MELSEC non ha un comando di identificazione sicuro: solo osservazione",
    "omron-fins": "FINS non ha un comando di identificazione sicuro: solo osservazione",
}


def fingerprint_asset(asset: Asset, guard: SafetyGuard, deep: bool = False) -> Dict[str, Any]:
    """Esegue tutte le sonde read-only compatibili con le porte aperte."""
    if guard.engagement.mode == "passive":
        return {"attempted": 0, "successful": 0, "skipped": ["modalita' passiva"]}

    ports = {p.port for p in asset.ports if p.state == "open"}
    service_ports: Dict[str, int] = {}
    for obs in asset.ports:
        if obs.state == "open" and obs.service:
            service_ports.setdefault(obs.service.lower(), obs.port)
    if deep:
        ports |= {502, 102, 44818, 161, 4840, 80}

    def port_of(service: str, default: int) -> int:
        """Usa la porta osservata (anche non standard) per quel servizio."""
        return service_ports.get(service, default)

    def present(service: str, default: int) -> bool:
        return port_of(service, default) in ports

    results: Dict[str, Any] = {}
    attempted = 0
    successful = 0
    skipped: List[str] = []

    def run(protocol: str, fn, port: int, *args) -> None:
        nonlocal attempted, successful
        attempted += 1
        try:
            guard.check_cancelled()
            res = fn(asset.ip, guard, port, *args)
        except UnsafeOperationError as exc:
            results[protocol] = _result(protocol, False, error=str(exc))
            return
        except Exception as exc:  # una sonda non deve mai fermare l'assessment
            results[protocol] = _result(protocol, False, error=f"{type(exc).__name__}: {exc}")
            return
        results[protocol] = res
        if res.get("success"):
            successful += 1

    if present("modbus", 502):
        run("modbus", probe_modbus_identity, port_of("modbus", 502))
    if present("s7comm", 102):
        run("s7comm", probe_s7_identity, port_of("s7comm", 102))
    if present("enip", 44818):
        run("enip", probe_enip_identity, port_of("enip", 44818))
    if present("bacnet", 47808):
        run("bacnet", probe_bacnet_identity, port_of("bacnet", 47808))
    if present("snmp", 161):
        run("snmp", probe_snmp_identity, port_of("snmp", 161))
    if present("opcua", 4840):
        run("opcua", probe_opcua_identity, port_of("opcua", 4840))
    http_ports = {p.port for p in asset.ports
                  if p.state == "open" and p.service in ("http", "http-alt", "https", "https-alt")}
    http_ports |= {p for p in (80, 443, 8080, 8443) if p in ports}
    for port in sorted(http_ports)[:1]:
        run(f"http-{port}", probe_http_identity, port)

    for proto in asset.protocols:
        if proto in NO_PROBE_PROTOCOLS:
            skipped.append(f"{proto}: {NO_PROBE_PROTOCOLS[proto]}")

    _apply_identity(asset, results)
    return {
        "attempted": attempted,
        "successful": successful,
        "skipped": skipped,
        "results": results,
    }


def _apply_identity(asset: Asset, results: Dict[str, Any]) -> None:
    for key, res in results.items():
        if not res.get("success"):
            continue
        identity = res.get("identity", {})
        proto = str(res.get("protocol", key))
        asset.identities[proto] = identity
        asset.add_protocol(proto.split("-")[0] if proto.startswith("http") else proto)
        asset.add_observation(res.get("evidence", ""))
        asset.confidence = "high"

        vendor = identity.get("vendor_name") or identity.get("vendor")
        if vendor and not asset.vendor:
            asset.vendor = str(vendor)
        model = identity.get("model_name") or identity.get("product_name") or identity.get("mlfb")
        if model:
            asset.model = str(model)
        firmware = identity.get("firmware") or identity.get("revision")
        if firmware and not asset.firmware:
            asset.firmware = str(firmware)

        if proto == "modbus":
            asset.device_type = "plc" if asset.device_type in ("unknown", "io-device") else asset.device_type
            asset.is_ot = True
        elif proto == "s7comm":
            asset.device_type = "plc"
            asset.is_ot = True
        elif proto == "enip":
            dtype = str(identity.get("device_type", ""))
            asset.device_type = "hmi" if dtype == "hmi" else "plc"
            asset.is_ot = True
        elif proto == "bacnet":
            asset.device_type = "bacnet-controller"
            asset.is_ot = True
        elif proto == "opcua":
            asset.device_type = "opcua-server" if asset.device_type == "unknown" else asset.device_type
        elif proto == "snmp":
            asset.hostname = asset.hostname or str(identity.get("sys_name", ""))
            descr = str(identity.get("sys_descr", "")).lower()
            if "cisco" in descr or "switch" in descr:
                asset.device_type = "switch"
            elif "windows" in descr and asset.device_type == "unknown":
                asset.device_type = "server"
        elif proto.startswith("http"):
            product = str(identity.get("product", ""))
            if product and asset.device_type in ("unknown",):
                asset.device_type = "hmi" if any(
                    k in product.lower() for k in ("simatic", "wincc", "ignition", "wonderware",
                                                   "factorytalk", "webvisu", "magelis", "hmi")
                ) else asset.device_type
            title = str(identity.get("title", ""))
            if title and not asset.hostname:
                asset.hostname = title[:40]

    if asset.is_ot and asset.purdue_level == 0:
        asset.purdue_level = 1 if asset.device_type in ("plc", "rtu", "io-device") else 2
