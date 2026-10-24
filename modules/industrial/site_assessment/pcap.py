"""Lettore pcap/pcapng senza dipendenze esterne.

Un tecnico sul campo cattura con Wireshark (pcapng) o con tcpdump (pcap) e
carica il file nell'assessment: nessun driver, nessun privilegio, nessun
rischio per la rete dell'impianto.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_MAGIC = 0x0A0D0D0A


class PcapError(RuntimeError):
    pass


def _read_pcap(data: bytes) -> Iterator[Tuple[float, bytes]]:
    if len(data) < 24:
        raise PcapError("file pcap troncato")
    if data[0:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif data[0:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise PcapError("magic pcap non riconosciuto")

    magic = struct.unpack(endian + "I", data[0:4])[0]
    nano = magic == PCAP_MAGIC_NS
    offset = 24
    total = len(data)
    while offset + 16 <= total:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if incl_len > 262144 or offset + incl_len > total:
            break
        ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
        yield ts, data[offset:offset + incl_len]
        offset += incl_len


def _read_pcapng(data: bytes) -> Iterator[Tuple[float, bytes]]:
    offset = 0
    total = len(data)
    endian = "<"
    if_tsresol: List[int] = []
    linktypes: List[int] = []

    while offset + 12 <= total:
        block_type = struct.unpack(endian + "I", data[offset:offset + 4])[0]

        if block_type == PCAPNG_MAGIC:
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("pcapng: byte-order magic non valido")
            block_type = struct.unpack(endian + "I", data[offset:offset + 4])[0]

        block_len = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
        if block_len < 12 or offset + block_len > total:
            break
        body = data[offset + 8:offset + block_len - 4]

        if block_type == 0x00000001 and len(body) >= 8:          # Interface Description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            linktypes.append(linktype)
            resol = 6  # default: microsecondi
            i = 8
            while i + 4 <= len(body):
                code, length = struct.unpack(endian + "HH", body[i:i + 4])
                value = body[i + 4:i + 4 + length]
                if code == 0:
                    break
                if code == 9 and value:
                    resol = value[0] & 0x7F
                i += 4 + length + ((4 - length % 4) % 4)
            if_tsresol.append(resol)

        elif block_type == 0x00000006 and len(body) >= 20:       # Enhanced Packet
            iface_id, ts_high, ts_low, cap_len, _pkt_len = struct.unpack(endian + "IIIII", body[0:20])
            resol = if_tsresol[iface_id] if iface_id < len(if_tsresol) else 6
            raw_ts = (ts_high << 32) | ts_low
            divisor = 2 ** resol if resol < 64 else 1e9
            packet = body[20:20 + cap_len]
            yield raw_ts / divisor, packet

        elif block_type == 0x00000003 and len(body) >= 4:        # Simple Packet (legacy)
            pkt_len = struct.unpack(endian + "I", body[0:4])[0]
            yield 0.0, body[4:4 + pkt_len]

        offset += block_len


def iter_packets(path: str | Path, max_packets: Optional[int] = None) -> Iterator[Tuple[float, bytes]]:
    """Itera (timestamp, frame) da un file pcap o pcapng."""
    raw = Path(path).read_bytes()
    if len(raw) < 4:
        raise PcapError("file vuoto")
    if raw[0:4] == b"\x0a\x0d\x0d\x0a":
        iterator: Iterator[Tuple[float, bytes]] = _read_pcapng(raw)
    else:
        iterator = _read_pcap(raw)

    count = 0
    for ts, frame in iterator:
        if max_packets is not None and count >= max_packets:
            break
        count += 1
        yield ts, frame


def count_packets(path: str | Path) -> int:
    return sum(1 for _ in iter_packets(path))


def write_pcap(path: str | Path, packets, linktype: int = 1) -> str:
    """Scrive un pcap classico (little-endian).

    Serve per esportare evidenze e per i test end-to-end senza rete reale.
    ``packets`` e' un iterabile di ``(timestamp, frame)`` oppure di soli frame.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 262144, linktype))
        for item in packets:
            if isinstance(item, tuple):
                ts, frame = item
            else:
                ts, frame = 0.0, item
            sec = int(ts)
            usec = int(round((float(ts) - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    return str(target)
