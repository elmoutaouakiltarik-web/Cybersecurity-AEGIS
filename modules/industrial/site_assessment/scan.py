"""Scansione porte TCP e identificazione servizi, con ritmo controllato.

Regole di ingaggio applicate qui:

* TCP connect (nessun pacchetto SYN "spoofato", nessun half-open): il device
  vede una connessione normale e la chiude subito;
* un solo tentativo per porta, timeout breve, concorrenza bassa;
* nessun banner grabbing sulle porte OT: per quelle ci pensa ``fingerprint``
  con PDU di sola lettura previste dal protocollo;
* rate limiter per host e globale (``SafetyGuard.pace``).
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional

from .dissect import IT_PORTS as IT_PORT_NAMES
from .dissect import OT_TCP_PORTS
from .models import PortObservation
from .safety import SafetyGuard

LOGGER = logging.getLogger("aegis.site.scan")

# Profilo "ot": solo protocolli industriali e servizi di management tipici.
OT_PORTS: List[int] = sorted(set(OT_TCP_PORTS) | {161, 80, 443, 22, 23, 21, 445, 3389, 8080, 8443})

# Profilo "it": servizi enterprise che in una zona OT sono un rischio.
IT_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433,
                       1521, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017]

# Top 200 porte TCP piu' comuni + tutte le OT: buon compromesso in campo.
COMMON_PORTS: List[int] = sorted(set(OT_PORTS) | set(IT_PORTS) | {
    1, 7, 9, 13, 17, 19, 49, 67, 68, 69, 70, 79, 81, 82, 83, 84, 85, 88, 89, 90,
    99, 100, 106, 109, 111, 113, 119, 123, 137, 138, 179, 199, 389, 427, 444, 465,
    500, 512, 513, 514, 515, 526, 540, 548, 554, 563, 587, 631, 636, 646, 873, 990,
    992, 994, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1241, 1311, 1352, 1434,
    1701, 1720, 1723, 1755, 1812, 1813, 1900, 2000, 2049, 2121, 2222, 2323, 2483,
    2484, 2745, 2967, 3052, 3074, 3128, 3260, 3306, 3389, 3689, 3784, 3785, 4333,
    4444, 4500, 4664, 4672, 4899, 5000, 5009, 5051, 5060, 5190, 5222, 5269, 5357,
    5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6129, 6257, 6346, 6347, 6500,
    6566, 6699, 6881, 6998, 7000, 7071, 7100, 7937, 8000, 8008, 8009, 8080, 8081,
    8086, 8087, 8090, 8091, 8098, 8100, 8180, 8192, 8193, 8200, 8222, 8300, 8443,
    8500, 8888, 9000, 9001, 9020, 9090, 9100, 9200, 9443, 9535, 9999, 10000,
    10243, 11211, 27017, 32768, 49152, 49153, 49154,
})

PORT_PROFILES: Dict[str, List[int]] = {
    "ot": OT_PORTS,
    "it": IT_PORTS,
    "common": COMMON_PORTS,
    "full": list(range(1, 1001)) + OT_PORTS,
}

# Classificazione di sicurezza del canale.
CONTROL_PORT_CLASS = {
    502: "control", 102: "control", 2404: "control", 20000: "control",
    44818: "control", 2222: "control", 47808: "control", 4840: "control",
    2455: "control", 9600: "control", 5006: "control", 5007: "control",
    1911: "control", 789: "control", 5094: "control",
}
MANAGEMENT_PORTS = {21, 22, 23, 135, 139, 445, 3389, 5900, 5985, 8080, 8443, 80, 443}

# Porte su cui e' sicuro leggere un banner applicativo.
BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 8080, 8081, 8443, 9000}

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8081, 9000}


def service_name(port: int) -> str:
    if port in OT_TCP_PORTS:
        return OT_TCP_PORTS[port]
    if port in IT_PORT_NAMES:
        return IT_PORT_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def safety_class(port: int) -> str:
    if port in CONTROL_PORT_CLASS:
        return CONTROL_PORT_CLASS[port]
    if port in MANAGEMENT_PORTS:
        return "management"
    return "unknown"


def ports_for_profile(profile: str, extra: Optional[Iterable[int]] = None) -> List[int]:
    ports = list(PORT_PROFILES.get(profile, COMMON_PORTS))
    if extra:
        ports.extend(int(p) for p in extra if str(p).isdigit())
    return sorted(set(p for p in ports if 0 < p < 65536))


def tcp_connect(ip: str, port: int, timeout: float = 0.8) -> str:
    """Ritorna 'open', 'closed' o 'filtered'."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return "open"
            # ECONNREFUSED = host raggiungibile, porta chiusa.
            if result in (111, 61, 10061):
                return "closed"
            return "filtered"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"


def grab_banner(ip: str, port: int, timeout: float = 1.2) -> str:
    """Legge un banner solo su porte non-OT e solo se il servizio lo prevede."""
    if port not in BANNER_PORTS:
        return ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in HTTP_PORTS:
                host = ip
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AEGIS-Assess/1.0\r\n\r\n".encode()
                )
            data = b""
            deadline = time.time() + timeout
            while time.time() < deadline and len(data) < 512:
                try:
                    chunk = sock.recv(512)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode("latin-1", errors="replace").strip()
    except OSError:
        return ""


def scan_host(ip: str, ports: List[int], guard: SafetyGuard, timeout: float = 0.8,
              workers: int = 16, banners: bool = True,
              progress_cb: Optional[Callable[[int], None]] = None) -> List[PortObservation]:
    """Scansiona un host rispettando lo scope e il rate limit."""
    guard.authorize_ip(ip, purpose="port-scan")
    guard.require_network_actions()

    results: List[PortObservation] = []
    total = max(1, len(ports))
    done = [0]
    lock = threading.Lock()

    def probe(port: int) -> None:
        if guard.cancel_event.is_set():
            return
        guard.pace(ip)
        state = tcp_connect(ip, port, timeout=timeout)
        with lock:
            done[0] += 1
            if progress_cb:
                progress_cb(int(done[0] * 100 / total))
        if state != "open":
            return
        banner = grab_banner(ip, port, timeout=timeout + 0.4) if banners else ""
        results.append(PortObservation(
            port=port, proto="tcp", service=service_name(port), state="open",
            banner=banner, safety_class=safety_class(port),
            evidence="tcp-connect",
        ))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
        list(pool.map(probe, ports))

    return sorted(results, key=lambda p: p.port)


def host_alive(ip: str, guard: SafetyGuard, timeout: float = 0.6) -> bool:
    """Verifica presenza host su porte tipiche, senza ICMP flood."""
    guard.authorize_ip(ip, purpose="host-discovery")
    for port in (502, 102, 80, 443, 445, 22, 161):
        guard.pace(ip)
        if tcp_connect(ip, port, timeout=timeout) == "open":
            return True
    return False


def expand_targets(target: str, guard: SafetyGuard, limit: int = 512) -> List[str]:
    """Espande un CIDR in host, sempre dentro lo scope autorizzato."""
    guard.authorize_target(target, purpose="expand")
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]
    hosts: List[str] = []
    for host in net.hosts():
        ip = str(host)
        ok, _ = guard.engagement.check_ip(ip)
        if ok:
            hosts.append(ip)
        if len(hosts) >= limit:
            LOGGER.warning("Limite di %d host raggiunto per %s", limit, target)
            break
    return hosts
