"""Safety gate per assessment di reti industriali.

Principi (NIST SP 800-82r3, IEC 62443-3-3):
1. **Autorizzazione esplicita**: nessun pacchetto viene inviato senza un
   riferimento di autorizzazione scritto e una finestra temporale valida.
2. **Passivo prima di attivo**: la modalita' ``passive`` non invia nulla.
3. **Sola lettura sui protocolli di processo**: le funzioni di scrittura
   (write coil/register, download, operate, DCP Set, OPC UA Write, CIP Write)
   sono bloccate a livello di codice.
4. **Ritmo controllato**: rate limiter per host e globale, cosi' un PLC o un
   switch degli anni 2000 non viene sovraccaricato.
5. **Tracciabilita'**: ogni azione finisce in un audit log JSONL.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger("aegis.site.safety")

MODES = ("passive", "readonly", "active")
_MODE_RANK = {"passive": 0, "readonly": 1, "active": 2}

_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

# Intervalli speciali che non sono "internet" ma nemmeno LAN aziendali.
_SPECIAL = [
    ipaddress.IPv4Network("100.64.0.0/10"),   # CGNAT
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local
    ipaddress.IPv4Network("127.0.0.0/8"),
]


class UnsafeOperationError(RuntimeError):
    """Tentativo di eseguire un'operazione non read-only su un protocollo OT."""


class ScopeViolation(RuntimeError):
    """Target fuori dallo scope autorizzato."""


# ── Funzioni di protocollo considerate distruttive ────────────────────────────
# NB: i protocolli industriali non hanno autenticazione. Una singola richiesta
# di scrittura puo' muovere un attuatore: qui non vengono mai generate.
DANGEROUS_OPERATIONS: Dict[str, Dict[int, str]] = {
    "modbus": {
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x08: "Diagnostics (puo' riavviare la comunicazione)",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Server ID (legacy, alcuni device lo interpretano male)",
        0x15: "Write File Record",
        0x16: "Mask Write Register",
        0x17: "Read/Write Multiple Registers",
        0x18: "Read FIFO Queue (bloccante su alcuni PLC)",
        0x2B: "Encapsulated Interface (consentito solo 0x0E Read Device ID)",
    },
    "s7": {
        0x05: "Write Variable",
        0x1A: "Request Download",
        0x1B: "Download Block",
        0x1C: "Download Ended",
        0x1D: "Start Upload",
        0x1E: "Upload",
        0x1F: "End Upload",
        0x28: "PLC Control (RUN/STOP)",
        0x29: "PLC Stop",
    },
    "dnp3": {
        0x02: "Write",
        0x03: "Select",
        0x04: "Operate",
        0x05: "Direct Operate",
        0x06: "Direct Operate No Ack",
        0x0D: "Cold Restart",
        0x0E: "Warm Restart",
        0x12: "Stop Application",
    },
    "iec104": {
        45: "C_SC_NA_1 Single Command",
        46: "C_DC_NA_1 Double Command",
        47: "C_RC_NA_1 Regulating Step",
        48: "C_SE_NA_1 Setpoint normalized",
        49: "C_SE_NB_1 Setpoint scaled",
        50: "C_SE_NC_1 Setpoint float",
        100: "C_IC_NA_1 Interrogation",
        101: "C_CI_NA_1 Counter Interrogation",
        103: "C_CS_NA_1 Clock Synchronization",
        105: "C_RP_NA_1 Reset Process",
    },
    "enip": {
        0x4D: "CIP Write Tag",
        0x4E: "CIP Write Tag Fragmented",
        0x52: "CIP Read Modify Write Tag",
        0x53: "CIP Write",
        0x54: "CIP Start",
        0x55: "CIP Stop",
        0x56: "CIP Create",
        0x57: "CIP Delete",
    },
    "opcua": {
        0x2BF: "WriteRequest",
        0x2C0: "HistoryUpdateRequest",
        0x2C1: "CallRequest (metodi)",
        0x2C2: "AddNodesRequest",
        0x2C3: "DeleteNodesRequest",
    },
    "bacnet": {
        15: "WriteProperty",
        16: "WritePropertyMultiple",
        20: "ReinitializeDevice",
        21: "VTOpen",
        22: "VTClose",
        27: "DeviceCommunicationControl",
        28: "ConfirmedPrivateTransfer",
    },
    "profinet": {
        0x04: "DCP Set (modifica nome/IP del device)",
        0x05: "DCP Identify (consentito)",
        0x06: "DCP Hello",
    },
}

# Sotto-funzioni esplicitamente consentite anche se il codice e' in blacklist.
ALLOWED_EXCEPTIONS: Dict[str, set] = {
    "modbus": {0x2B},   # solo con MEI type 0x0E (Read Device Identification)
    "profinet": {0x05},
}


@dataclass
class Engagement:
    """Contratto di assessment: chi, dove, come, fino a quando."""

    client: str = ""
    site: str = ""
    operator: str = ""
    authorization_ref: str = ""
    mode: str = "readonly"
    allowed_cidrs: List[str] = field(default_factory=list)
    excluded_ips: List[str] = field(default_factory=list)
    zones: List[Dict[str, Any]] = field(default_factory=list)
    max_hosts: int = 512
    max_pps: float = 200.0
    per_host_interval_s: float = 0.02
    allow_public: bool = False
    expires_at: str = ""
    maintenance_window: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── costruttori ─────────────────────────────────────────────────────────
    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Engagement":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (raw or {}).items() if k in known})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # ── validazione ─────────────────────────────────────────────────────────
    def validate(self) -> List[str]:
        problems: List[str] = []
        if self.mode not in MODES:
            problems.append(f"modalita' non valida: {self.mode!r} (attese: {', '.join(MODES)})")
        if not self.authorization_ref.strip():
            problems.append(
                "authorization_ref mancante: serve un riferimento scritto "
                "(es. ordine di lavoro, contratto, email del responsabile di stabilimento)"
            )
        if not self.site.strip():
            problems.append("site mancante")
        if not self.allowed_cidrs:
            problems.append("allowed_cidrs vuoto: dichiarare almeno una rete autorizzata")
        for cidr in self.allowed_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                problems.append(f"CIDR non valido: {cidr}")
        for ip in self.excluded_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                # Sono ammessi anche CIDR nelle esclusioni.
                try:
                    ipaddress.ip_network(ip, strict=False)
                except ValueError:
                    problems.append(f"esclusione non valida: {ip}")
        if self.max_hosts <= 0:
            problems.append("max_hosts deve essere > 0")
        if self.expires_at:
            try:
                expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry < datetime.now(timezone.utc):
                    problems.append("finestra di autorizzazione scaduta (expires_at nel passato)")
            except ValueError:
                problems.append("expires_at non in formato ISO-8601")
        return problems

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry < datetime.now(timezone.utc)

    # ── scope ───────────────────────────────────────────────────────────────
    def _networks(self) -> List[ipaddress._BaseNetwork]:
        nets = []
        for cidr in self.allowed_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        return nets

    def check_ip(self, ip: str) -> Tuple[bool, str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"indirizzo non valido: {ip}"

        for excluded in self.excluded_ips:
            try:
                if addr in ipaddress.ip_network(excluded, strict=False):
                    return False, f"{ip} e' escluso dallo scope"
            except ValueError:
                continue

        nets = self._networks()
        if not nets:
            return False, "nessuna rete autorizzata dichiarata"
        if not any(addr in net for net in nets):
            return False, f"{ip} non appartiene a nessuna rete autorizzata"

        is_private = any(addr in net for net in _RFC1918) or any(addr in net for net in _SPECIAL)
        if not is_private and not self.allow_public:
            return False, (
                f"{ip} e' un indirizzo pubblico: serve allow_public=true "
                "(di norma un assessment industriale resta su reti private)"
            )
        return True, ""

    def check_target(self, target: str) -> Tuple[bool, str]:
        """Accetta singolo IP o CIDR e verifica dimensione + appartenenza."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.version != 4:
                return False, "sono supportate solo reti IPv4"
            if net.num_addresses - 2 > self.max_hosts:
                return False, (
                    f"target troppo grande: {net.num_addresses - 2} host "
                    f"(max_hosts={self.max_hosts})"
                )
            # Le esclusioni valgono anche quando il target e' un CIDR.
            for excluded in self.excluded_ips:
                try:
                    excluded_net = ipaddress.ip_network(excluded, strict=False)
                except ValueError:
                    continue
                if net.num_addresses == 1:
                    if net.network_address in excluded_net:
                        return False, f"{target} e' escluso dallo scope"
                elif net.overlaps(excluded_net):
                    return False, f"{target} contiene un indirizzo escluso ({excluded})"

            nets = self._networks()
            if not nets:
                return False, "nessuna rete autorizzata dichiarata"
            if not any(net.subnet_of(auth) for auth in nets if net.version == auth.version):
                return False, f"{target} non e' contenuto nelle reti autorizzate"
            # Un CIDR interamente pubblico richiede allow_public.
            if not self.allow_public and not any(net.subnet_of(p) for p in _RFC1918):
                return False, f"{target} non e' una rete privata: serve allow_public=true"
            return True, ""
        except ValueError:
            return self.check_ip(target)

    def zone_for(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for zone in self.zones:
            for cidr in zone.get("cidrs", []):
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return zone
                except ValueError:
                    continue
        return None


class RateLimiter:
    """Token bucket semplice + intervallo minimo per host."""

    def __init__(self, max_pps: float = 200.0, per_host_interval_s: float = 0.02) -> None:
        self.max_pps = max(1.0, float(max_pps))
        self.per_host_interval_s = max(0.0, float(per_host_interval_s))
        self._lock = threading.Lock()
        self._tokens = self.max_pps
        self._last = time.monotonic()
        self._host_last: Dict[str, float] = {}

    def acquire(self, host: str = "", cancel_event: Optional[threading.Event] = None) -> bool:
        # Intervallo per host (protegge i device fragili).
        if host and self.per_host_interval_s:
            with self._lock:
                now = time.monotonic()
                last = self._host_last.get(host, 0.0)
                wait = self.per_host_interval_s - (now - last)
            if wait > 0:
                if cancel_event is not None and cancel_event.wait(wait):
                    return False
                elif cancel_event is None:
                    time.sleep(wait)
            with self._lock:
                self._host_last[host] = time.monotonic()

        # Token bucket globale.
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.max_pps, self._tokens + elapsed * self.max_pps)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                deficit = (1.0 - self._tokens) / self.max_pps
            if cancel_event is not None:
                if cancel_event.wait(deficit):
                    return False
            else:
                time.sleep(deficit)


class AuditLog:
    """Audit log append-only (JSONL) delle azioni eseguite sul campo."""

    def __init__(self, path: Optional[str] = None) -> None:
        default = Path(__file__).resolve().parents[3] / "data" / "site_assessment" / "audit.jsonl"
        self.path = Path(path) if path else Path(os.getenv("AEGIS_ASSESS_AUDIT") or default)
        self._lock = threading.Lock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.path = Path("aegis_assessment_audit.jsonl")

    def log(self, action: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:  # audit non deve mai bloccare l'assessment
                LOGGER.debug("audit log non scrivibile: %s", exc)
        LOGGER.debug("audit %s", line)


class SafetyGuard:
    """Punto unico di controllo per ogni azione inviata in rete."""

    def __init__(self, engagement: Engagement, audit: Optional[AuditLog] = None,
                 cancel_event: Optional[threading.Event] = None) -> None:
        self.engagement = engagement
        self.audit = audit or AuditLog()
        self.cancel_event = cancel_event or threading.Event()
        self.limiter = RateLimiter(engagement.max_pps, engagement.per_host_interval_s)
        self.blocked_attempts: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ── autorizzazione ──────────────────────────────────────────────────────
    def require_valid_engagement(self) -> None:
        problems = self.engagement.validate()
        if problems:
            raise ScopeViolation("; ".join(problems))
        if self.engagement.is_expired():
            raise ScopeViolation("finestra di autorizzazione scaduta")

    def is_passive(self) -> bool:
        return self.engagement.mode == "passive"

    def require_network_actions(self) -> None:
        """Alza se la modalita' non consente di inviare pacchetti."""
        if self.is_passive():
            raise ScopeViolation("modalita' passiva: nessun pacchetto puo' essere inviato")

    def require_mode(self, needed: str) -> None:
        if _MODE_RANK.get(self.engagement.mode, -1) < _MODE_RANK.get(needed, 99):
            raise ScopeViolation(
                f"modalita' {self.engagement.mode!r} insufficiente per {needed!r}"
            )

    def authorize_ip(self, ip: str, purpose: str = "") -> None:
        ok, reason = self.engagement.check_ip(ip)
        if not ok:
            self.audit.log("scope_denied", ip=ip, purpose=purpose, reason=reason)
            raise ScopeViolation(reason)

    def authorize_target(self, target: str, purpose: str = "") -> None:
        ok, reason = self.engagement.check_target(target)
        if not ok:
            self.audit.log("scope_denied", target=target, purpose=purpose, reason=reason)
            raise ScopeViolation(reason)

    def pace(self, host: str = "") -> None:
        if not self.limiter.acquire(host, self.cancel_event):
            raise ScopeViolation("operazione annullata durante il rate limiting")

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise ScopeViolation("assessment annullato")

    # ── protocolli industriali ──────────────────────────────────────────────
    def assert_readonly(self, protocol: str, operation: Any) -> None:
        """Blocca funzioni di scrittura. Va chiamata PRIMA di ogni invio."""
        proto = str(protocol).lower()
        table = DANGEROUS_OPERATIONS.get(proto, {})
        allowed = ALLOWED_EXCEPTIONS.get(proto, set())
        try:
            op = int(operation)
        except (TypeError, ValueError):
            return
        if op in allowed:
            return
        if op in table:
            reason = f"{proto} op 0x{op:02X} ({table[op]}) non e' read-only"
            with self._lock:
                self.blocked_attempts.append({"protocol": proto, "operation": op, "reason": reason})
            self.audit.log("blocked_write", protocol=proto, operation=op, reason=reason)
            raise UnsafeOperationError(reason)

    def is_write(self, protocol: str, operation: int) -> bool:
        proto = str(protocol).lower()
        if int(operation) in ALLOWED_EXCEPTIONS.get(proto, set()):
            return False
        return int(operation) in DANGEROUS_OPERATIONS.get(proto, {})

    def record(self, action: str, **fields: Any) -> None:
        self.audit.log(action, engagement=self.engagement.authorization_ref, mode=self.engagement.mode, **fields)


# ── preflight ─────────────────────────────────────────────────────────────────
def preflight() -> Dict[str, Any]:
    """Verifica cosa e' realmente possibile fare su questa macchina.

    Il report usa questo dizionario per dichiarare i limiti: meglio dire
    "non testato" che produrre un falso senso di sicurezza.
    """
    caps: Dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "is_admin": False,
        "scapy": False,
        "nmap": shutil.which("nmap") or "",
        "pcap_capture": False,
        "interfaces": [],
        "notes": [],
    }
    try:
        import scapy  # noqa: F401
        caps["scapy"] = True
    except Exception:
        caps["notes"].append("scapy non installato: cattura live e parsing L2 avanzato limitati")

    try:
        if platform.system() == "Windows":
            import ctypes
            caps["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            caps["is_admin"] = os.geteuid() == 0
    except Exception:
        caps["is_admin"] = False

    try:
        caps["interfaces"] = list_interfaces()
    except Exception as exc:
        caps["notes"].append(f"enumerazione interfacce fallita: {exc}")

    caps["pcap_capture"] = bool(caps["scapy"] and (caps["is_admin"] or platform.system() == "Windows"))
    if not caps["pcap_capture"]:
        caps["notes"].append(
            "cattura live non disponibile (serve scapy + privilegi): usare un pcap esportato da Wireshark"
        )
    return caps


def list_interfaces() -> List[Dict[str, str]]:
    """Elenca le interfacce con indirizzo IPv4, senza dipendere da scapy."""
    found: Dict[str, Dict[str, str]] = {}

    if platform.system() == "Windows":
        try:
            import subprocess
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | "
                 "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15,
            )
            if out.returncode == 0 and out.stdout.strip():
                data = json.loads(out.stdout)
                if isinstance(data, dict):
                    data = [data]
                for row in data:
                    name = str(row.get("InterfaceAlias", ""))
                    ip = str(row.get("IPAddress", ""))
                    if name and ip and not ip.startswith("127."):
                        found[name] = {"name": name, "ip": ip, "cidr": f"{ip}/24"}
        except Exception as exc:
            LOGGER.debug("enumerazione interfacce Windows fallita: %s", exc)

    if not found:
        try:
            for name in os.listdir("/sys/class/net"):
                if name == "lo":
                    continue
                try:
                    import fcntl
                    import struct
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        packed = struct.pack("256s", name[:15].encode())
                        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])
                    if ip and not ip.startswith("127."):
                        found[name] = {"name": name, "ip": ip, "cidr": f"{ip}/24"}
                except Exception:
                    continue
        except OSError:
            pass

    if not found:
        # Fallback universale: route verso Internet (non invia traffico reale).
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))
                ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                found["default"] = {"name": "default", "ip": ip, "cidr": f"{ip}/24"}
        except Exception:
            pass

    return list(found.values())


def guess_zone_of(ip: str, zones: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for zone in zones:
        for cidr in zone.get("cidrs", []):
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return zone
            except ValueError:
                continue
    return None
