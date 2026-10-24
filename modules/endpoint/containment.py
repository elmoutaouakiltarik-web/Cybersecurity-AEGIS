#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Containment Actions
==========================================
Reversible response actions, **dry-run by default**.

Available actions:
  block_ip_inbound    — netsh advfirewall rule blocking inbound from IP
  block_ip_outbound   — netsh advfirewall rule blocking outbound to IP
  unblock_ip          — remove the rule by display name
  kill_pid            — Stop-Process -Id <pid> -Force
  disable_account     — net user <name> /active:no
  enable_account      — net user <name> /active:yes
  quarantine_file     — move file to {AEGIS_QUARANTINE_DIR}/<sha256>.quarantined
  isolate_host        — block ALL outbound except orchestrator (BIG button)

Every action requires the request header `X-AEGIS-Confirm: yes` to actually
execute. Without the header, the response is `dry_run: true` and shows the
exact command that would be run.

Every executed action is logged to {AEGIS_QUARANTINE_DIR}/containment.log.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("aegis.endpoint.containment")

QUARANTINE_DIR = Path(os.getenv("AEGIS_QUARANTINE_DIR",
                                 str(Path.home() / "AppData" / "Local" / "AEGIS-Quarantine")))
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = QUARANTINE_DIR / "containment.log"


def _is_admin() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _append_log(entry: Dict[str, Any]) -> None:
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        LOGGER.warning("Could not write containment log: %s", e)


def _execute(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Execute and capture command output."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, encoding="utf-8", errors="replace")
        return {
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "").strip()[:4000],
            "stderr": (proc.stderr or "").strip()[:4000],
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


# ── Action implementations ───────────────────────────────────────────────────

def action_block_ip(ip: str, direction: str = "in", *,
                    confirm: bool, reason: str = "manual") -> Dict[str, Any]:
    direction = direction.lower()
    if direction not in ("in", "out"):
        return {"ok": False, "error": "direction must be 'in' or 'out'"}
    rule_name = f"AEGIS-Block-{direction}-{ip}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        f"dir={direction}",
        "action=block",
        f"remoteip={ip}",
        "protocol=any",
        "enable=yes",
    ]
    if not confirm:
        return {
            "ok": True, "dry_run": True, "would_execute": cmd,
            "rule_name": rule_name,
            "explanation": f"Aggiunge una regola firewall che blocca tutto il traffico {direction.upper()} verso/da {ip}. Per eseguirla davvero invia di nuovo con header X-AEGIS-Confirm: yes.",
        }
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore (avvia aegis-endpoint.ps1 -Admin)"}
    res = _execute(cmd)
    entry = {"action": "block_ip", "ip": ip, "direction": direction,
             "rule_name": rule_name, "reason": reason, **res}
    _append_log(entry)
    return {"ok": res["exit_code"] == 0, "dry_run": False, "rule_name": rule_name, **res}


def action_unblock_ip(ip: str, direction: str = "in",
                      *, confirm: bool) -> Dict[str, Any]:
    rule_name = f"AEGIS-Block-{direction}-{ip}"
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    if not confirm:
        return {"ok": True, "dry_run": True, "would_execute": cmd, "rule_name": rule_name}
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    res = _execute(cmd)
    _append_log({"action": "unblock_ip", "ip": ip, "direction": direction,
                 "rule_name": rule_name, **res})
    return {"ok": res["exit_code"] == 0, "dry_run": False, **res}


def action_kill_pid(pid: int, *, confirm: bool, reason: str = "manual") -> Dict[str, Any]:
    try:
        import psutil  # type: ignore
        try:
            p = psutil.Process(int(pid))
        except psutil.NoSuchProcess:
            return {"ok": False, "error": f"PID {pid} non esiste"}
        info = {"pid": p.pid, "name": p.name(), "exe": p.exe(),
                "cmdline": p.cmdline(), "user": p.username()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

    if not confirm:
        return {
            "ok": True, "dry_run": True,
            "would_kill": info,
            "explanation": f"Terminerà il processo {info['name']} (PID {pid}) e tutti i suoi figli. Invia di nuovo con header X-AEGIS-Confirm: yes.",
        }
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    try:
        # Kill children first to avoid orphans
        children = p.children(recursive=True)
        for c in children:
            try:
                c.kill()
            except Exception:
                pass
        p.kill()
        p.wait(timeout=4)
        _append_log({"action": "kill_pid", "pid": pid, "info": info, "reason": reason,
                     "children_killed": [c.pid for c in children]})
        return {"ok": True, "dry_run": False, "killed": info,
                "children_killed": [c.pid for c in children]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def action_quarantine_file(path: str, *, confirm: bool,
                            reason: str = "manual") -> Dict[str, Any]:
    src = Path(path)
    if not src.is_file():
        return {"ok": False, "error": f"file non trovato: {path}"}
    size = src.stat().st_size
    if size > 1024 * 1024 * 1024:
        return {"ok": False, "error": "file > 1 GB, troppo grande per quarantena"}
    try:
        with open(src, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
    except Exception as e:
        return {"ok": False, "error": f"hash failed: {e}"}
    dest = QUARANTINE_DIR / f"{sha}.quarantined"
    if not confirm:
        return {
            "ok": True, "dry_run": True,
            "source": str(src), "dest": str(dest),
            "sha256": sha, "size": size,
            "explanation": f"Sposterà il file in {dest} (rinomina + lock). Invia di nuovo con X-AEGIS-Confirm: yes.",
        }
    try:
        shutil.move(str(src), str(dest))
        # Restrict ACL: only Administrators read/execute
        if sys.platform == "win32":
            subprocess.run(["icacls", str(dest), "/inheritance:r",
                            "/grant:r", "Administrators:R"], capture_output=True, timeout=10)
        _append_log({"action": "quarantine_file", "source": str(src),
                     "dest": str(dest), "sha256": sha, "size": size, "reason": reason})
        return {"ok": True, "dry_run": False, "source": str(src),
                "dest": str(dest), "sha256": sha, "size": size}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def action_disable_account(name: str, *, confirm: bool,
                            reason: str = "manual") -> Dict[str, Any]:
    if not name or "/" in name or ".." in name:
        return {"ok": False, "error": "nome account non valido"}
    cmd = ["net", "user", name, "/active:no"]
    if not confirm:
        return {"ok": True, "dry_run": True, "would_execute": cmd,
                "explanation": f"Disabiliterà l'account locale '{name}'. Invia con X-AEGIS-Confirm: yes."}
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    res = _execute(cmd)
    _append_log({"action": "disable_account", "user": name, "reason": reason, **res})
    return {"ok": res["exit_code"] == 0, "dry_run": False, **res}


def action_enable_account(name: str, *, confirm: bool) -> Dict[str, Any]:
    if not name or "/" in name or ".." in name:
        return {"ok": False, "error": "nome account non valido"}
    cmd = ["net", "user", name, "/active:yes"]
    if not confirm:
        return {"ok": True, "dry_run": True, "would_execute": cmd}
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    res = _execute(cmd)
    _append_log({"action": "enable_account", "user": name, **res})
    return {"ok": res["exit_code"] == 0, "dry_run": False, **res}


def action_isolate_host(*, confirm: bool, allow_ip: str = "",
                         reason: str = "manual incident response") -> Dict[str, Any]:
    """Block ALL outbound + inbound except for the loopback and (optionally)
    one allow_ip (the orchestrator/IR server). This is the 'big red button'."""
    rule_name_out = "AEGIS-Isolate-Out"
    rule_name_in = "AEGIS-Isolate-In"
    cmds = [
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name_out}", "dir=out", "action=block",
         "remoteip=any", "protocol=any", "enable=yes"],
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name_in}", "dir=in", "action=block",
         "remoteip=any", "protocol=any", "enable=yes"],
    ]
    if allow_ip:
        cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=AEGIS-Isolate-Allow-{allow_ip}", "dir=out",
                     "action=allow", f"remoteip={allow_ip}",
                     "protocol=any", "enable=yes"])
    if not confirm:
        return {
            "ok": True, "dry_run": True, "would_execute": cmds,
            "warning": "ISOLAMENTO TOTALE: blocca tutta la rete del host. Solo lo stesso host può fare unisolate.",
            "explanation": "Per eseguire davvero, invia di nuovo con X-AEGIS-Confirm: yes. Per ripristinare usa /contain/unisolate.",
        }
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    out = []
    for c in cmds:
        out.append({"cmd": c, **_execute(c)})
    _append_log({"action": "isolate_host", "reason": reason,
                 "allow_ip": allow_ip, "results": out})
    return {"ok": all(r["exit_code"] == 0 for r in out), "dry_run": False, "results": out}


def action_unisolate_host(*, confirm: bool) -> Dict[str, Any]:
    rules = ["AEGIS-Isolate-Out", "AEGIS-Isolate-In"]
    cmds = [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r}"]
            for r in rules]
    if not confirm:
        return {"ok": True, "dry_run": True, "would_execute": cmds}
    if not _is_admin():
        return {"ok": False, "error": "richiede privilegi amministratore"}
    out = [{"cmd": c, **_execute(c)} for c in cmds]
    _append_log({"action": "unisolate_host", "results": out})
    return {"ok": True, "dry_run": False, "results": out}


def recent_log(limit: int = 50) -> List[Dict[str, Any]]:
    if not LOG_FILE.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for line in lines[-limit:]:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
    return rows
