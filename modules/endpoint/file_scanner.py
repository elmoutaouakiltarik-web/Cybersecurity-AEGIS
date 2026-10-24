#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — File Scanner
===================================
Defensive file analysis. Three engines:

  1. YARA rules — pattern match using the rules shipped at
     modules/intelligence/yara/rules/*.yar
  2. Hash check — SHA-256 against an in-memory blacklist seed and an
     optional malicious_hashes.txt file (one hex hash per line).
  3. Microsoft Defender — MpCmdRun.exe -Scan -ScanType 3 on the target
     path. Read-only (no quarantine), always returns the textual report.

All scans are LOCAL. Files are never uploaded to a remote service.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("aegis.endpoint.file_scanner")


@dataclass
class YaraMatch:
    rule: str
    namespace: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanResult:
    file_path: str
    file_size: int
    sha256: str
    md5: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    hash_match: Optional[Dict[str, Any]] = None
    defender_report: Optional[str] = None
    defender_threats: List[str] = field(default_factory=list)
    verdict: str = "clean"   # clean | suspicious | malicious | error
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Hash database ────────────────────────────────────────────────────────────
# These are real, publicly documented malware sample hashes used as seed.

KNOWN_MALICIOUS_SHA256: Dict[str, str] = {
    # WannaCry: dropper, well-documented in IR literature
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "WannaCry ransomware (dropper)",
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": "WannaCry payload",
    # NotPetya / Petya
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": "NotPetya / Nyetya wiper",
    # EICAR test (always flagged by AV — useful for self-test)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File (benign signature)",
    # Emotet
    "82de80ce6fb3934a8bee7b67aaab606ae6cd97a0a9e2287e314e6fda93cea0d6": "Emotet trojan",
}


class FileScanner:
    def __init__(self,
                 yara_rules_dir: Optional[str] = None,
                 additional_hashes_file: Optional[str] = None,
                 enable_defender: bool = True) -> None:
        self.yara_rules_dir = yara_rules_dir
        self.enable_defender = enable_defender and (sys.platform == "win32")
        self._yara_rules = None
        self._hash_db = dict(KNOWN_MALICIOUS_SHA256)
        self._lock = threading.RLock()
        if additional_hashes_file and os.path.isfile(additional_hashes_file):
            self._load_hash_file(additional_hashes_file)
        self._load_yara()

    def _load_hash_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    h = parts[0].lower()
                    desc = parts[1] if len(parts) > 1 else "user-provided IoC"
                    if len(h) == 64:
                        self._hash_db[h] = desc
            LOGGER.info("Loaded %d hash IoCs from %s", len(self._hash_db), path)
        except Exception as e:
            LOGGER.warning("Cannot load hash file %s: %s", path, e)

    def _load_yara(self) -> None:
        if not self.yara_rules_dir or not os.path.isdir(self.yara_rules_dir):
            LOGGER.warning("YARA rules dir not found: %s — YARA disabled", self.yara_rules_dir)
            return
        try:
            import yara  # type: ignore
        except ImportError:
            LOGGER.warning("yara-python not installed — pip install yara-python")
            return
        filepaths = {}
        for root, _, files in os.walk(self.yara_rules_dir):
            for fn in files:
                if fn.endswith((".yar", ".yara")):
                    full = os.path.join(root, fn)
                    namespace = os.path.relpath(full, self.yara_rules_dir).replace(os.sep, "/")
                    filepaths[namespace] = full
        if not filepaths:
            LOGGER.warning("No .yar files found in %s", self.yara_rules_dir)
            return
        try:
            self._yara_rules = yara.compile(filepaths=filepaths)
            LOGGER.info("Compiled %d YARA rule file(s)", len(filepaths))
        except Exception as e:
            LOGGER.error("YARA compile failed: %s", e)

    # ── Public API ──────────────────────────────────────────────────────────

    def scan_bytes(self, content: bytes, label: str = "<memory>",
                   run_defender: bool = False) -> ScanResult:
        """Scan an in-memory byte buffer (e.g. an HTTP upload).

        Avoids round-tripping through the filesystem, which is fragile on
        Windows when the same path was just written by another handle.
        """
        result = ScanResult(file_path=label, file_size=len(content), sha256="", md5="")
        try:
            result.sha256 = hashlib.sha256(content).hexdigest()
            result.md5    = hashlib.md5(content).hexdigest()

            if result.sha256 in self._hash_db:
                result.hash_match = {"sha256": result.sha256, "label": self._hash_db[result.sha256]}
                result.verdict = "malicious"
                result.summary = f"Hash match: {self._hash_db[result.sha256]}"

            if self._yara_rules is not None:
                try:
                    matches = self._yara_rules.match(data=content)
                    for m in matches:
                        result.yara_matches.append({
                            "rule": m.rule,
                            "namespace": getattr(m, "namespace", ""),
                            "tags": list(getattr(m, "tags", [])),
                            "meta": dict(getattr(m, "meta", {})),
                            "strings": [
                                {"identifier": s.identifier,
                                 "offsets": [inst.offset for inst in s.instances][:5],
                                 "matched_data": [inst.matched_data[:60].hex() for inst in s.instances][:3]}
                                for s in m.strings
                            ] if hasattr(m, "strings") else [],
                        })
                    if matches and result.verdict == "clean":
                        result.verdict = "suspicious"
                        result.summary = f"YARA matched {len(matches)} rule(s): " + ", ".join(m.rule for m in matches[:5])
                except Exception as e:
                    LOGGER.warning("YARA scan_bytes failed: %s", e)

            if run_defender and self.enable_defender:
                # Defender needs a real path, so we persist to a uniquely named
                # temp file and shell out. Failure here does not corrupt the
                # YARA/hash result above.
                import tempfile
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
                try:
                    tmp.write(content)
                    tmp.flush()
                finally:
                    tmp.close()
                try:
                    rep = self._defender_scan(tmp.name)
                    if rep:
                        result.defender_report = rep["report"]
                        result.defender_threats = rep["threats"]
                        if rep["threats"] and result.verdict == "clean":
                            result.verdict = "malicious"
                            result.summary = f"Defender threats: {', '.join(rep['threats'])}"
                finally:
                    try:
                        os.unlink(tmp.name)
                    except Exception:
                        pass

            if result.verdict == "clean":
                result.summary = "No malicious indicators detected."

        except Exception as e:
            LOGGER.exception("scan_bytes failed for %s", label)
            result.error = str(e)
            result.verdict = "error"
        return result

    def scan(self, path: str, run_defender: bool = False) -> ScanResult:
        """Scan a single file. Returns a structured ScanResult."""
        result = ScanResult(file_path=path, file_size=0, sha256="", md5="")
        try:
            p = Path(path)
            if not p.is_file():
                result.error = f"Not a regular file: {path}"
                result.verdict = "error"
                return result

            stat = p.stat()
            result.file_size = stat.st_size
            # 200 MB hard cap to avoid memory blowups on weird inputs
            if stat.st_size > 200 * 1024 * 1024:
                result.error = "File exceeds 200 MB limit"
                result.verdict = "error"
                return result

            with open(p, "rb") as fh:
                content = fh.read()
            result.sha256 = hashlib.sha256(content).hexdigest()
            result.md5    = hashlib.md5(content).hexdigest()

            # Hash IoC check
            if result.sha256 in self._hash_db:
                result.hash_match = {"sha256": result.sha256, "label": self._hash_db[result.sha256]}
                result.verdict = "malicious"
                result.summary = f"Hash match: {self._hash_db[result.sha256]}"

            # YARA
            if self._yara_rules is not None:
                try:
                    matches = self._yara_rules.match(data=content)
                    for m in matches:
                        result.yara_matches.append({
                            "rule": m.rule,
                            "namespace": getattr(m, "namespace", ""),
                            "tags": list(getattr(m, "tags", [])),
                            "meta": dict(getattr(m, "meta", {})),
                            "strings": [
                                {"identifier": s.identifier,
                                 "offsets": [inst.offset for inst in s.instances][:5],
                                 "matched_data": [inst.matched_data[:60].hex() for inst in s.instances][:3]}
                                for s in m.strings
                            ] if hasattr(m, "strings") else [],
                        })
                    if matches and result.verdict == "clean":
                        result.verdict = "suspicious"
                        result.summary = f"YARA matched {len(matches)} rule(s): " + ", ".join(m.rule for m in matches[:5])
                except Exception as e:
                    LOGGER.warning("YARA scan failed on %s: %s", path, e)

            # Defender on-demand (Windows only, optional)
            if run_defender and self.enable_defender:
                rep = self._defender_scan(path)
                if rep:
                    result.defender_report = rep["report"]
                    result.defender_threats = rep["threats"]
                    if rep["threats"] and result.verdict == "clean":
                        result.verdict = "malicious"
                        result.summary = f"Defender threats: {', '.join(rep['threats'])}"

            if result.verdict == "clean":
                result.summary = "No malicious indicators detected."

        except Exception as e:
            LOGGER.exception("Scan failed for %s", path)
            result.error = str(e)
            result.verdict = "error"
        return result

    def scan_directory(self, directory: str,
                       max_files: int = 5000,
                       extensions: Optional[List[str]] = None,
                       run_defender: bool = False) -> Dict[str, Any]:
        """Walk a directory, scanning every file with YARA + hash."""
        d = Path(directory)
        if not d.is_dir():
            return {"error": f"Not a directory: {directory}"}
        ext_set = set(e.lower().lstrip(".") for e in extensions) if extensions else None
        scanned: List[Dict[str, Any]] = []
        suspicious: List[Dict[str, Any]] = []
        files_seen = 0
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            files_seen += 1
            if files_seen > max_files:
                break
            if ext_set is not None:
                if p.suffix.lstrip(".").lower() not in ext_set:
                    continue
            res = self.scan(str(p), run_defender=run_defender)
            scanned.append(res.to_dict())
            if res.verdict in ("suspicious", "malicious"):
                suspicious.append(res.to_dict())
        return {
            "directory": directory,
            "files_scanned": len(scanned),
            "files_seen": files_seen,
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
            "limit_reached": files_seen >= max_files,
        }

    def _defender_scan(self, path: str) -> Optional[Dict[str, Any]]:
        """Run MpCmdRun.exe -Scan -ScanType 3 -File <path>.

        ScanType 3 = custom scan. Returns text report and a list of threat
        names parsed from the output.
        """
        mp = self._find_mpcmdrun()
        if not mp:
            return None
        try:
            proc = subprocess.run(
                [mp, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                capture_output=True, text=True, timeout=180, encoding="utf-8", errors="replace",
            )
            report = (proc.stdout or "") + (proc.stderr or "")
            threats: List[str] = []
            for line in report.splitlines():
                # Defender prints "Threat ... " when something is found
                low = line.strip().lower()
                if low.startswith("threat ") or "threats detected" in low or "found malware" in low:
                    threats.append(line.strip())
            return {"report": report[:8000], "threats": threats, "exit_code": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"report": "Defender scan timeout (180s)", "threats": [], "exit_code": -1}
        except Exception as e:
            LOGGER.warning("Defender invocation failed: %s", e)
            return None

    def _find_mpcmdrun(self) -> Optional[str]:
        if sys.platform != "win32":
            return None
        candidates = [
            os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform"),
        ]
        # MpCmdRun lives in a versioned folder under Platform — pick the newest
        platform_dir = os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform")
        try:
            if os.path.isdir(platform_dir):
                subs = sorted([s for s in os.listdir(platform_dir) if os.path.isdir(os.path.join(platform_dir, s))])
                if subs:
                    cand = os.path.join(platform_dir, subs[-1], "MpCmdRun.exe")
                    if os.path.isfile(cand):
                        return cand
        except Exception:
            pass
        # Fall back to Program Files location
        if os.path.isfile(candidates[0]):
            return candidates[0]
        return shutil.which("MpCmdRun.exe")
