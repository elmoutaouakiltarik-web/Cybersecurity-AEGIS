#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Secrets Sweeper
======================================
Scans a directory tree for hardcoded credentials, API keys, private keys,
and connection strings. Inspired by Gitleaks/TruffleHog but stdlib-only.

Returns structured findings with file path, line number, masked match, and
remediation hint. Files are NEVER uploaded — analysis is purely local.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

LOGGER = logging.getLogger("aegis.endpoint.secrets")

# Each rule = (id, severity, description, compiled regex). The regexes are
# anchored to keywords or known formats to keep false positives manageable.
RULES: List[Tuple[str, str, str, Pattern[str]]] = [
    ("aws_access_key", "critical", "AWS Access Key ID",
     re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("aws_secret_key", "critical", "AWS Secret Access Key (40-char)",
     re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("gcp_api_key", "critical", "Google API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("github_pat", "critical", "GitHub Personal Access Token",
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("github_oauth", "critical", "GitHub OAuth token",
     re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("slack_token", "critical", "Slack token",
     re.compile(r"xox[abprs]-[0-9A-Za-z-]{10,48}")),
    ("slack_webhook", "high", "Slack webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("discord_webhook", "high", "Discord webhook",
     re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")),
    ("openai_key", "critical", "OpenAI API key",
     re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic_key", "critical", "Anthropic API key",
     re.compile(r"sk-ant-[A-Za-z0-9_\-]{30,}")),
    ("stripe_secret", "critical", "Stripe secret key",
     re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}")),
    ("stripe_publishable", "low", "Stripe publishable key (public, no risk)",
     re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}")),
    ("twilio_sid", "high", "Twilio SID",
     re.compile(r"AC[a-fA-F0-9]{32}")),
    ("sendgrid_key", "critical", "SendGrid API key",
     re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    ("mailgun_key", "high", "Mailgun API key",
     re.compile(r"key-[a-z0-9]{32}")),
    ("rsa_private_key", "critical", "PEM private key (RSA/EC/DSA/OPENSSH)",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("pgp_private", "critical", "PGP private key block",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    ("jwt", "medium", "JWT (verify if it carries secrets in payload)",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic_password", "medium", "Likely hardcoded password",
     re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
    ("generic_secret", "medium", "Likely hardcoded secret",
     re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]")),
    ("postgres_url", "high", "PostgreSQL URL with embedded password",
     re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+")),
    ("mysql_url", "high", "MySQL URL with embedded password",
     re.compile(r"mysql://[^:\s]+:[^@\s]+@[^/\s]+")),
    ("mongodb_url", "high", "MongoDB URI with embedded password",
     re.compile(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+")),
    ("redis_url", "medium", "Redis URI with embedded password",
     re.compile(r"redis://[^:\s]*:[^@\s]+@[^/\s]+")),
    ("azure_sas", "high", "Azure SAS token",
     re.compile(r"sig=[A-Za-z0-9%]{32,}&se=\d{4}")),
    ("docker_auth", "medium", "Docker config auth blob",
     re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"')),
    ("npm_token", "high", "npm authentication token",
     re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("heroku_key", "high", "Heroku API key",
     re.compile(r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("private_ipv4_creds", "low", "IPv4 with credentials in URL",
     re.compile(r"https?://[^/\s]+:[^@\s]+@(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)\d+\.\d+")),
]

# Files we never want to inspect to avoid huge wasted work
SKIP_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".mp3", ".mp4", ".webm", ".mov", ".avi", ".mkv", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".class",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".idea", ".vscode", ".gradle", ".pytest_cache",
             "target", "vendor", ".terraform"}

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per file


@dataclass
class Secret:
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    match: str          # masked for sensitive ones
    raw_length: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _mask(s: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    return s[:keep_start] + "*" * (len(s) - keep_start - keep_end) + s[-keep_end:]


def _looks_binary(chunk: bytes) -> bool:
    if not chunk:
        return False
    # Heuristic: high ratio of NULL bytes or non-printable
    nulls = chunk.count(b"\x00")
    if nulls > 0:
        return True
    nonprint = sum(1 for b in chunk[:1024] if b < 9 or (13 < b < 32))
    return nonprint > 32


def scan_file(path: str) -> List[Secret]:
    """Scan a single file. Returns list of Secret findings."""
    findings: List[Secret] = []
    try:
        p = Path(path)
        if not p.is_file():
            return findings
        if p.suffix.lower() in SKIP_EXTENSIONS:
            return findings
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            return findings
        with open(p, "rb") as fh:
            data = fh.read()
        if _looks_binary(data):
            return findings
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return findings
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Skip very long lines (likely minified)
            if len(line) > 2000:
                continue
            for rule_id, severity, desc, pat in RULES:
                m = pat.search(line)
                if not m:
                    continue
                raw = m.group(0)
                masked = _mask(raw)
                findings.append(Secret(
                    rule_id=rule_id, severity=severity, description=desc,
                    file=str(p), line=lineno, match=masked, raw_length=len(raw),
                ))
    except Exception as e:
        LOGGER.debug("secrets scan_file error on %s: %s", path, e)
    return findings


def scan_directory(directory: str,
                   max_files: int = 20000,
                   include_dotfiles: bool = True) -> Dict[str, Any]:
    """Recursively scan a directory tree for secrets.

    Honours SKIP_DIRS and SKIP_EXTENSIONS. Returns aggregated results.
    """
    d = Path(directory)
    if not d.is_dir():
        return {"error": f"Not a directory: {directory}"}
    findings: List[Dict[str, Any]] = []
    files_seen = 0
    files_scanned = 0
    started = datetime.now(timezone.utc).isoformat()

    for root, dirs, files in os.walk(d):
        # Prune skip dirs
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and (include_dotfiles or not x.startswith("."))]
        for fn in files:
            files_seen += 1
            if files_seen > max_files:
                break
            full = os.path.join(root, fn)
            res = scan_file(full)
            if res:
                files_scanned += 1
                for s in res:
                    findings.append(s.to_dict())
        if files_seen > max_files:
            break

    # Summarize
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_rule: Dict[str, int] = {}
    by_file: Dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
        by_file[f["file"]] = by_file.get(f["file"], 0) + 1

    return {
        "directory": str(d),
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "files_seen": files_seen,
        "files_with_findings": files_scanned,
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_rule": by_rule,
        "top_files": sorted(by_file.items(), key=lambda kv: -kv[1])[:20],
        "findings": findings[:1000],   # cap response payload
    }
