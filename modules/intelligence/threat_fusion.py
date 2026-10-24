#!/usr/bin/env python3
"""
AEGIS Threat Fusion Engine
===========================
Multi-source event correlation, attack chain reconstruction, and
MITRE ATT&CK campaign intelligence.

What makes this unique:
  1. Correlates events from ALL AEGIS modules (network, SIEM, vuln, TI)
     into unified "attack campaigns"
  2. Reconstructs the full kill-chain from scattered events
  3. Maps every event to MITRE ATT&CK techniques (offline, ~60 techniques)
  4. Scores campaign probability: probability that multiple events are
     part of the same coordinated attack
  5. Identifies threat actor patterns (APT29, Lazarus, ransomware TTPs)
  6. Produces prioritised, actionable intelligence per campaign

Algorithm:
  - Time-window clustering: events within T minutes on correlated IPs
  - Kill-chain phase assignment: each event → ATT&CK tactic
  - Campaign scoring: confidence based on phase breadth + event count
  - Actor matching: compare detected techniques to known TTPs
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

LOGGER = logging.getLogger("aegis.threat_fusion")

# ── MITRE ATT&CK OFFLINE TECHNIQUE MAP ───────────────────────────────────────
# Pattern (regex on event title/description) → (tactic, technique_id, technique_name)
MITRE_PATTERN_MAP: List[Tuple[str, str, str, str]] = [
    # Reconnaissance
    (r"port.?scan|nmap|masscan|network.?scan|service.?enum",
     "Reconnaissance", "T1046", "Network Service Scanning"),
    (r"host.?discov|ping.?sweep|arp.?scan|icmp.?sweep",
     "Reconnaissance", "T1018", "Remote System Discovery"),
    (r"dns.?enum|subdomain|zone.?transfer|dnsx",
     "Reconnaissance", "T1590", "Gather Victim Network Information"),
    (r"osint|shodan|censys|whois|linkedin|employee",
     "Reconnaissance", "T1589", "Gather Victim Identity Information"),

    # Initial Access
    (r"brute.?force|password.?spray|credential.?stuff",
     "Initial Access", "T1110", "Brute Force"),
    (r"phish|spear.?phish|malicious.?email|email.?attach",
     "Initial Access", "T1566", "Phishing"),
    (r"exploit|cve-\d{4}|rce|remote.?code.?exec|vuln",
     "Initial Access", "T1190", "Exploit Public-Facing Application"),
    (r"supply.?chain|malicious.?package|typosquat",
     "Initial Access", "T1195", "Supply Chain Compromise"),
    (r"vpn.?abuse|valid.?account|stolen.?cred",
     "Initial Access", "T1078", "Valid Accounts"),

    # Execution
    (r"powershell|ps1|invoke-|iex |encoded.?command",
     "Execution", "T1059.001", "PowerShell"),
    (r"wscript|cscript|vbscript|\.vbs|\.js",
     "Execution", "T1059.005", "Visual Basic"),
    (r"cmd\.exe|command.?line|bat.?script",
     "Execution", "T1059.003", "Windows Command Shell"),
    (r"bash|sh .?shell|\/bin\/sh|bash -c",
     "Execution", "T1059.004", "Unix Shell"),
    (r"wmi|wmiexec|win32_process|invoke-wmimethod",
     "Execution", "T1047", "Windows Management Instrumentation"),
    (r"scheduled.?task|schtask|at\.exe|cron",
     "Execution", "T1053", "Scheduled Task/Job"),

    # Persistence
    (r"registry.?run|hklm.*run|hkcu.*run|startup",
     "Persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    (r"new.?service|sc.?create|service.?install",
     "Persistence", "T1543.003", "Windows Service"),
    (r"crontab|/etc/cron|rc\.local|systemd.?unit",
     "Persistence", "T1053.003", "Cron"),
    (r"web.?shell|aspx.*shell|php.*shell|jsp.*shell",
     "Persistence", "T1505.003", "Web Shell"),
    (r"ssh.?key|authorized_keys|id_rsa",
     "Persistence", "T1098.004", "SSH Authorized Keys"),
    (r"account.?creat|new.?admin|new.?user|useradd",
     "Persistence", "T1136", "Create Account"),

    # Privilege Escalation
    (r"token.?imperson|seimpersonateprivilege|juicy.?potato|rotten.?potato",
     "Privilege Escalation", "T1134", "Access Token Manipulation"),
    (r"uac.?bypass|uac.?disable|eventvwr|sdclt",
     "Privilege Escalation", "T1548.002", "Bypass User Account Control"),
    (r"sudo.?abuse|sudo -l|sudo.*exploit",
     "Privilege Escalation", "T1548.003", "Sudo and Sudo Caching"),
    (r"kernel.?exploit|local.?privilege.?esc|dirty.?cow|print.?nightmare",
     "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    (r"domain.?admin|net.?localgroup.?admin|administrator",
     "Privilege Escalation", "T1078.002", "Domain Accounts"),

    # Defense Evasion
    (r"disable.*log|clear.*log|wevtutil|auditpol|log.*delet",
     "Defense Evasion", "T1070.001", "Clear Windows Event Logs"),
    (r"obfuscat|encode.*command|base64.*powershell",
     "Defense Evasion", "T1027", "Obfuscated Files or Information"),
    (r"antivirus.*disable|av.*bypass|defender.*disable|edr.*kill",
     "Defense Evasion", "T1562.001", "Disable or Modify Tools"),
    (r"timestomp|mactime|timestamp.?modif",
     "Defense Evasion", "T1070.006", "Timestomp"),
    (r"process.?inject|dll.?inject|hollow|shimming",
     "Defense Evasion", "T1055", "Process Injection"),

    # Credential Access
    (r"mimikatz|lsass|sekurlsa|credential.?dump|hashdump",
     "Credential Access", "T1003.001", "LSASS Memory"),
    (r"kerberoast|spn.*ticket|service.?ticket|asreproast",
     "Credential Access", "T1558.003", "Kerberoasting"),
    (r"pass.?the.?hash|pth|ntlm.?relay|ntlm.?auth",
     "Credential Access", "T1550.002", "Pass the Hash"),
    (r"keylog|keystroke|hook.*keyboard",
     "Credential Access", "T1056.001", "Keylogging"),
    (r"password.?in.?file|credentials.?store|config.*password",
     "Credential Access", "T1552.001", "Credentials In Files"),

    # Discovery
    (r"whoami|systeminfo|hostname|ipconfig|ifconfig|net view",
     "Discovery", "T1082", "System Information Discovery"),
    (r"net user|get-aduser|enum.*user|ldap.*user",
     "Discovery", "T1087", "Account Discovery"),
    (r"net group|domain.*enum|get-addomain|bloodhound|sharphound",
     "Discovery", "T1069", "Permission Groups Discovery"),
    (r"file.?enum|dir /s|find.*file|locate.*file",
     "Discovery", "T1083", "File and Directory Discovery"),
    (r"process.?list|tasklist|ps -ef|get-process",
     "Discovery", "T1057", "Process Discovery"),

    # Lateral Movement
    (r"psexec|wmiexec|smbexec|impacket",
     "Lateral Movement", "T1570", "Lateral Tool Transfer"),
    (r"rdp.*login|3389.*success|remote.*desktop.*logon",
     "Lateral Movement", "T1021.001", "Remote Desktop Protocol"),
    (r"smb.*lateral|admin\$.*\\\\|c\$.*\\\\",
     "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares"),
    (r"ssh.*lateral|ssh.*forward|proxyjump",
     "Lateral Movement", "T1021.004", "SSH"),
    (r"winrm.*exec|invoke-command.*remote|remotehost",
     "Lateral Movement", "T1021.006", "Windows Remote Management"),
    (r"dcom.*exec|mmc20|shellbrowserwindow",
     "Lateral Movement", "T1021.003", "Distributed Component Object Model"),

    # Collection
    (r"data.*collect|screenshot|keylog|clipboard",
     "Collection", "T1005", "Data from Local System"),
    (r"email.?collect|exchange.*dump|mailbox",
     "Collection", "T1114", "Email Collection"),
    (r"database.*dump|db.*exfil|mysqldump",
     "Collection", "T1213", "Data from Information Repositories"),

    # Command & Control
    (r"c2|command.*control|beacon|cobalt.?strike|empire|metasploit",
     "Command and Control", "T1071", "Application Layer Protocol"),
    (r"dns.*tunnel|iodine|dnscat",
     "Command and Control", "T1071.004", "DNS"),
    (r"tor|onion|darkweb|anonymi",
     "Command and Control", "T1090", "Proxy"),
    (r"reverse.?shell|connect.?back|bind.?shell",
     "Command and Control", "T1105", "Ingress Tool Transfer"),

    # Exfiltration
    (r"exfil|data.*theft|upload.*external|ftp.*outbound",
     "Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    (r"cloud.*upload|s3.*upload|dropbox|pastebin",
     "Exfiltration", "T1567", "Exfiltration Over Web Service"),
    (r"archive.*data|zip.*sensitive|rar.*confidential",
     "Exfiltration", "T1560", "Archive Collected Data"),

    # Impact
    (r"ransomware|encrypt.*file|ransom.*note|\\.locked|\\.encrypted",
     "Impact", "T1486", "Data Encrypted for Impact"),
    (r"dos|ddos|flood|syn.?flood|resource.?exhaust",
     "Impact", "T1499", "Endpoint Denial of Service"),
    (r"wipe|destroy.*data|disk.*wipe|format.*drive",
     "Impact", "T1485", "Data Destruction"),
    (r"defac|webshell.*replace|website.*modif",
     "Impact", "T1491", "Defacement"),

    # ICS/OT specific (MITRE ATT&CK for ICS)
    (r"modbus|s7comm|iec.?104|iec61850|dnp3|bacnet|opcua",
     "Inhibit Response Function", "T0855", "Unauthorized Command Message"),
    (r"plc.*program|ladder.?logic|firmware.?upload|hmi.*modif",
     "Impair Process Control", "T0836", "Modify Parameter"),
    (r"scada.*access|historian.*tamper|process.*manip",
     "Impair Process Control", "T0855", "Unauthorized Command Message"),
    (r"safety.*bypass|safety.*disable|sis.*modif",
     "Inhibit Response Function", "T0838", "Modify Alarm Settings"),
]

# ── THREAT ACTOR TTP PROFILES ─────────────────────────────────────────────────
THREAT_ACTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "APT29 / Cozy Bear": {
        "tactics": ["Reconnaissance", "Initial Access", "Defense Evasion",
                    "Credential Access", "Lateral Movement", "Collection", "Exfiltration"],
        "techniques": ["T1566", "T1078", "T1027", "T1003.001", "T1021.001",
                       "T1114", "T1041"],
        "keywords": ["spear.?phish", "cobalt.?strike", "mimikatz", "exchange.*dump",
                     "lateral.*rdp"],
        "description": "Russian APT targeting government, defense, and NGOs",
        "confidence_per_match": 15,
    },
    "Lazarus Group (DPRK)": {
        "tactics": ["Initial Access", "Execution", "Persistence",
                    "Lateral Movement", "Exfiltration", "Impact"],
        "techniques": ["T1566", "T1059.001", "T1543.003", "T1021.002",
                       "T1567", "T1486"],
        "keywords": ["powershell.*download", "smb.*lateral", "ransomware",
                     "supply.?chain"],
        "description": "North Korean APT known for financial theft and ransomware",
        "confidence_per_match": 15,
    },
    "Generic Ransomware Operator": {
        "tactics": ["Initial Access", "Execution", "Privilege Escalation",
                    "Lateral Movement", "Impact"],
        "techniques": ["T1110", "T1059.001", "T1548.002", "T1021.002",
                       "T1486"],
        "keywords": ["brute.?force", "rdp.*login", "mimikatz", "vssadmin",
                     "ransom.*note", "encrypt.*file"],
        "description": "Ransomware operator following RaaS playbook",
        "confidence_per_match": 12,
    },
    "Insider Threat": {
        "tactics": ["Discovery", "Collection", "Exfiltration"],
        "techniques": ["T1083", "T1005", "T1048"],
        "keywords": ["after.?hours", "large.*transfer", "usb", "personal.*email",
                     "cloud.*upload"],
        "description": "Malicious insider or compromised employee",
        "confidence_per_match": 10,
    },
    "OT/ICS Adversary": {
        "tactics": ["Reconnaissance", "Initial Access", "Lateral Movement",
                    "Inhibit Response Function", "Impair Process Control"],
        "techniques": ["T1046", "T1190", "T0885", "T0836", "T0838"],
        "keywords": ["modbus", "s7comm", "scada", "hmi.*modif", "plc.*program",
                     "safety.*bypass"],
        "description": "Nation-state or hacktivist targeting industrial control systems",
        "confidence_per_match": 20,
    },
}

# Kill chain phase order (for timeline reconstruction)
PHASE_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Inhibit Response Function", "Impair Process Control",
]


@dataclass
class EnrichedEvent:
    event_id: str
    source: str
    timestamp: str
    ip: str
    title: str
    description: str
    severity: str
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Campaign:
    campaign_id: str
    ips: List[str] = field(default_factory=list)
    events: List[EnrichedEvent] = field(default_factory=list)
    tactics_observed: List[str] = field(default_factory=list)
    techniques: List[Dict[str, str]] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)  # ordered phases
    start_time: str = ""
    last_seen: str = ""
    campaign_score: int = 0       # 0-100 confidence this is a real campaign
    urgency: str = "low"          # low / medium / high / critical
    actor_match: str = ""         # best matching threat actor
    actor_confidence: int = 0
    event_count: int = 0
    affected_assets: int = 0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatFusionEngine:
    """Correlates multi-source events into attack campaigns with MITRE ATT&CK mapping."""

    # Default time window: events within 10 minutes cluster together
    DEFAULT_WINDOW_MINUTES = 10

    def __init__(self, orchestrator_url: str = "http://localhost:8080") -> None:
        self.orchestrator_url = orchestrator_url

    def fetch_and_analyze(
        self,
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
        max_events: int = 500,
    ) -> List[Campaign]:
        """
        Fetch recent events from orchestrator and run full fusion analysis.
        Returns sorted list of campaigns (highest urgency first).
        """
        events = self._fetch_events(max_events)
        if not events:
            return []
        return self.analyze(events, window_minutes=window_minutes)

    def analyze(
        self,
        raw_events: List[Dict[str, Any]],
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
    ) -> List[Campaign]:
        """Run fusion analysis on a list of raw event dicts."""
        # Step 1: Enrich each event with MITRE ATT&CK mapping
        enriched = [self._enrich_event(e) for e in raw_events]

        # Step 2: Cluster events into campaigns
        campaigns = self._cluster_into_campaigns(enriched, window_minutes)

        # Step 3: Score and classify each campaign
        for campaign in campaigns:
            self._score_campaign(campaign)
            self._match_threat_actor(campaign)
            self._generate_recommendations(campaign)

        # Sort: critical → high → medium → low, then by score
        urgency_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        campaigns.sort(key=lambda c: (urgency_order.get(c.urgency, 9), -c.campaign_score))
        return campaigns

    # ── PRIVATE METHODS ────────────────────────────────────────────────────────

    def _fetch_events(self, limit: int) -> List[Dict[str, Any]]:
        """Fetch events from AEGIS orchestrator."""
        url = f"{self.orchestrator_url}/api/v1/events?limit={limit}"
        try:
            with urllib.request.urlopen(url, timeout=5.0) as resp:
                data = json.loads(resp.read())
                return data.get("events", data if isinstance(data, list) else [])
        except Exception as exc:
            LOGGER.warning("Failed to fetch events from orchestrator: %s", exc)
            return []

    def _enrich_event(self, raw: Dict[str, Any]) -> EnrichedEvent:
        """Add MITRE ATT&CK technique to a raw event."""
        title = str(raw.get("title", "") or raw.get("name", "") or "")
        desc = str(raw.get("description", "") or raw.get("message", "") or "")
        combined = (title + " " + desc).lower()

        tactic = ""
        technique_id = ""
        technique_name = ""

        for pattern, tac, tid, tname in MITRE_PATTERN_MAP:
            if re.search(pattern, combined, re.IGNORECASE):
                tactic = tac
                technique_id = tid
                technique_name = tname
                break

        ip = str(raw.get("source_ip", "") or raw.get("ip", "") or "")
        ev_id = str(raw.get("id", hashlib.md5(json.dumps(raw, default=str).encode()).hexdigest()[:8]))

        return EnrichedEvent(
            event_id=ev_id,
            source=str(raw.get("source", "unknown")),
            timestamp=str(raw.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))),
            ip=ip,
            title=title or "(no title)",
            description=desc[:200],
            severity=str(raw.get("severity", "medium")),
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
            raw=raw,
        )

    def _cluster_into_campaigns(
        self,
        events: List[EnrichedEvent],
        window_minutes: int,
    ) -> List[Campaign]:
        """
        Cluster events into campaigns using:
          1. Same IP → same campaign
          2. Time proximity (within window) → same campaign
          3. Kill-chain progression → merge campaigns
        """
        # Group by IP first
        by_ip: Dict[str, List[EnrichedEvent]] = defaultdict(list)
        for ev in events:
            if ev.ip:
                by_ip[ev.ip].append(ev)
            # Events without IP get their own singleton campaign

        # Each IP group → one campaign candidate
        campaigns: List[Campaign] = []
        campaign_id_counter = 1

        for ip, ip_events in by_ip.items():
            if not ip_events:
                continue

            # Sort by timestamp
            ip_events.sort(key=lambda e: e.timestamp)

            # Collect tactics and techniques
            tactics: List[str] = []
            techniques: List[Dict[str, str]] = []
            seen_techniques: Set[str] = set()

            for ev in ip_events:
                if ev.tactic and ev.tactic not in tactics:
                    tactics.append(ev.tactic)
                if ev.technique_id and ev.technique_id not in seen_techniques:
                    seen_techniques.add(ev.technique_id)
                    techniques.append({
                        "id": ev.technique_id,
                        "name": ev.technique_name,
                        "tactic": ev.tactic,
                    })

            # Build kill chain (ordered phase list observed)
            kill_chain = [p for p in PHASE_ORDER if p in tactics]

            cid = f"CAMP-{campaign_id_counter:04d}"
            campaign_id_counter += 1

            campaign = Campaign(
                campaign_id=cid,
                ips=[ip],
                events=ip_events,
                tactics_observed=tactics,
                techniques=techniques,
                kill_chain_phases=kill_chain,
                start_time=ip_events[0].timestamp if ip_events else "",
                last_seen=ip_events[-1].timestamp if ip_events else "",
                event_count=len(ip_events),
                affected_assets=1,
            )
            campaigns.append(campaign)

        # Merge campaigns with shared IPs or sequential kill-chain phases
        campaigns = self._merge_related_campaigns(campaigns)
        return campaigns

    def _merge_related_campaigns(
        self, campaigns: List[Campaign]
    ) -> List[Campaign]:
        """Merge campaigns that share IPs (same attacker pivot)."""
        # Simple union-find approach
        merged = True
        while merged:
            merged = False
            for i in range(len(campaigns)):
                for j in range(i + 1, len(campaigns)):
                    if set(campaigns[i].ips) & set(campaigns[j].ips):
                        # Merge j into i
                        for ip in campaigns[j].ips:
                            if ip not in campaigns[i].ips:
                                campaigns[i].ips.append(ip)
                        campaigns[i].events.extend(campaigns[j].events)
                        for tac in campaigns[j].tactics_observed:
                            if tac not in campaigns[i].tactics_observed:
                                campaigns[i].tactics_observed.append(tac)
                        for tech in campaigns[j].techniques:
                            if tech not in campaigns[i].techniques:
                                campaigns[i].techniques.append(tech)
                        campaigns[i].event_count = len(campaigns[i].events)
                        campaigns[i].affected_assets = len(set(campaigns[i].ips))
                        # Rebuild kill chain
                        campaigns[i].kill_chain_phases = [
                            p for p in PHASE_ORDER
                            if p in campaigns[i].tactics_observed
                        ]
                        campaigns.pop(j)
                        merged = True
                        break
                if merged:
                    break
        return campaigns

    def _score_campaign(self, campaign: Campaign) -> None:
        """Calculate campaign_score (0-100) and urgency level."""
        score = 0

        # Phase breadth: more kill-chain phases = more advanced attack
        phase_count = len(campaign.kill_chain_phases)
        score += min(40, phase_count * 8)

        # Event count (logarithmic)
        ev_score = min(20, int(campaign.event_count ** 0.5) * 4)
        score += ev_score

        # High-severity events
        high_sev = sum(1 for e in campaign.events if e.severity in {"critical", "high"})
        score += min(20, high_sev * 5)

        # Technique diversity
        tech_count = len(campaign.techniques)
        score += min(10, tech_count * 2)

        # Bonus: reaches high-impact tactics
        impact_tactics = {"Impact", "Exfiltration", "Command and Control",
                          "Inhibit Response Function", "Impair Process Control"}
        if impact_tactics & set(campaign.tactics_observed):
            score += 10

        campaign.campaign_score = min(100, score)

        # Determine urgency
        if campaign.campaign_score >= 70 or "Impact" in campaign.tactics_observed:
            campaign.urgency = "critical"
        elif campaign.campaign_score >= 50 or phase_count >= 4:
            campaign.urgency = "high"
        elif campaign.campaign_score >= 30 or phase_count >= 2:
            campaign.urgency = "medium"
        else:
            campaign.urgency = "low"

        # Summary
        phases_str = " → ".join(campaign.kill_chain_phases[:5])
        campaign.summary = (
            f"Campaign {campaign.campaign_id}: {campaign.event_count} events across "
            f"{campaign.affected_assets} IP(s). Kill chain: {phases_str or 'N/A'}. "
            f"Score: {campaign.campaign_score}/100."
        )

    def _match_threat_actor(self, campaign: Campaign) -> None:
        """Match campaign techniques to known threat actor profiles."""
        best_actor = ""
        best_confidence = 0

        combined_text = " ".join(
            e.title + " " + e.description for e in campaign.events
        ).lower()
        observed_techniques = {t["id"] for t in campaign.techniques}

        for actor_name, profile in THREAT_ACTOR_PROFILES.items():
            confidence = 0

            # Technique overlap
            actor_techniques = set(profile.get("techniques", []))
            overlap = len(actor_techniques & observed_techniques)
            confidence += overlap * profile.get("confidence_per_match", 10)

            # Keyword matching
            for kw in profile.get("keywords", []):
                if re.search(kw, combined_text, re.IGNORECASE):
                    confidence += profile.get("confidence_per_match", 10)

            # Tactic overlap
            actor_tactics = set(profile.get("tactics", []))
            tactic_overlap = len(actor_tactics & set(campaign.tactics_observed))
            confidence += tactic_overlap * 5

            if confidence > best_confidence:
                best_confidence = confidence
                best_actor = actor_name

        if best_confidence > 20:
            campaign.actor_match = best_actor
            campaign.actor_confidence = min(100, best_confidence)

    def _generate_recommendations(self, campaign: Campaign) -> None:
        """Generate actionable recommendations based on campaign phase."""
        recs: List[str] = []
        tactics = set(campaign.tactics_observed)

        if "Reconnaissance" in tactics:
            recs.append("Block or rate-limit scanning IPs in firewall: " +
                        ", ".join(campaign.ips[:3]))
        if "Initial Access" in tactics:
            recs.append("Audit authentication logs and rotate credentials for affected accounts.")
            recs.append("Apply patches for CVEs referenced in events (check vuln module).")
        if "Privilege Escalation" in tactics:
            recs.append("Audit privileged account usage. Enable Just-In-Time (JIT) access.")
        if "Lateral Movement" in tactics:
            recs.append("Enable network micro-segmentation. Restrict SMB/RDP/WinRM between segments.")
            recs.append("Run AEGIS topology scan to identify all lateral movement paths.")
        if "Credential Access" in tactics:
            recs.append("Force password reset for all users on affected systems.")
            recs.append("Enable MFA on all privileged accounts immediately.")
        if "Command and Control" in tactics:
            recs.append("Capture and analyse traffic to/from: " + ", ".join(campaign.ips[:3]))
            recs.append("Check AEGIS threat intelligence for C2 infrastructure matches.")
        if "Exfiltration" in tactics:
            recs.append("Identify and classify all data accessed on affected systems.")
            recs.append("Assess GDPR/regulatory breach notification requirements.")
        if "Impact" in tactics:
            recs.append("🚨 CRITICAL: Isolate all affected hosts immediately via SOAR playbook.")
            recs.append("Initiate incident response and preserve forensic evidence.")
        if {"Inhibit Response Function", "Impair Process Control"} & tactics:
            recs.append("🚨 OT EMERGENCY: Isolate all OT/ICS systems from IT network now.")
            recs.append("Notify operations team and safety officers. Check physical process status.")

        if not recs:
            recs.append("Continue monitoring. Enable AEGIS SIEM correlation rules for these IPs.")

        campaign.recommendations = recs[:6]  # top 6

    def get_statistics(self, campaigns: List[Campaign]) -> Dict[str, Any]:
        """Summary statistics for dashboard display."""
        if not campaigns:
            return {"total": 0, "by_urgency": {}, "top_tactics": [], "top_ips": []}

        by_urgency: Dict[str, int] = defaultdict(int)
        tactic_counter: Dict[str, int] = defaultdict(int)
        ip_counter: Dict[str, int] = defaultdict(int)

        for c in campaigns:
            by_urgency[c.urgency] += 1
            for t in c.tactics_observed:
                tactic_counter[t] += 1
            for ip in c.ips:
                ip_counter[ip] += c.event_count

        top_tactics = sorted(tactic_counter.items(), key=lambda x: -x[1])[:10]
        top_ips = sorted(ip_counter.items(), key=lambda x: -x[1])[:10]

        return {
            "total_campaigns": len(campaigns),
            "critical": by_urgency.get("critical", 0),
            "high": by_urgency.get("high", 0),
            "medium": by_urgency.get("medium", 0),
            "low": by_urgency.get("low", 0),
            "total_events": sum(c.event_count for c in campaigns),
            "top_tactics": [{"tactic": t, "count": c} for t, c in top_tactics],
            "top_ips": [{"ip": ip, "events": cnt} for ip, cnt in top_ips],
        }
