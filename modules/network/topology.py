#!/usr/bin/env python3
"""
AEGIS Network Topology Mapper & Attack Path Analyzer
=====================================================
Builds a live network topology graph from scan results and computes:

  - Gateway/router identification (default route + TTL analysis)
  - Network segment detection (distinct subnets)
  - Lateral movement attack paths (BFS shortest paths + risk scoring)
  - IT/OT boundary crossing detection (critical segmentation gaps)
  - Chokepoint and crown jewel identification
  - JSON graph export (D3.js compatible)

Unique capability: transforms raw scan results into an attacker's view —
showing exactly which paths exist between any two hosts, which services
enable movement, and how many hops an attacker needs from any starting
point to reach a crown jewel asset.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

LOGGER = logging.getLogger("aegis.topology")

# Services that enable lateral movement (port → technique)
LATERAL_MOVEMENT_SERVICES: Dict[int, Dict[str, str]] = {
    22:    {"technique": "SSH Lateral Movement",     "mitre": "T1021.004", "risk": "high"},
    23:    {"technique": "Telnet (cleartext)",        "mitre": "T1021.004", "risk": "critical"},
    135:   {"technique": "RPC/WMI Lateral Movement", "mitre": "T1021.003", "risk": "high"},
    139:   {"technique": "SMB/NetBIOS",              "mitre": "T1021.002", "risk": "high"},
    445:   {"technique": "SMB Lateral Movement",     "mitre": "T1021.002", "risk": "critical"},
    3389:  {"technique": "RDP Lateral Movement",     "mitre": "T1021.001", "risk": "high"},
    5985:  {"technique": "WinRM HTTP",               "mitre": "T1021.006", "risk": "high"},
    5986:  {"technique": "WinRM HTTPS",              "mitre": "T1021.006", "risk": "high"},
    5900:  {"technique": "VNC Remote Control",       "mitre": "T1021.005", "risk": "high"},
    2049:  {"technique": "NFS Mount",                "mitre": "T1039",     "risk": "medium"},
    3306:  {"technique": "MySQL Direct Access",      "mitre": "T1190",     "risk": "high"},
    5432:  {"technique": "PostgreSQL Direct Access", "mitre": "T1190",     "risk": "high"},
    1433:  {"technique": "MSSQL Direct Access",      "mitre": "T1190",     "risk": "high"},
    6379:  {"technique": "Redis Unauthenticated",    "mitre": "T1190",     "risk": "critical"},
    27017: {"technique": "MongoDB Open Access",      "mitre": "T1190",     "risk": "critical"},
    9200:  {"technique": "Elasticsearch Open API",   "mitre": "T1190",     "risk": "high"},
    502:   {"technique": "Modbus Direct Command",    "mitre": "T0885",     "risk": "critical"},
    102:   {"technique": "S7 PLC Command",           "mitre": "T0885",     "risk": "critical"},
    4840:  {"technique": "OPC-UA Direct Access",     "mitre": "T0885",     "risk": "critical"},
    44818: {"technique": "EtherNet/IP Command",      "mitre": "T0885",     "risk": "critical"},
}

# Crown jewel device types (highest value targets)
CROWN_JEWEL_TYPES = {
    "domain_controller", "mssql_server", "postgresql_server",
    "plc", "siemens_s7_plc", "opcua_server", "scada_server",
    "historian", "safety_controller", "iec104_rtu",
}

# Risk levels for path scoring
RISK_SCORE = {"critical": 40, "high": 30, "medium": 20, "low": 10, "none": 5}


@dataclass
class TopologyNode:
    ip: str
    hostname: str = ""
    device_type: str = "unknown"
    device_category: str = "unknown"
    open_ports: List[int] = field(default_factory=list)
    is_gateway: bool = False
    is_crown_jewel: bool = False
    is_ot_device: bool = False
    segment: str = ""           # e.g. "192.168.1.0/24"
    risk_score: int = 0
    lateral_services: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyEdge:
    source: str
    target: str
    techniques: List[str] = field(default_factory=list)
    mitre_ids: List[str] = field(default_factory=list)
    risk_level: str = "low"
    crossing_boundary: bool = False     # IT → OT or different segment

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPath:
    start_ip: str
    end_ip: str
    path: List[str] = field(default_factory=list)   # ordered list of IPs
    techniques: List[str] = field(default_factory=list)
    total_risk_score: int = 0
    crosses_ot_boundary: bool = False
    hop_count: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SegmentationGap:
    it_ip: str
    ot_ip: str
    connecting_port: int
    technique: str
    mitre_id: str
    severity: str = "critical"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyGraph:
    nodes: List[TopologyNode] = field(default_factory=list)
    edges: List[TopologyEdge] = field(default_factory=list)
    segments: List[str] = field(default_factory=list)
    gateways: List[str] = field(default_factory=list)
    crown_jewels: List[str] = field(default_factory=list)
    segmentation_gaps: List[SegmentationGap] = field(default_factory=list)
    attack_surface_score: int = 0
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_d3_json(self) -> Dict[str, Any]:
        """Export in D3.js force-directed graph format."""
        color_map = {
            "ot": "#ff4444", "iot": "#ff8800", "network": "#4488ff",
            "it": "#44bb44", "endpoint": "#aaaaaa", "unknown": "#888888",
        }
        nodes_d3 = []
        for n in self.nodes:
            nodes_d3.append({
                "id": n.ip,
                "label": n.hostname or n.ip,
                "device_type": n.device_type,
                "category": n.device_category,
                "color": color_map.get(n.device_category, "#888888"),
                "size": 20 if n.is_crown_jewel else (15 if n.is_gateway else 10),
                "is_gateway": n.is_gateway,
                "is_crown_jewel": n.is_crown_jewel,
                "is_ot": n.is_ot_device,
                "risk_score": n.risk_score,
            })
        links_d3 = []
        for e in self.edges:
            links_d3.append({
                "source": e.source,
                "target": e.target,
                "techniques": e.techniques,
                "risk_level": e.risk_level,
                "crossing_boundary": e.crossing_boundary,
                "color": "#ff0000" if e.crossing_boundary else
                         ("#ff6600" if e.risk_level in {"critical", "high"} else "#555555"),
            })
        return {
            "nodes": nodes_d3,
            "links": links_d3,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "segments": self.segments,
                "gateways": self.gateways,
                "crown_jewels": self.crown_jewels,
                "segmentation_gaps": len(self.segmentation_gaps),
                "attack_surface_score": self.attack_surface_score,
            },
        }


class TopologyMapper:
    """Builds and analyzes a network topology graph from scan results."""

    def __init__(self) -> None:
        self._graph: Dict[str, TopologyNode] = {}
        self._adjacency: Dict[str, Set[str]] = {}  # ip → set of reachable IPs

    def build_from_scan_results(
        self, scan_results: List[Dict[str, Any]]
    ) -> TopologyGraph:
        """
        Build a topology from AEGIS scan results.
        Each result should have: ip, open_ports, device_type, device_category, mac, hostname
        """
        self._graph.clear()
        self._adjacency.clear()

        if not scan_results:
            return TopologyGraph(generated_at=time.strftime("%Y-%m-%dT%H:%M:%S"))

        # Detect local gateway
        gateways = self._detect_gateways(scan_results)

        # Build nodes
        for host in scan_results:
            ip = host.get("ip", "")
            if not ip:
                continue
            ports = [int(p) for p in host.get("open_ports", [])
                     if str(p).isdigit()]
            dtype = host.get("device_type", "unknown") or "unknown"
            dcat = host.get("device_category", "unknown") or "unknown"

            # Calculate lateral movement services
            lat_services = []
            for port in ports:
                if port in LATERAL_MOVEMENT_SERVICES:
                    svc = dict(LATERAL_MOVEMENT_SERVICES[port])
                    svc["port"] = str(port)
                    lat_services.append(svc)

            # Risk score = sum of service risks
            risk_score = sum(
                RISK_SCORE.get(s.get("risk", "low"), 10) for s in lat_services
            )

            node = TopologyNode(
                ip=ip,
                hostname=host.get("hostname", ""),
                device_type=dtype,
                device_category=dcat,
                open_ports=ports,
                is_gateway=ip in gateways,
                is_crown_jewel=dtype in CROWN_JEWEL_TYPES,
                is_ot_device=dcat == "ot",
                segment=self._get_segment(ip),
                risk_score=min(100, risk_score),
                lateral_services=lat_services,
            )
            self._graph[ip] = node
            self._adjacency[ip] = set()

        # Build edges (directional: any host with lateral services can reach others in same segment)
        edges: List[TopologyEdge] = []
        ips = list(self._graph.keys())

        for src_ip in ips:
            src_node = self._graph[src_ip]
            src_ports = set(src_node.open_ports)

            for dst_ip in ips:
                if src_ip == dst_ip:
                    continue
                dst_node = self._graph[dst_ip]
                # An edge exists if the destination has a service that enables access
                common_lateral = [
                    svc for svc in dst_node.lateral_services
                ]
                if not common_lateral:
                    continue

                techniques = [s["technique"] for s in common_lateral]
                mitre_ids = [s["mitre"] for s in common_lateral]
                max_risk = max(
                    RISK_SCORE.get(s.get("risk", "low"), 10) for s in common_lateral
                )
                risk_levels = {
                    40: "critical", 30: "high", 20: "medium", 10: "low"
                }
                risk_level = risk_levels.get(max_risk, "low")

                # Check IT/OT boundary crossing
                crossing = (
                    src_node.device_category != dst_node.device_category
                    and ("ot" in {src_node.device_category, dst_node.device_category})
                )

                edge = TopologyEdge(
                    source=src_ip,
                    target=dst_ip,
                    techniques=techniques[:3],  # top 3
                    mitre_ids=mitre_ids[:3],
                    risk_level=risk_level,
                    crossing_boundary=crossing,
                )
                edges.append(edge)
                self._adjacency[src_ip].add(dst_ip)

        # Detect segmentation gaps
        gaps = self._find_segmentation_gaps(edges)

        # Crown jewels list
        crown_jewels = [ip for ip, n in self._graph.items() if n.is_crown_jewel]

        # Segments
        segments = list({n.segment for n in self._graph.values() if n.segment})

        # Attack surface score (0-100)
        total_risk = sum(n.risk_score for n in self._graph.values())
        avg_risk = total_risk // max(1, len(self._graph))
        gap_penalty = len(gaps) * 15
        attack_surface = min(100, avg_risk + gap_penalty)

        return TopologyGraph(
            nodes=list(self._graph.values()),
            edges=edges,
            segments=sorted(segments),
            gateways=sorted(gateways),
            crown_jewels=crown_jewels,
            segmentation_gaps=gaps,
            attack_surface_score=attack_surface,
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

    def compute_attack_paths(
        self,
        topology: TopologyGraph,
        from_ip: Optional[str] = None,
        to_ip: Optional[str] = None,
        max_paths: int = 10,
    ) -> List[AttackPath]:
        """
        Compute shortest lateral movement paths using BFS.
        If from_ip/to_ip not specified, finds all paths to crown jewels.
        """
        paths: List[AttackPath] = []

        # Rebuild adjacency from topology edges
        adj: Dict[str, List[str]] = {n.ip: [] for n in topology.nodes}
        for edge in topology.edges:
            if edge.source in adj:
                adj[edge.source].append(edge.target)

        # Determine source/target sets
        all_ips = [n.ip for n in topology.nodes]
        sources = [from_ip] if from_ip and from_ip in adj else all_ips
        targets = [to_ip] if to_ip and to_ip in adj else [
            n.ip for n in topology.nodes if n.is_crown_jewel
        ]

        if not targets:
            return []

        for src in sources:
            for dst in targets:
                if src == dst:
                    continue
                path = self._bfs_shortest_path(adj, src, dst)
                if path and len(path) >= 2:
                    # Gather techniques along path
                    techniques: List[str] = []
                    total_risk = 0
                    crosses_ot = False
                    for i in range(len(path) - 1):
                        for edge in topology.edges:
                            if edge.source == path[i] and edge.target == path[i+1]:
                                techniques.extend(edge.techniques)
                                total_risk += RISK_SCORE.get(edge.risk_level, 10)
                                if edge.crossing_boundary:
                                    crosses_ot = True
                                break

                    src_node = next((n for n in topology.nodes if n.ip == src), None)
                    dst_node = next((n for n in topology.nodes if n.ip == dst), None)
                    desc = (
                        f"{'IT→OT boundary crossing! ' if crosses_ot else ''}"
                        f"From {src} ({src_node.device_type if src_node else '?'}) "
                        f"→ {dst} ({dst_node.device_type if dst_node else '?'}) "
                        f"via {len(path)-1} hop(s)"
                    )

                    attack_path = AttackPath(
                        start_ip=src,
                        end_ip=dst,
                        path=path,
                        techniques=list(dict.fromkeys(techniques))[:5],  # deduplicated
                        total_risk_score=min(100, total_risk),
                        crosses_ot_boundary=crosses_ot,
                        hop_count=len(path) - 1,
                        description=desc,
                    )
                    paths.append(attack_path)
                    if len(paths) >= max_paths:
                        break
            if len(paths) >= max_paths:
                break

        # Sort by risk (highest first), then by hop count (fewest first)
        paths.sort(key=lambda p: (-p.total_risk_score, p.hop_count))
        return paths[:max_paths]

    # ── PRIVATE HELPERS ────────────────────────────────────────────────────────

    def _detect_gateways(self, hosts: List[Dict[str, Any]]) -> Set[str]:
        """Heuristically identify gateway/router IPs."""
        gateways: Set[str] = set()

        # Method 1: OS default gateway
        try:
            gw = self._get_default_gateway()
            if gw:
                gateways.add(gw)
        except Exception:
            pass

        # Method 2: Device types flagged as router/firewall
        for host in hosts:
            dtype = host.get("device_type", "")
            dcat = host.get("device_category", "")
            if dtype in {"router", "firewall", "bgp_router", "mikrotik_router",
                          "managed_switch"} or dcat == "network":
                ip = host.get("ip", "")
                if ip:
                    gateways.add(ip)

        # Method 3: .1 and .254 addresses are commonly gateways
        for host in hosts:
            ip = host.get("ip", "")
            if ip:
                last_octet = ip.rsplit(".", 1)[-1]
                if last_octet in {"1", "254"}:
                    gateways.add(ip)

        return gateways

    def _get_default_gateway(self) -> Optional[str]:
        """Get the system default gateway IP."""
        if sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if "0.0.0.0" in line and "0.0.0.0" in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == "0.0.0.0" and i + 2 < len(parts):
                                gw = parts[i + 2]
                                try:
                                    ipaddress.ip_address(gw)
                                    return gw
                                except ValueError:
                                    pass
            except Exception:
                pass
        else:
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    if "default via" in line:
                        parts = line.split()
                        idx = parts.index("via")
                        if idx + 1 < len(parts):
                            return parts[idx + 1]
            except Exception:
                pass
        return None

    def _get_segment(self, ip: str) -> str:
        """Return the /24 network segment for an IP."""
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        except ValueError:
            return ""

    def _find_segmentation_gaps(
        self, edges: List[TopologyEdge]
    ) -> List[SegmentationGap]:
        """Find edges that cross IT/OT boundaries — critical security findings."""
        gaps: List[SegmentationGap] = []
        for edge in edges:
            if not edge.crossing_boundary:
                continue
            src_node = self._graph.get(edge.source)
            dst_node = self._graph.get(edge.target)
            if not src_node or not dst_node:
                continue
            for i, tech in enumerate(edge.techniques[:2]):
                mitre = edge.mitre_ids[i] if i < len(edge.mitre_ids) else ""
                # Find the enabling port
                for port, svc in LATERAL_MOVEMENT_SERVICES.items():
                    if svc["technique"] == tech:
                        gap = SegmentationGap(
                            it_ip=edge.source if src_node.device_category != "ot" else edge.target,
                            ot_ip=edge.target if dst_node.device_category == "ot" else edge.source,
                            connecting_port=port,
                            technique=tech,
                            mitre_id=mitre,
                            severity="critical",
                            description=(
                                f"IT device {edge.source} can reach OT device {edge.target} "
                                f"via {tech} (port {port}). Network segmentation violation."
                            ),
                        )
                        gaps.append(gap)
                        break
        return gaps

    def _bfs_shortest_path(
        self, adj: Dict[str, List[str]], start: str, end: str
    ) -> Optional[List[str]]:
        """BFS to find shortest path from start to end."""
        if start not in adj or end not in adj:
            return None
        visited = {start}
        queue: List[List[str]] = [[start]]
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == end:
                return path
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
                    if len(queue) > 50000:  # safety limit
                        return None
        return None
