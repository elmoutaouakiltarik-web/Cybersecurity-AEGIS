# Cybersecurity-AEGIS — Commercial Overview

Copyright (C) 2026 **El Moutaouakil Tarik** — all rights reserved.

Cybersecurity-AEGIS is the exclusive property of its author, El Moutaouakil
Tarik, who is the sole copyright holder. All commercial rights — including
redistribution, OEM embedding, white-labelling and MSP multi-tenant use — are
reserved to the author and are granted only through a written commercial
license. Attribution to the author must remain visible in every commercial
deployment.

## Product Identity

**Cybersecurity-AEGIS** is the first personal, on-premise cybersecurity control plane that unifies IT endpoint defense, network monitoring, threat intelligence, AI-driven anomaly detection, and OT/ICS passive visibility in a single composable suite.

## Unique Value Proposition

1. **IT + OT in One Fabric**: Unlike traditional SIEMs that ignore industrial protocols, AEGIS includes native Modbus, DNP3, OPC UA, IEC 61850, and BACnet parsing — all passive and safety-gated.
2. **AI-Native, Not AI-Bolted**: CyberShield AI provides real NSL-KDD model artifacts for network anomaly detection, integrated directly into the event pipeline.
3. **Open-Source Composable Core**: Built on Wazuh, Suricata, Zeek, MISP, OpenCTI, StackStorm, and 30+ verified open-source projects — no vendor lock-in.
4. **Local-First, Privacy-First**: All data stays on your infrastructure. Optional cloud only for non-sensitive CI/CD and threat-feed mirroring.
5. **Defensive-Only, Legally Safe**: No exploit frameworks, C2 systems, or aggressive OT automation. Designed for authorized environments with GDPR/NIS2 alignment.

## Target Markets

- **SMBs & Mid-Market** that need enterprise-grade security without enterprise pricing.
- **Industrial SMEs** with SCADA/PLC networks requiring safe visibility.
- **Managed Security Providers (MSPs)** wanting a white-label defensive stack.
- **Critical Infrastructure** pilot projects needing NIS2-compliant tooling.
- **Cybersecurity Training & Research Labs** requiring a realistic but safe environment.

## Licensing Model

The author retains ownership of the project in every tier. A license grants
rights of use; it never transfers the project or its copyright.

- **Community Edition**: AGPL-3.0 + Commons Clause — free for personal, research, and internal use.
- **Commercial License**: required for redistribution, OEM embedding, and MSP multi-tenant deployments. Contact the author for pricing.
- **Support Tiers**: Bronze (community forums), Silver (email support + quarterly updates), Gold (24/7 SLA + dedicated engineer).
- **Attribution**: the copyright notice and the [NOTICE](NOTICE) file must be preserved in all deployments and derivative works.

## Competitive Differentiation

| Feature | AEGIS | Typical SIEM | Typical OT Tool |
|---------|-------|--------------|-----------------|
| IT + OT unified | ✅ Yes | ❌ No | ❌ IT only |
| On-premise first | ✅ Yes | ⚠️ Cloud push | ✅ Yes |
| AI/ML IDS included | ✅ Yes | ❌ Add-on | ❌ Rare |
| Open-source core | ✅ Yes | ❌ Proprietary | ⚠️ Partial |
| OT read-only default | ✅ Yes | N/A | ⚠️ Varies |
| GDPR/NIS2 aligned | ✅ Yes | ⚠️ Audit needed | ⚠️ Audit needed |
| Personal/SMB pricing | ✅ Yes | ❌ Enterprise | ❌ Enterprise |

## Roadmap for Revenue

- **Q3 2026**: v1.0 GA with installer, documentation, and support portal.
- **Q4 2026**: Plugin marketplace (custom detection rules, OT protocol packs, YARA rules).
- **Q1 2027**: Cloud bridge (non-sensitive telemetry only) for distributed deployments.
- **Q2 2027**: Hardware appliance (ARM-based edge collector) for plant deployments.

## Contact

For partnership, licensing, and enterprise pilot programs, open an issue or
send a message through the author's GitHub profile:

- GitHub: [@elmoutaouakiltarik-web](https://github.com/elmoutaouakiltarik-web)
- Repository: [Cybersecurity-AEGIS](https://github.com/elmoutaouakiltarik-web/Cybersecurity-AEGIS)
- Security reports: see [SECURITY.md](SECURITY.md) (private advisory, not a public issue)
