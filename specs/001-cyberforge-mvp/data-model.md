# Data Model: Cybersecurity-AEGIS MVP Control Plane

## SecurityEvent

Represents one normalized event from any integration.

Fields:
- `id`: unique event identifier.
- `timestamp`: event time in RFC3339 format.
- `source`: source integration, such as `wazuh`, `suricata`, `crowdsec`, `ot_monitor`, or `generic`.
- `category`: `endpoint`, `network`, `perimeter`, `identity`, `intelligence`, `industrial`, or `system`.
- `severity`: `critical`, `high`, `medium`, `low`, or `info`.
- `title`: short human-readable summary.
- `description`: longer explanation.
- `mitre`: optional MITRE ATT&CK or ATT&CK for ICS mapping.
- `ot_context`: optional industrial context.
- `raw_data`: source payload with secret redaction expected before production use.
- `resolved`: boolean analyst workflow flag.
- `tags`: string labels.

Validation:
- `id`, `timestamp`, `source`, `category`, `severity`, and `title` are required.
- Unknown severity maps to `info`.
- Raw payload size should be bounded in future durable storage.

## MITREAttack

Fields:
- `tactic_id`
- `tactic_name`
- `technique_id`
- `technique_name`
- `is_ics`

Validation:
- `is_ics=true` for ATT&CK for ICS mappings.

## OTContext

Fields:
- `protocol`: `modbus`, `dnp3`, `iec61850`, `opc_ua`, `profinet`, `ethernet_ip`, `bacnet`, `iec104`, or `unknown`.
- `purdue_level`: integer from 0 to 4, or -1 when unknown.
- `device_type`: `plc`, `hmi`, `rtu`, `ied`, `historian`, `gateway`, `unknown`.
- `asset_id`: optional Cybersecurity-AEGIS asset reference.
- `process_area`: optional plant/process label.

Validation:
- Unknown Purdue level does not block event ingestion.
- OT context never authorizes active control actions in MVP.

## ModuleStatus

Fields:
- `name`
- `status`: `running`, `stopped`, `error`, `degraded`, or `unknown`.
- `version`
- `last_seen`
- `events_in_24h`
- `alerts_24h`
- `error`

Validation:
- Unknown modules can be reported but start with `unknown` status.

## OTAsset

Fields:
- `ip`
- `mac`
- `hostname`
- `vendor`
- `device_type`
- `purdue_level`
- `protocols`
- `first_seen`
- `last_seen`
- `is_authorized`
- `risk_score`

Validation:
- Asset discovery is advisory and passive.
- Unauthorized assets generate alerts but do not trigger automatic blocking.

## DetectionRule

Fields:
- `name`
- `rule_type`: `yara` initially, later `sigma`.
- `scope`: `endpoint`, `industrial`, `ransomware`, `secrets`, etc.
- `severity`
- `validation_status`: `example`, `tested`, `production-approved`.
- `source_file`

Validation:
- MVP rules ship as `example`.
