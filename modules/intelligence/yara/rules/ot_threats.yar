/*
Cybersecurity-AEGIS defensive YARA examples: OT/ICS threat hunting.

These rules help analysts search binaries or captured artifacts for industrial
protocol and malware-family indicators. They do not perform network scanning.
*/

rule Cybersecurity_AEGIS_OT_IEC61850_Tooling_Indicators
{
    meta:
        description = "IEC 61850 MMS/GOOSE tooling or payload indicators"
        author = "Cybersecurity-AEGIS"
        severity = "high"
        target = "Electric grid"
        mitre_ics = "T0855"

    strings:
        $iec_1 = "IEC-61850" ascii nocase
        $iec_2 = "GOOSE" ascii
        $iec_3 = "XCBR" ascii
        $iec_4 = "CSWI" ascii
        $iec_5 = "Pos.stVal" ascii
        $mms_1 = "IedConnection_create" ascii
        $asn1_mms = { 61 82 ?? ?? 30 82 }

    condition:
        uint16(0) == 0x5a4d and
        ((2 of ($iec_*) and $mms_1) or $asn1_mms)
}

rule Cybersecurity_AEGIS_OT_Safety_System_Targeting
{
    meta:
        description = "Safety instrumented system targeting indicators"
        author = "Cybersecurity-AEGIS"
        severity = "critical"
        target = "SIS"
        mitre_ics = "T0838"

    strings:
        $sis_1 = "Triconex" ascii nocase
        $sis_2 = "TriStation" ascii nocase
        $sis_3 = "SafetyFunctionBlock" ascii nocase
        $cmd_1 = "program_download" ascii nocase
        $port_8000 = { 1F 40 }

    condition:
        2 of ($sis_*) or ($cmd_1 and $port_8000)
}

rule Cybersecurity_AEGIS_OT_Modbus_And_FINS_Framework
{
    meta:
        description = "Modbus and OMRON FINS framework indicators"
        author = "Cybersecurity-AEGIS"
        severity = "high"
        mitre_ics = "T0846"

    strings:
        $modbus_1 = "pymodbus" ascii nocase
        $modbus_2 = "modbus_tk" ascii nocase
        $modbus_3 = { 00 00 00 00 00 06 01 01 }
        $fins_1 = "FINS" ascii fullword
        $fins_2 = { 46 49 4E 53 }
        $fins_header = { 80 00 02 00 00 00 00 00 }

    condition:
        2 of ($modbus_*) or ($fins_1 and $fins_header) or ($fins_2 and $fins_header)
}

rule Cybersecurity_AEGIS_OT_OPC_Tooling_Indicators
{
    meta:
        description = "OPC DA/UA tooling and automation indicators"
        author = "Cybersecurity-AEGIS"
        severity = "medium"
        mitre_ics = "T0869"

    strings:
        $opc_1 = "OpcUa" ascii
        $opc_2 = "OPC.Server" ascii
        $opc_3 = "opc.tcp://" ascii nocase
        $opc_4 = "urn:S7Comm" ascii

    condition:
        2 of ($opc_*)
}

rule Cybersecurity_AEGIS_OT_Siemens_S7_Indicators
{
    meta:
        description = "Siemens S7 protocol and engineering artifact indicators"
        author = "Cybersecurity-AEGIS"
        severity = "high"
        target = "Siemens S7"
        mitre_ics = "T0843"

    strings:
        $s7_1 = "s7comm" ascii nocase
        $s7_2 = "S7_SetPassword" ascii
        $s7_3 = "STEP 7" ascii
        $s7_4 = "python-snap7" ascii nocase
        $s7_pdu = { 32 01 00 00 }

    condition:
        uint16(0) == 0x5a4d and
        (2 of ($s7_*) or ($s7_pdu and any of ($s7_*)))
}
