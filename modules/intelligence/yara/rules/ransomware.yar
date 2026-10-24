/*
Cybersecurity-AEGIS defensive YARA examples: ransomware indicators.

Use only on systems and files you are authorized to scan. These rules are meant
for triage and hunting; tune them with local allowlists before production use.
*/

rule Cybersecurity_AEGIS_Ransomware_Generic_Behavior
{
    meta:
        description = "Generic ransomware behavior strings"
        author = "Cybersecurity-AEGIS"
        severity = "critical"
        mitre_attack = "T1486"

    strings:
        $note_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $note_2 = "HOW TO RESTORE YOUR FILES" ascii nocase
        $note_3 = "RECOVERY INSTRUCTIONS" ascii nocase
        $note_4 = "decrypt your files" ascii nocase
        $pay_1 = "bitcoin" ascii nocase
        $pay_2 = "monero" ascii nocase

        $api_1 = "CryptEncrypt" ascii
        $api_2 = "BCryptEncrypt" ascii
        $api_3 = "FindFirstFileW" ascii
        $shadow_1 = "vssadmin delete shadows" ascii nocase
        $shadow_2 = "wbadmin delete catalog" ascii nocase
        $shadow_3 = "WMIC SHADOWCOPY DELETE" ascii nocase

        $chacha = "expand 32-byte k" ascii

    condition:
        (
            uint16(0) == 0x5a4d and filesize < 20MB and
            (
                2 of ($note_*) or
                any of ($shadow_*) or
                ($chacha and any of ($api_*))
            )
        ) or
        (
            not uint16(0) == 0x5a4d and filesize < 1MB and
            3 of ($note_*) and any of ($pay_*)
        )
}

rule Cybersecurity_AEGIS_Ransomware_LockBit_Style_Indicators
{
    meta:
        description = "LockBit-style strings and recovery note indicators"
        author = "Cybersecurity-AEGIS"
        severity = "critical"
        family = "LockBit-style"
        mitre_attack = "T1486,T1490"

    strings:
        $lb_1 = "LockBit" ascii nocase
        $lb_2 = "Restore-My-Files.txt" ascii
        $lb_3 = "lockbit" ascii nocase
        $vss = "cmd.exe /c vssadmin" ascii nocase
        $mutex = "Global\\{" ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 30MB and
        (2 of ($lb_*) or ($vss and $mutex))
}

rule Cybersecurity_AEGIS_Ransomware_Rust_Builder_Style
{
    meta:
        description = "Rust ransomware builder style indicators"
        author = "Cybersecurity-AEGIS"
        severity = "high"
        mitre_attack = "T1486"

    strings:
        $rust_1 = "rust_begin_unwind" ascii
        $rust_2 = "panicked at" ascii
        $crypto_1 = "chacha20" ascii nocase
        $crypto_2 = "aes-gcm" ascii nocase
        $note = "encrypted" ascii nocase

    condition:
        uint16(0) == 0x5a4d and filesize < 40MB and
        all of ($rust_*) and
        (any of ($crypto_*) and $note)
}

rule Cybersecurity_AEGIS_Ransomware_OT_Process_Targeting
{
    meta:
        description = "Ransomware targeting common OT/SCADA process names"
        author = "Cybersecurity-AEGIS"
        severity = "critical"
        target = "OT/ICS"
        mitre_ics = "T0827"

    strings:
        $proc_1 = "Intouch.exe" ascii
        $proc_2 = "CimView.exe" ascii
        $proc_3 = "FactoryTalk" ascii
        $proc_4 = "RSLinx" ascii
        $proc_5 = "OPCServer" ascii
        $proc_6 = "wincc" ascii nocase
        $proc_7 = "pvhost" ascii

        $kill_1 = "TerminateProcess" ascii
        $kill_2 = "ControlService" ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 40MB and
        any of ($kill_*) and 3 of ($proc_*)
}
