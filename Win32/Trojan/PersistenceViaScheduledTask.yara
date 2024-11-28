rule Trojan_Win32_PersistenceViaScheduledTask_A_2147927124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceViaScheduledTask.A"
        threat_id = "2147927124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceViaScheduledTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "schtasks.exe /create /tn " wide //weight: 3
        $x_3_2 = {61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 20 00 74 00 61 00 73 00 6b 00 [0-112] 5c 00 [0-42] 2e 00 62 00 61 00 74 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

