rule Trojan_Win32_Relatsnif_A_2147919071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.A"
        threat_id = "2147919071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 00 75 00 72 00 6c 00 90 00 02 00 0c 00 20 00 2d 00 6f 00 20 00}  //weight: 2, accuracy: High
        $x_1_2 = "curse-breaker.org" wide //weight: 1
        $x_1_3 = "files/installer.dll" wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\IFInstaller.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Relatsnif_B_2147919080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.B"
        threat_id = "2147919080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Resource {} is unavailable" ascii //weight: 1
        $x_1_2 = "Could not find resource" ascii //weight: 1
        $x_1_3 = "Failed to commit transaction" ascii //weight: 1
        $x_1_4 = "resource deadlock would occur" ascii //weight: 1
        $x_1_5 = "network unreachable" ascii //weight: 1
        $x_1_6 = "connection already in progress" ascii //weight: 1
        $x_1_7 = "too many files open in system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Relatsnif_C_2147919081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.C"
        threat_id = "2147919081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net stop mozyprobackup /y" ascii //weight: 1
        $x_1_2 = "net stop EraserSvc11710 /y" ascii //weight: 1
        $x_1_3 = "net stop SstpSvc /y" ascii //weight: 1
        $x_1_4 = "net stop MSSQLSERVER /y" ascii //weight: 1
        $x_1_5 = "net stop SQLWriter /y" ascii //weight: 1
        $x_1_6 = "too many files open in system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

