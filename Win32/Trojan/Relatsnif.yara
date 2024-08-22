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
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 00 75 00 72 00 6c 00 [0-16] 20 00 2d 00 6f 00 20 00}  //weight: 2, accuracy: Low
        $x_2_2 = "curse-breaker.org" wide //weight: 2
        $x_1_3 = "files/installer.dll" wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\IFInstaller.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Relatsnif_A_2147919071_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.A"
        threat_id = "2147919071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "WATAUAVAWH" ascii //weight: 2
        $x_2_2 = "VWATAVAWH" ascii //weight: 2
        $x_2_3 = {83 e0 7f 42 0f b6 0c ?? 0f b6 44 15 ?? 32 c8 88 4c 15 ?? 48 ff c2 48 83 fa ?? 72 e1}  //weight: 2, accuracy: Low
        $x_1_4 = "ABCDEFGHIJKLMNOPn" ascii //weight: 1
        $x_1_5 = "14.121.222.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
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

rule Trojan_Win32_Relatsnif_D_2147919213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.D"
        threat_id = "2147919213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Standalone values not allowed. Was given: {}" ascii //weight: 1
        $x_1_2 = "Config file contents:" ascii //weight: 1
        $x_1_3 = "DQAADQAADQAADQAA" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\chocolatey\\lib\\Connhost\\tools\\sb.conf" ascii //weight: 1
        $x_1_5 = "GetComputerNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relatsnif_E_2147919214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.E"
        threat_id = "2147919214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to rename {} to {}. Error code: {}" ascii //weight: 1
        $x_1_2 = "Renamed {} to {}." ascii //weight: 1
        $x_1_3 = "File {} {}." ascii //weight: 1
        $x_1_4 = "{} {}. Error code: {}" ascii //weight: 1
        $x_1_5 = "Overwrote {} with {} {} {})" ascii //weight: 1
        $x_1_6 = "[{}] [{}] {}" ascii //weight: 1
        $x_1_7 = "{} {} after renaming it." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

