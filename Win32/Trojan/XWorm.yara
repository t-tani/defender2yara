rule Trojan_Win32_XWorm_NWR_2147890114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.NWR!MTB"
        threat_id = "2147890114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 49 ff ff ff 3b 43 20 75 ?? 33 c0 89 43 20 eb ?? 8b 43 1c e8 b9 67 fa ff 8b d0 8b c6 e8 ?? ?? ?? ?? 89 43 20 83 c3}  //weight: 5, accuracy: Low
        $x_1_2 = "shutdown.exe /f /s /t 0" wide //weight: 1
        $x_1_3 = "StartDDos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XWorm_AMAT_2147916822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XWorm.AMAT!MTB"
        threat_id = "2147916822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = "EXECUTE ( \"A\" & \"sc(Str\" & \"ingM\" & \"id" ascii //weight: 2
        $x_2_4 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-15] 28 00 22 00}  //weight: 2, accuracy: Low
        $x_2_5 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 [0-15] 28 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

