rule Trojan_Win32_DarkCloud_MBHP_2147852877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.MBHP!MTB"
        threat_id = "2147852877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 38 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 80 35 40 00 40 35 40 00 c0 33 40 00 78 00 00 00 85 00 00 00 8e 00 00 00 8f}  //weight: 1, accuracy: High
        $x_1_2 = "svpaAfhWDOZhcfQttjAUreOpHTGCbHMhwWDQuwgeQPF" ascii //weight: 1
        $x_1_3 = "hvkLxKbCtVIhsSxYuBtRpFekZrFGjKZt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_MBIP_2147890349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.MBIP!MTB"
        threat_id = "2147890349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 b5 4c 02 ce 82 e6 1d 87 19 44 52 33 d7 ec 1c 59 06 0e}  //weight: 1, accuracy: High
        $x_1_2 = {f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 ac 32 40 00 ac 32 40 00 2c 31 40 00 78 00 00 00 80 00 00 00 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_DA_2147897757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.DA!MTB"
        threat_id = "2147897757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 04 ab 91 e9 d1 5b 89 c1 c1 e9 18 31 c1 69 c1 91 e9 d1 5b 69 f6 91 e9 d1 5b 31 c6 45 39 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_GZA_2147901776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.GZA!MTB"
        threat_id = "2147901776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 8d 4d ?? ff d6 ba ?? ?? ?? ?? 8d 4d 94 ff d7 8b 55 ?? 89 5d ?? 8d 4d 98 ff d6 8d 4d 94 51 8d 55 98 52}  //weight: 10, accuracy: Low
        $x_1_2 = "ChromeMetaMaskVaultData.txt" ascii //weight: 1
        $x_1_3 = "DARKCLOUD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

