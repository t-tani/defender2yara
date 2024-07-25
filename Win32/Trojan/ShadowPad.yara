rule Trojan_Win32_ShadowPad_A_2147723094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.A!dha"
        threat_id = "2147723094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "D:\\tortoiseSVN\\nsc5\\bin\\Release\\nssock2.pdb" ascii //weight: 100
        $x_100_2 = "###ERROR###" ascii //weight: 100
        $x_100_3 = {6a 40 68 00 10 00 00 68 [0-2] 00 00 6a 00 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_E_2147723170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.E!dha"
        threat_id = "2147723170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 0f 32 d0 88 11 8b d0 69 c0 ?? ?? ?? ?? c1 ea 10 69 d2}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 04 55 89 e5 81 ec 00 04 00 00 51 68 ?? ?? 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

