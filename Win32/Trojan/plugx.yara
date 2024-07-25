rule Trojan_Win32_plugx_2147841657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/plugx.psyB!MTB"
        threat_id = "2147841657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "plugx"
        severity = "Critical"
        info = "psyB: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {33 d2 8a d4 89 15 94 e5 42 00 8b c8 81 e1 ff 00 00 00 89 0d 90 e5 42 00 c1 e1 08 03 ca 89 0d 8c e5 42 00 c1 e8 10 a3 88 e5 42 00 33 f6 56}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_plugx_2147842174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/plugx.psyC!MTB"
        threat_id = "2147842174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "plugx"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {07 08 9a 0d 09 6f 15 00 00 0a 72 01 00 00 70 28 16 00 00 0a 2c 28 09 6f 17 00 00 0a 20 0e 00 02 00 12 00 28 01 00 00 06 2d 01 2a 06 28 03 00 00 06 26 09 6f 17 00 00 0a 28 02 00 00 06 26 08 17 58 0c 08}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

