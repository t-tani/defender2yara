rule Trojan_Win32_Bayrob_SIB_2147805771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.SIB!MTB"
        threat_id = "2147805771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 89 da ?? [0-96] 89 11 83 c1 04 [0-48] 83 ea ?? [0-10] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 db e9 e3 [0-48] 8b 8a ?? ?? ?? ?? [0-16] 33 1c 8f [0-160] 83 c2 04 [0-10] 39 d0 [0-10] 0f 84 ?? ?? ?? ?? [0-80] e9}  //weight: 1, accuracy: Low
        $x_1_3 = {89 74 24 04 89 3c 24 [0-48] e8 ?? ?? ?? ?? [0-48] 89 3c 24 [0-10] e8 ?? ?? ?? ?? [0-64] 33 1d 69 76 43 00 [0-170] b8 20 51 43 00 29 d8 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARA_2147902715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARA!MTB"
        threat_id = "2147902715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 10 30 11 41 40 3b cf 75 f6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARA_2147902715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARA!MTB"
        threat_id = "2147902715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 39 00 74 ?? 80 31 1a 41 eb f5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARAQ_2147908940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARAQ!MTB"
        threat_id = "2147908940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 30 06 ff 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

