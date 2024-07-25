rule Trojan_Win32_VBClone_RG_2147890027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBClone.RG!MTB"
        threat_id = "2147890027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBClone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 61 00 61 00 61 00 61 00 00 00 00 00 40 00 1e 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4b 00 61 00 77 00 61 00 69 00 69 00 2d 00 55 00 6e 00 69 00 63 00 6f 00 72 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBClone_CCIB_2147912477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBClone.CCIB!MTB"
        threat_id = "2147912477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBClone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0e dd 87 4a bd 0f 5a 09 49 b5 36 eb dd ad fe ba 62 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3}  //weight: 1, accuracy: High
        $x_1_2 = "\\Unicorn-" wide //weight: 1
        $x_1_3 = "cmd /c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

