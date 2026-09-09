rule Trojan_Win32_ClixkFix_NF_2147977830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NF!MTB"
        threat_id = "2147977830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iex $" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-32] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "irm " wide //weight: 1
        $x_1_4 = "param($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NG_2147977831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NG!MTB"
        threat_id = "2147977831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Process powershell -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File'" wide //weight: 1
        $x_1_2 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-32] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NI_2147977832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NI!MTB"
        threat_id = "2147977832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "('powershell -ep bypass -f '+[char]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NN_2147977834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NN!MTB"
        threat_id = "2147977834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ";powershell -E $" wide //weight: 1
        $x_1_2 = ";AntiBOT Check" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

