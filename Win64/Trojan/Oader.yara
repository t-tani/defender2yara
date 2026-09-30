rule Trojan_Win64_Oader_NP_2147979493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oader.NP!MTB"
        threat_id = "2147979493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 65 64 65 6e 74 69 61 6c 73 [0-46] 2e 6a 73 65}  //weight: 2, accuracy: Low
        $x_2_2 = "AppData%\\Microsoft\\Credentials\\Wscript.exe" ascii //weight: 2
        $x_2_3 = "Hide" ascii //weight: 2
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "ClipboardData" ascii //weight: 1
        $x_2_6 = "sleep" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

