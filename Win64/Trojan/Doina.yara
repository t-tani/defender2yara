rule Trojan_Win64_Doina_ND_2147900480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.ND!MTB"
        threat_id = "2147900480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {78 0f 3b 35 60 af 02 00 73 07 b8 ?? ?? ?? ?? eb 02 33 c0 85 c0 75 33 41 c6 41 38 ?? 41 83 61 34}  //weight: 5, accuracy: Low
        $x_1_2 = "DeleteFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_CCHI_2147902002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.CCHI!MTB"
        threat_id = "2147902002"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/output" ascii //weight: 1
        $x_1_2 = "/Login Data" ascii //weight: 1
        $x_1_3 = "/History" ascii //weight: 1
        $x_1_4 = "/Web Data" ascii //weight: 1
        $x_1_5 = "/network/cookies" ascii //weight: 1
        $x_1_6 = "/logindata" ascii //weight: 1
        $x_1_7 = "/webdata" ascii //weight: 1
        $x_1_8 = "/cookie" ascii //weight: 1
        $x_1_9 = "/session" ascii //weight: 1
        $x_1_10 = "/log" ascii //weight: 1
        $x_1_11 = "/autofill" ascii //weight: 1
        $x_1_12 = "chat_id" ascii //weight: 1
        $x_1_13 = "/sendDocument" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_CH_2147903155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.CH!MTB"
        threat_id = "2147903155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Users\\Public\\winRes\\qr.bmp" wide //weight: 2
        $x_1_2 = "185.216.68.72" wide //weight: 1
        $x_1_3 = "185.246.90.200" wide //weight: 1
        $x_1_4 = "files/test.exe" wide //weight: 1
        $x_1_5 = "Public\\Videos\\winRes\\aaa.exe" wide //weight: 1
        $x_1_6 = "YOU HAVE BEEN BETRAYED!" wide //weight: 1
        $x_1_7 = "your criminal activities are linked to your real identity!" wide //weight: 1
        $x_1_8 = "Thats why we have compromised your device and" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

