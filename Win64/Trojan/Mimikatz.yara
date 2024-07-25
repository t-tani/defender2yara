rule Trojan_Win64_Mimikatz_D_2147829739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.D!MSR"
        threat_id = "2147829739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start gg.lnk" ascii //weight: 1
        $x_1_2 = "sekurlsa::logonpasswords" ascii //weight: 1
        $x_1_3 = "start procdump.exe -accepteula -ma lsass.exe lsass.dmp" ascii //weight: 1
        $x_1_4 = "expand mim mimi.exe" ascii //weight: 1
        $x_1_5 = "mimi.exestop" ascii //weight: 1
        $x_1_6 = "shaykhelislamov/Documents/Codetest/testproject/main/exec.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mimikatz_RPZ_2147902279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mimikatz.RPZ!MTB"
        threat_id = "2147902279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimikatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c6 48 89 7c 24 40 48 89 74 24 48 48 63 70 3c 8b 54 30 50 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

