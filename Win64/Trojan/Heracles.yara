rule Trojan_Win64_Heracles_TMX_2147948036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Heracles.TMX!MTB"
        threat_id = "2147948036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "$85BA0DFC-746D-4292-997C-9EFAE29CA57F" ascii //weight: 4
        $x_4_2 = "C:\\webview2\\webview2\\obj\\Release\\webview2.pdb" ascii //weight: 4
        $x_1_3 = "Palindrome" ascii //weight: 1
        $x_1_4 = "Fahrenheit" ascii //weight: 1
        $x_1_5 = "GetRandomWord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Heracles_PAHU_2147979910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Heracles.PAHU!MTB"
        threat_id = "2147979910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetObject(\"winmgmts:\\\\.\\root\\cimv2" ascii //weight: 1
        $x_2_2 = "wmi.ExecQuery(\"SELECT * FROM Win32_Process WHERE Name='yupdate.exe'" ascii //weight: 2
        $x_2_3 = "schtasks /create /tn \"YandexChromeUpdateLogon\" /tr \"\\\"%s\\\"\" /sc onlogon /rl LIMITED /f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

