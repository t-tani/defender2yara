rule Trojan_Win64_AntiVM_NV_2147977665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AntiVM.NV!MTB"
        threat_id = "2147977665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AntiVM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_2_3 = "ncrthost.dll" ascii //weight: 2
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "vboxservice.exe" ascii //weight: 1
        $x_1_6 = "vmwareuser.exe" ascii //weight: 1
        $x_1_7 = "safemode-encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

