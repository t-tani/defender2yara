rule Trojan_Win64_SteamStealer_AAA_2147973529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SteamStealer.AAA!AMTB"
        threat_id = "2147973529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SteamStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\ConsoleApplication6\\x64\\Release\\Application.pdb" ascii //weight: 15
        $x_15_2 = "\\ConsoleApplication6\\x64\\Release\\ConsoleApplication6.pdb" ascii //weight: 15
        $x_2_3 = "SOFTWARE\\WOW6432Node\\Valve\\Steam" wide //weight: 2
        $x_2_4 = "taskkill /F /IM steam.exe" wide //weight: 2
        $x_2_5 = "\\steam.exe" ascii //weight: 2
        $x_2_6 = "\\config\\loginusers.vdf" ascii //weight: 2
        $x_2_7 = "\\config\\localconfig.vdf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 5 of ($x_2_*))) or
            ((2 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_SteamStealer_PA_2147977671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SteamStealer.PA!MTB"
        threat_id = "2147977671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SteamStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=eval(" ascii //weight: 1
        $x_1_2 = "JSON.stringify(" ascii //weight: 1
        $x_3_3 = {68 74 74 70 3a 2f 2f 31 32 30 2e 34 38 2e 31 35 36 2e 31 37 2f [0-8] 2e 70 68 70}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

