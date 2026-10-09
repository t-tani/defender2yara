rule Trojan_MSIL_ShelbyLoader_DA_2147979870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShelbyLoader.DA!MTB"
        threat_id = "2147979870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShelbyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "aHR0cHM6Ly9naXRodWIuY29tL2hvc3NlaW5hYmRvbGkvbXktanNvbi1zdG9yYWdlL3Jhdy9yZWZzL2hlYWRzL21haW4vU2V0dGluZ3NTeW5jLmV4ZQ==" wide //weight: 10
        $x_10_2 = "https://sabzoom.com/SettingsSync.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_ShelbyLoader_AB_2147980025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShelbyLoader.AB!MTB"
        threat_id = "2147980025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShelbyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 1c 00 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a fe 0e 00 00 28 ?? 00 00 06 fe 0e 01 00 28 ?? 00 00 06 fe 0e 02 00 fe 0c 00 00 28}  //weight: 2, accuracy: Low
        $x_1_2 = {fe 0e 00 00 20 00 00 00 00 fe 0e 01 00 38 8d 00 00 00 fe 0c 00 00 fe 0c 01 00 9a 28 ?? 00 00 06 20 38 00 00 00 6f ?? 00 00 0a fe 0e 02 00 fe 0c 02 00 14 28 ?? 00 00 0a 39 54 00 00 00 fe 0c 02 00 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

