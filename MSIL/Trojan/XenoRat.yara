rule Trojan_MSIL_XenoRat_RPX_2147898899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.RPX!MTB"
        threat_id = "2147898899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xeno rat client" wide //weight: 1
        $x_1_2 = "AntivirusProduct" wide //weight: 1
        $x_1_3 = "choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_4 = "nothingset" wide //weight: 1
        $x_1_5 = "schtasks.exe" wide //weight: 1
        $x_1_6 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "delete /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_XenoRat_SG_2147900905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XenoRat.SG!MTB"
        threat_id = "2147900905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cuckoomon.dll" ascii //weight: 1
        $x_1_2 = "XenoUpdateManager" wide //weight: 1
        $x_1_3 = "/query /v /fo csv" wide //weight: 1
        $x_1_4 = "xeno rat client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

