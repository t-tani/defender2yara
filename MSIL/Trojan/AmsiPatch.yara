rule Trojan_MSIL_AmsiPatch_DA_2147921352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiPatch.DA!MTB"
        threat_id = "2147921352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiPatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Injecting VM hook code" ascii //weight: 100
        $x_1_2 = "SophosAmsiProvider.dll" ascii //weight: 1
        $x_1_3 = "com_antivirus.dll" ascii //weight: 1
        $x_1_4 = "Malwarebytes" ascii //weight: 1
        $x_1_5 = "[eax+ebx]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

