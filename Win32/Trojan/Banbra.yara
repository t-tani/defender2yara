rule Trojan_Win32_Banbra_VC_2147753560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banbra.VC!MTB"
        threat_id = "2147753560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /gorX" ascii //weight: 1
        $x_1_2 = "/gordinha.pac" ascii //weight: 1
        $x_1_3 = "sbmultimarcas.info" ascii //weight: 1
        $x_1_4 = ":\\Windows\\saad7.pac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Banbra_RPX_2147847111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banbra.RPX!MTB"
        threat_id = "2147847111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c2 6a 00 ff ca fe c0 ff c9 ff c2 fe c2 ff c8 81 c1 ?? ?? 00 00 ff d7 ff c2 ff c9 fe cb fe c2 50 fe cb ff c8 03 c1 2b cb 81 f3 ?? ?? 00 00 33 d0 03 c1 fe ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

