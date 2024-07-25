rule Trojan_Win64_Stealerc_GPA_2147916632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealerc.GPA!MTB"
        threat_id = "2147916632"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XEBWZZk<uCEBY[rSEB_XWB_YX" ascii //weight: 1
        $x_1_2 = "dCXfDSeSBCFuY[[WXREeSUB_YX<" ascii //weight: 1
        $x_1_3 = "<mdCXfDSeSBCFuY[[WXREeSUB_YXk<dsfzwusiuy{{wxriz" ascii //weight: 1
        $x_1_4 = "xs<BWE]]_ZZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

