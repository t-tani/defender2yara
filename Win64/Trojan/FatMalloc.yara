rule Trojan_Win64_FatMalloc_GV_2147979853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FatMalloc.GV!MTB"
        threat_id = "2147979853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FatMalloc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 c1 01 39 3c 0e 74 19 88 e3 32 1c 0e 88 5c 15 00 48 83 c1 01 48 ff c2 38 c1 76 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

