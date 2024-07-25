rule Ransom_Win32_CylanceLoader_IJ_2147915595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CylanceLoader.IJ!MTB"
        threat_id = "2147915595"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CylanceLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 30 22 40 00 6a 01 33 f6 56 ff 15 2c 20 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

