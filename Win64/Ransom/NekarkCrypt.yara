rule Ransom_Win64_NekarkCrypt_PA_2147918022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NekarkCrypt.PA!MTB"
        threat_id = "2147918022"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NekarkCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\README.txt" ascii //weight: 1
        $x_1_2 = ".pythonanywhere.com" ascii //weight: 1
        $x_4_3 = "Your files have been encrypted" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
