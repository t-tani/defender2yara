rule Trojan_MSIL_ZillaCrypt_NG_2147926320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZillaCrypt.NG!MTB"
        threat_id = "2147926320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZillaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {58 11 07 59 17 5b 6a 69 0c 2b 19 07 03 17}  //weight: 2, accuracy: High
        $x_1_2 = {00 08 16 32 14 09 16 32 10 09 08 31 0c 08 11 04 8e 69 fe 04 16 fe 01 2b 01}  //weight: 1, accuracy: High
        $x_1_3 = "94B35817-E9CA-477A-9F42-1A2184D47F00" ascii //weight: 1
        $x_1_4 = "TeZFfjD34A7jvG75o6Nq9C9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
