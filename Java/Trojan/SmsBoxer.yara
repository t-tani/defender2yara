rule Trojan_Java_SmsBoxer_B_2147914770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/SmsBoxer.B!MTB"
        threat_id = "2147914770"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "SmsBoxer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9b 00 17 1c 2a b4 00 0f a2 00 0f 1c 10 0d 9f 00 09 1c 10 0a}  //weight: 1, accuracy: High
        $x_1_2 = {1d 2b b6 00 1b a2 00 15 1c 2a 2b 1d b6 00 12 b6 00 11 60 3d 84 03 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

