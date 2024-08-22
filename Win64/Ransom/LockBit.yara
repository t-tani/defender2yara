rule Ransom_Win64_LockBit_B_2147919350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockBit.B"
        threat_id = "2147919350"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.!T" ascii //weight: 1
        $x_1_2 = {99 b5 5b 9b}  //weight: 1, accuracy: High
        $x_1_3 = {09 a6 52 d2}  //weight: 1, accuracy: High
        $x_1_4 = {cc bf 63 aa}  //weight: 1, accuracy: High
        $x_1_5 = {1d aa a3 3c}  //weight: 1, accuracy: High
        $x_1_6 = {5b 8d 47 89}  //weight: 1, accuracy: High
        $x_1_7 = {c5 0f 95 bc}  //weight: 1, accuracy: High
        $x_1_8 = {23 32 a1 6f}  //weight: 1, accuracy: High
        $x_1_9 = "XpSimulateParanoid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

