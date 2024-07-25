rule Ransom_Win64_LockFile_MBK_2147795409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.MBK!MTB"
        threat_id = "2147795409"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winsta0\\default" ascii //weight: 1
        $x_1_2 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "The price of decryption software is" ascii //weight: 1
        $x_1_4 = "We only accept Bitcoin payment" ascii //weight: 1
        $x_1_5 = {52 00 45 00 41 00 44 00 4d 00 45 00 2d 00 46 00 49 00 4c 00 45 00 [0-32] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 41 44 4d 45 2d 46 49 4c 45 [0-32] 2e 68 74 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

