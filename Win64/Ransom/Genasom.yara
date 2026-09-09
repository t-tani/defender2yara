rule Ransom_Win64_Genasom_AR_2147754406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Genasom.AR!MTB"
        threat_id = "2147754406"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt" ascii //weight: 1
        $x_10_2 = "C:/Users/windows/go/src/VashRansomwarev2/Encrypt.go" ascii //weight: 10
        $x_1_3 = "decrypt all your files after paying the ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Genasom_NE_2147977775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Genasom.NE!MTB"
        threat_id = "2147977775"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "self_destruct.bW" ascii //weight: 2
        $x_2_2 = "DARKMATTER" ascii //weight: 2
        $x_1_3 = "free space after encryption" ascii //weight: 1
        $x_1_4 = "Override default credentials" ascii //weight: 1
        $x_1_5 = "remote directories" ascii //weight: 1
        $x_1_6 = "Enable self-delete" ascii //weight: 1
        $x_2_7 = "Encrypt local files only, don't delete executable" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

