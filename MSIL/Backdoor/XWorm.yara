rule Backdoor_MSIL_XWorm_GNQ_2147851646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.GNQ!MTB"
        threat_id = "2147851646"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AAKKq4CKBIAAAYoKQAACgMoFAAABigqAAAK0AUAABs" wide //weight: 1
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "The car is going as fast as it can!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_MBJR_2147892579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.MBJR!MTB"
        threat_id = "2147892579"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 56 71 51 d0 b8 d0 b8 4d d0 b8 d0 b8 d0 b8 d0 b8 45 d0 b8 d0 b8 d0 b8 d0 b8 2f 2f 38 d0 b8 d0 b8 4c 67 d0 b8 d0 b8 d0 b8}  //weight: 1, accuracy: High
        $x_1_2 = "4906-bd89-4b958b0d0c1c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_KAA_2147892848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.KAA!MTB"
        threat_id = "2147892848"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 e3 81 9f 4c 6e 4a 6c 62 47 39 6a e3 81 9f e3 81 9f e3 81 9f 4d e3 81 9f e3 81 9f e3 81 9f e3 81 9f e3}  //weight: 1, accuracy: High
        $x_1_2 = {67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a e3 81 9f e3}  //weight: 1, accuracy: High
        $x_1_3 = "ShutdownEventHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XWorm_PAEW_2147913786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XWorm.PAEW!MTB"
        threat_id = "2147913786"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OxyOxyOron.BaltazaROrion" wide //weight: 2
        $x_2_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

