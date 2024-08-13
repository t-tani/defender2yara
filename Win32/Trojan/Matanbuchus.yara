rule Trojan_Win32_Matanbuchus_QW_2147806069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.QW!MTB"
        threat_id = "2147806069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 e4 bb 03 00 00 00 33 5d 08 83 c3 37 2b 5d 10 83 c3 68}  //weight: 10, accuracy: High
        $x_10_2 = {83 c6 57 81 ee 54 6b b6 93 33 75 1c 81 c6 30 e2 71 d9}  //weight: 10, accuracy: High
        $x_3_3 = "SzToWz" ascii //weight: 3
        $x_3_4 = "CmBuildFullPathFromRelativeW" ascii //weight: 3
        $x_3_5 = "Qm7kljQTRKhBcOve3JPpwE4XOoZcy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_DA_2147918562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.DA!MTB"
        threat_id = "2147918562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "B:\\LoadDll6\\LoadDll\\result\\Release\\libcurl.pdb" ascii //weight: 20
        $x_1_2 = "DllInitialize" ascii //weight: 1
        $x_1_3 = "DllInstall" ascii //weight: 1
        $x_1_4 = "RegisterDll" ascii //weight: 1
        $x_1_5 = "ThreadFunction" ascii //weight: 1
        $x_1_6 = "curl_easy_cleanup" ascii //weight: 1
        $x_1_7 = "curl_easy_init" ascii //weight: 1
        $x_1_8 = "curl_easy_perform" ascii //weight: 1
        $x_1_9 = "curl_easy_setopt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

