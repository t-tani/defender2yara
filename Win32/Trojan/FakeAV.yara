rule Trojan_Win32_FakeAV_AG_2147819838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AG!MTB"
        threat_id = "2147819838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bcdedit.exe -set" ascii //weight: 2
        $x_2_2 = "ZSTSIGNING ON" ascii //weight: 2
        $x_2_3 = "JSDA.EXE" wide //weight: 2
        $x_2_4 = "Pro23ctVersion" wide //weight: 2
        $x_2_5 = "W_ aH" ascii //weight: 2
        $x_2_6 = "D7togE" ascii //weight: 2
        $x_2_7 = "hutdownPtil" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_AK_2147896090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AK!MTB"
        threat_id = "2147896090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dump of offset" ascii //weight: 1
        $x_1_2 = "EIP=" ascii //weight: 1
        $x_1_3 = "EFL=" ascii //weight: 1
        $x_1_4 = "WriteConsoleOutputCharacterA" ascii //weight: 1
        $x_1_5 = "WriteConsoleOutputAttribute" ascii //weight: 1
        $x_1_6 = "FlushConsoleInputBuffer" ascii //weight: 1
        $x_1_7 = "0C0M0S0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_ARAA_2147906264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.ARAA!MTB"
        threat_id = "2147906264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 00 74 0a 8a 06 32 c3 88 06 46 49 eb f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

