rule Trojan_MSIL_DelShad_ABFA_2147927590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DelShad.ABFA!MTB"
        threat_id = "2147927590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 02 8e 69 5d 7e ?? 00 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? 00 06 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DelShad_AC_2147979511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DelShad.AC!MTB"
        threat_id = "2147979511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" wide //weight: 2
        $x_2_2 = "bcdedit /set {default} recoveryenabled No" wide //weight: 2
        $x_2_3 = "Disable-ComputerRestore -Drive 'C:\\'" wide //weight: 2
        $x_2_4 = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /f" wide //weight: 2
        $x_2_5 = "SYSTEM\\CurrentControlSet\\Services\\kbdclass" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

