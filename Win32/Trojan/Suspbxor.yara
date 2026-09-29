rule Trojan_Win32_Suspbxor_ZZ_2147979206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.ZZ!MTB"
        threat_id = "2147979206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-bxor" wide //weight: 10
        $x_10_2 = "user32.dll" wide //weight: 10
        $x_1_3 = ";[rEfLeCTioN.AsSeMbLy]::lOaD($" wide //weight: 1
        $x_1_4 = "+[ChaR]" wide //weight: 1
        $x_1_5 = "iex([TExT.ENCodiNg]::UTF8.GetString($" wide //weight: 1
        $x_1_6 = "[Io.fILE]::ReadAllBytes($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

