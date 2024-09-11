rule Ransom_Win32_Mimic_MA_2147847147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.MA!MTB"
        threat_id = "2147847147"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 c7 45 e8 00 00 00 00 68 ?? ?? 5d 00 8d 4d d8 c7 45 ec 07 00 00 00 66 89 45 d8 e8 ?? ?? fd ff 8b 45 e8 8d 55 8c 83 7d bc 08 8d 4d a8 6a 00 0f 43 4d a8 52 6a 00 68 06 01 02 00 8d 1c 00 33 c0 38 05 ?? ?? 5e}  //weight: 5, accuracy: Low
        $x_2_2 = "MIMIC_LOG.txt" wide //weight: 2
        $x_2_3 = "DontDecompileMePlease" ascii //weight: 2
        $x_2_4 = "Delete Shadow Copies" wide //weight: 2
        $x_2_5 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 2
        $x_2_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_7 = "ChaCha20 for x86, CRYPTOGAMS by" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_DA_2147905035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.DA!MTB"
        threat_id = "2147905035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mimic 4.3" wide //weight: 1
        $x_1_2 = "Delete Shadow Copies" wide //weight: 1
        $x_1_3 = "\\temp\\lock.txt" wide //weight: 1
        $x_1_4 = "powershell.exe -ExecutionPolicy Bypass \"Get-VM | Stop-VM" wide //weight: 1
        $x_1_5 = "Software\\Classes\\mimicfile\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mimic_ATZ_2147920882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mimic.ATZ!MTB"
        threat_id = "2147920882"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 65 f8 00 0f af 05 d8 6e 5f 00 8d 4d f0 33 d2 c7 45 fc e8 9a 53 00 f7 f7 03 05 d8 6e 5f 00 50}  //weight: 1, accuracy: High
        $x_1_2 = {8b 56 08 8b 45 08 c1 ea 03 c1 e8 03 2b d0}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 40 f0 0f c1 41 14 40 83 f8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

