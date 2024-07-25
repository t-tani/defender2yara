rule Backdoor_Win32_Rifdoor_A_2147731953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rifdoor.A!bit"
        threat_id = "2147731953"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifdoor"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 80 30 0f 41 8b c1 38 19 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = "Troy Source Code\\tcp1st\\rifle\\Release\\rifle.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rifdoor_B_2147734116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rifdoor.B!bit"
        threat_id = "2147734116"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifdoor"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 80 30 0f 41 8b c1 38 19 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\ProgramData\\AhnLab\\AhnSvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rifdoor_RPZ_2147833390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rifdoor.RPZ!MTB"
        threat_id = "2147833390"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"C:\\ProgramData\\Update\\Wwansvc.exe\" /run" ascii //weight: 1
        $x_1_2 = "/c del /q \"%s\" >> NUL" ascii //weight: 1
        $x_1_3 = "rifle.pdb" ascii //weight: 1
        $x_1_4 = "Window Update" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_7 = "WaitForSingleObject" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rifdoor_GFM_2147842285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rifdoor.GFM!MTB"
        threat_id = "2147842285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce 8b b5 ?? ?? ?? ?? c1 e9 18 c1 ea 10 22 ca 8a 95 ?? ?? ?? ?? 32 d9 8b 8d ?? ?? ?? ?? 22 d1 32 da 8d 94 3d ?? ?? ?? ?? 32 1c 16 8d 34 85 ?? ?? ?? ?? 33 f0 03 f6 33 f0 32 d8 83 e6 f0 c1 e0 04 33 f0 c1 e1 18 0b 8d ?? ?? ?? ?? c1 e6 14 0b b5 ?? ?? ?? ?? 47 88 1a 89 b5 ?? ?? ?? ?? 8b c1 3b bd ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
        $x_1_2 = "URLOpenBlockingStream" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "\\ProgramData\\Update\\WwanSvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

