rule Trojan_Win32_ZLoader_RZ_2147758548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.RZ!MTB"
        threat_id = "2147758548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\anger\\fit\\Shell\\Far\\Women\\deal\\fire.pdb" ascii //weight: 1
        $x_1_2 = "fire.dll" ascii //weight: 1
        $x_1_3 = "Chief" ascii //weight: 1
        $x_1_4 = "rpr/dnu8itecpo6 cnvmrlnEno" ascii //weight: 1
        $x_1_5 = "h60oedVidmr3/w iiR5dn6rnlSVoeymo brS" ascii //weight: 1
        $x_1_6 = "oncc3u610rea iexim5wmer1o 0daWi.M0kibi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_DA_2147767279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.DA!MTB"
        threat_id = "2147767279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\IXP000.TMP\\" ascii //weight: 1
        $x_1_2 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = "cmd /c tim.bat" ascii //weight: 1
        $x_1_5 = "Command.com /c %s" ascii //weight: 1
        $x_1_6 = "GetTempPathA" ascii //weight: 1
        $x_1_7 = "DoInfInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZLoader_A_2147777757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.A"
        threat_id = "2147777757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 84 c0 74 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 [0-30] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 55 08 89 d0 35 [0-8] 0f af ca}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 89 d0 35 [0-8] 80 cb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 70 03 00 00 8b ?? ?? 8b ?? ?? 68 6f 03 00 00 [0-8] 83 c4 04 89 ?? 89}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 ff d0 85 c0 14 00 [0-8] 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ZLoader_A_2147777758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoader.A!!ZLoader.A"
        threat_id = "2147777758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "ZLoader: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 84 c0 74 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 [0-30] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 55 08 89 d0 35 [0-8] 0f af ca}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 89 d0 35 [0-8] 80 cb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 70 03 00 00 8b ?? ?? 8b ?? ?? 68 6f 03 00 00 [0-8] 83 c4 04 89 ?? 89}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 ff d0 85 c0 14 00 [0-8] 68 ?? ?? ?? ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

