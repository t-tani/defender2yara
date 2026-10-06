rule VirTool_Win64_Empire_A_2147788333_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.A"
        threat_id = "2147788333"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stage1response" ascii //weight: 1
        $x_1_2 = "stage2Response" ascii //weight: 1
        $x_1_3 = "DotNetEmpire" ascii //weight: 1
        $x_1_4 = "StartAgentJob" ascii //weight: 1
        $x_1_5 = "EmpireStager" ascii //weight: 1
        $x_1_6 = "set_EnablePrivileges" ascii //weight: 1
        $x_1_7 = "get_DefaultCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_D_2147844991_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.D!MTB"
        threat_id = "2147844991"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-join[Char[]](& $R $data ($IV+$K))|IEX" ascii //weight: 1
        $x_1_2 = "$_-bxor$s[($s[$i]+$s[$h])%256]}}" ascii //weight: 1
        $x_1_3 = "=[system.text.encoding]::ascii.getbytes('" ascii //weight: 1
        $x_1_4 = "$ser+$t" ascii //weight: 1
        $x_1_5 = "Convert]::FromBase64String(" ascii //weight: 1
        $x_1_6 = "%{$J=($J+$S[$_]+$K[$_%$K.Count])%256" ascii //weight: 1
        $x_1_7 = ".proxy=[system.net.webrequest]::defaultwebproxy;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_G_2147895058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.G"
        threat_id = "2147895058"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 8b 40 ?? 48 83 e8 ?? 33 d2 b9 02}  //weight: 1, accuracy: Low
        $x_1_2 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 ff c0}  //weight: 1, accuracy: Low
        $x_1_3 = {40 55 57 48 81 ec ?? ?? 00 00 48 8d 6c 24 ?? 48 8d 7c 24 ?? b9 ?? ?? ?? ?? b8 cc cc cc cc f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_Q_2147971442_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.Q"
        threat_id = "2147971442"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 6c 24 28 41 b9 40 00 00 00 31 c9 41 b8 00 30 00 00 4c 89 e2 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 da 45 31 c0 31 c9 ff 15 ?? ?? ?? ?? 48 89 c3 48 85 c0 ?? ?? 48 89 c1 ff 15 ?? ?? ?? ?? 48 89 d9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_V_2147978920_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.V"
        threat_id = "2147978920"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 31 c9 41 b8 00 30 00 00 ?? 89 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 da 45 31 c0 31 c9 ff 15 ?? ?? ?? ?? 48 89 c3 48 85 c0 ?? ?? 48 89 c1 ff 15 ?? ?? ?? ?? 48 89 d9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Empire_T_2147979739_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Empire.T"
        threat_id = "2147979739"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 4c 6f 61 64 4c 69 62 72 48}  //weight: 1, accuracy: High
        $x_1_2 = {6b 00 65 00 [0-6] 72 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {65 48 8b 04 25 60 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 24 26 48 ba 45 00 4c 00 33 00 32 00 66 c7 44 24 3e 00 00 48 89 54 24 2e 48 ba 2e 00 44 00 4c 00 4c 00 48 89 54 24 36 31 d2 66 44 8b 44 14 0c 66 45 85 c0 74 30 66 45 8b 14 11 66 45 39 c2 74 08 66 44 3b 54 14 26 75 13 48 83 c2 02 eb db 4c 8b 48 50 4d 85 c9 0f 85 60 ff ff ff 48 8b 00 4c 39 d8 75 eb 31 c9 48 89 c8 48 83 c4 48 c3 8b 41 3c 49 89 d1 8b 94 01 88 00 00 00 31 c0 85 d2 74}  //weight: 1, accuracy: High
        $x_1_5 = {48 ba 6b 00 65 00 72 00 6e 00 66 c7 44 24 24 00 00 48 8b 48 20 48 89 54 24 0c 48 ba 65 00 6c 00 33 00 32 00 48 89 54 24 14 48 ba 2e 00 64 00 6c 00 6c 00 48 89 54 24 1c 48 ba 4b 00 45 00 52 00 4e 00 48 89 54 24 26 48 ba 45 00 4c 00 33 00 32 00 66 c7 44 24 3e 00 00 48 89 54 24 2e 48 ba 2e 00 44 00 4c 00 4c 00 48 89 54 24 36 31 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

