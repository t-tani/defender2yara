rule Trojan_Win64_ShellcodeInject_ME_2147907845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.ME!MTB"
        threat_id = "2147907845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 06 c1 e0 02 2b c8 41 8d 47 ff ff c1 42 32 1c 19 41 8b c9 42 88 1c 18}  //weight: 1, accuracy: High
        $x_1_2 = "shell.bin" ascii //weight: 1
        $x_1_3 = "Inject shellcode!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_RCB_2147908251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.RCB!MTB"
        threat_id = "2147908251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go-shellcode/shellcode" ascii //weight: 1
        $x_1_2 = "Available actions are: 'Encrypt payload', 'Decrypt payload', and 'Descrip and Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_MKB_2147909278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.MKB!MTB"
        threat_id = "2147909278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 0d ea 1a 10 00 48 89 4c 24 68 48 c7 44 24 70 02 00 00 00 48 c7 84 24 88 00 00 00 00 00 00 00 48 8d 4c 24 48 48 89 4c 24 78 48 c7 84 24 80 00 00 00 02 00 00 00 48 8d 4c 24 68 48 89 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_ADG_2147918453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.ADG!MTB"
        threat_id = "2147918453"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e1 20 83 b8 ed 33 ca 8b d1 d1 e9 41 23 d5 f7 da 81 e2 20 83 b8 ed 33 d1 41 0f b6 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_FEM_2147920231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.FEM!MTB"
        threat_id = "2147920231"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 89 6c 24 50 48 c7 44 24 58 0f 00 00 00 c6 44 24 40 00 49 8b 46 10 48 3b c6 0f 82 2f 01 00 00 48 2b c6 41 b8 02 00 00 00 49 3b c0 4c 0f 42 c0 49 8b c6 49 83 7e 18 10 72 03 49 8b 06}  //weight: 5, accuracy: High
        $x_1_2 = "Usage: %s <process_name> <hex_string>" ascii //weight: 1
        $x_1_3 = "inejct\\x64\\Release\\inejct.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_OKZ_2147920973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.OKZ!MTB"
        threat_id = "2147920973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 48 b8 f1 f0 f0 f0 f0 f0 f0 f0 45 03 d4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 0b 41 88 01 4d 03 cc 41 81 fa 00 7a 3c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_OLE_2147921716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.OLE!MTB"
        threat_id = "2147921716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 79 10 48 8b df}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 0c 42 88 4c 04 60 48 ff c0 66 44 39 3c 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_DA_2147924362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.DA!MTB"
        threat_id = "2147924362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 0b 40 30 f0 41 88 04 ?? 0f b6 44 0b 01 40 30 f0 41 88 44 ?? 01 0f b6 44 0b 02 40 30 f0 41 88 44 ?? 02 0f b6 44 0b 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {41 0f b6 04 ?? 40 30 f0 41 88 04 ?? 41 0f b6 44 ?? 01 40 30 f0 41 88 44 ?? 01 41 0f b6 44 ?? 02 40 30 f0 41 88 44 ?? 02 41 0f b6 44 ?? 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75}  //weight: 10, accuracy: Low
        $x_1_3 = "shellcode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeInject_RFAK_2147926153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.RFAK!MTB"
        threat_id = "2147926153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/xperience.bin" ascii //weight: 1
        $x_1_2 = "xpcs.tools" ascii //weight: 1
        $x_1_3 = "notepad.exe" ascii //weight: 1
        $x_1_4 = "alfRemoteLoader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_MP_2147929684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.MP!MTB"
        threat_id = "2147929684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 71 da 00 00 33 c9 8b f8 ff 15 2f da 00 00 48 8d 4c 24 48 ff 15 cc db 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_ASD_2147930019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.ASD!MTB"
        threat_id = "2147930019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msedgewhite.rtz" ascii //weight: 1
        $x_1_2 = "Failed to load and execute shellcode" ascii //weight: 1
        $x_1_3 = "Dll4.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

