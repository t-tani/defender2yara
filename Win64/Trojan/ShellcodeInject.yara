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

