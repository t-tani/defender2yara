rule Trojan_Win32_Runner_AR_2147743490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.AR!MTB"
        threat_id = "2147743490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "start mshta vbscript:createobject(\"wscript.shell\").run(\"\"\"C:\\kl\\ccc.cmd\"\" h\",0)(window.close)&&exit" ascii //weight: 10
        $x_10_2 = {53 54 41 52 54 20 68 74 74 70 3a 2f 2f 77 77 77 2e [0-9] 2e 74 77 2f [0-6] 2f 3f}  //weight: 10, accuracy: Low
        $x_10_3 = "c:\\kl\\ccc.cmd" ascii //weight: 10
        $x_10_4 = "C:\\kl\\ddd.cmd" ascii //weight: 10
        $x_1_5 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_6 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "RegRead" ascii //weight: 1
        $x_1_8 = "regwrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Runner_RP_2147910770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Runner.RP!MTB"
        threat_id = "2147910770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Mirc\\*.*" wide //weight: 1
        $x_1_2 = "unknowndll.pdb" ascii //weight: 1
        $x_1_3 = "Name Setup: Installing" ascii //weight: 1
        $x_1_4 = "Name Setup: Completed" ascii //weight: 1
        $x_1_5 = "ExecShell:" wide //weight: 1
        $x_1_6 = "NullsoftInst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

