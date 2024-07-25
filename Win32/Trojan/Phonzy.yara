rule Trojan_Win32_Phonzy_MA_2147809048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phonzy.MA!MTB"
        threat_id = "2147809048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phonzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHaiMoneyHost.dll" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide //weight: 1
        $x_1_3 = "shamhHost" wide //weight: 1
        $x_1_4 = "DelayedAutoStart" wide //weight: 1
        $x_1_5 = "ftp@example.com" ascii //weight: 1
        $x_1_6 = "anonymous" ascii //weight: 1
        $x_1_7 = "Set-Cookie:" ascii //weight: 1
        $x_1_8 = "blank" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "CryptEncrypt" ascii //weight: 1
        $x_1_11 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

