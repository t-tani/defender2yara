rule Trojan_Win32_Reverseshell_NT_2147979205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reverseshell.NT!MTB"
        threat_id = "2147979205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-60] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".TCPClient(" wide //weight: 1
        $x_1_3 = ".GetStream()" wide //weight: 1
        $x_1_4 = "[byte[]]$" wide //weight: 1
        $x_1_5 = ").GetBytes($" wide //weight: 1
        $x_1_6 = "Write($" wide //weight: 1
        $x_1_7 = "Length);$" wide //weight: 1
        $n_10_8 = "127.0.0.1" wide //weight: -10
        $n_10_9 = "localhost" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

