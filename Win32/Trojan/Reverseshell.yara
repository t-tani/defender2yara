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

rule Trojan_Win32_Reverseshell_ZG_2147979968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reverseshell.ZG!MTB"
        threat_id = "2147979968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TcpClient" wide //weight: 1
        $x_1_2 = ".ConnectAsync" wide //weight: 1
        $x_1_3 = "[Text.Encoding]:::ASCII.GetBytes" wide //weight: 1
        $x_1_4 = "[Environment" wide //weight: 1
        $x_1_5 = ".Write($" wide //weight: 1
        $n_50_6 = "127.0.0.1" wide //weight: -50
        $n_50_7 = "localhost" wide //weight: -50
        $n_50_8 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Reverseshell_ZH_2147979969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reverseshell.ZH!MTB"
        threat_id = "2147979969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TcpClient" wide //weight: 1
        $x_1_2 = "IO.StreamReader($" wide //weight: 1
        $x_1_3 = "]::UserName" wide //weight: 1
        $x_1_4 = "]::MachineName" wide //weight: 1
        $x_1_5 = "Invoke-Expression $" wide //weight: 1
        $x_1_6 = ".ConnectAsync(" wide //weight: 1
        $x_1_7 = "Environment" wide //weight: 1
        $n_50_8 = "127.0.0.1" wide //weight: -50
        $n_50_9 = "localhost" wide //weight: -50
        $n_50_10 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Reverseshell_ZI_2147979970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reverseshell.ZI!MTB"
        threat_id = "2147979970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TcpClient" wide //weight: 1
        $x_1_2 = ".ConnectAsync(" wide //weight: 1
        $x_1_3 = "::UserName" wide //weight: 1
        $x_1_4 = "::MachineName" wide //weight: 1
        $x_1_5 = "Environment" wide //weight: 1
        $n_50_6 = "127.0.0.1" wide //weight: -50
        $n_50_7 = "localhost" wide //weight: -50
        $n_50_8 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

