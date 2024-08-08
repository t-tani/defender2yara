rule Trojan_Win32_GhostRat_BAK_2147843973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.BAK!MTB"
        threat_id = "2147843973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 f8 99 f7 7d ec 8b 45 10 8a 0c 10 88 4d f3 0f be 55 ff 0f be 45 f3 33 d0 88 55 ff 8b 4d d0 51 6a 01 6a 01 8d 55 ff 52 e8 8f 89 02 00 83 c4 10 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 5, accuracy: High
        $x_5_2 = {8b 4d bc 89 4d e4 6a 04 68 00 10 00 00 8b 55 e4 52 6a 00 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRat_EH_2147846472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.EH!MTB"
        threat_id = "2147846472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "172.16.1,10.102.197,10.85.190,10.102.107,10.37.239,10.24.182,10.71.129,10.9.174" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "360tray.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_5 = "bfsvc.exe" wide //weight: 1
        $x_1_6 = "/c schtasks /create /sc onlogon /tn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRat_RP_2147911516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.RP!MTB"
        threat_id = "2147911516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6gkIBfkS+qY=" ascii //weight: 1
        $x_1_2 = "tNC2pg==" ascii //weight: 1
        $x_1_3 = "Sbrjar Kbskb" ascii //weight: 1
        $x_1_4 = "Gwogwo Hxfwofwo Qxogxogx Phxp" ascii //weight: 1
        $x_1_5 = "Dtldtlct Mdumduldu Mevmeum Fvnfvnev Ofw" ascii //weight: 1
        $x_1_6 = "266b547cc0ad48a44c180346fd5a4619" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRat_ZL_2147914669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.ZL!MTB"
        threat_id = "2147914669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 e9 f5 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRat_IJ_2147915524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.IJ!MTB"
        threat_id = "2147915524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c7 01 9e 68 10 00 00 c7 40 0c 00 00 00 00 c7 40 10 00 00 00 00 89 58 04 c7 00 01 00 00 00 89 70 08 c1 f8 0c 8d 96 80 10 00 00 89 f1 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GhostRat_AGH_2147918283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRat.AGH!MTB"
        threat_id = "2147918283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 ff 54 24 4c 8b 84 24 8c 00 00 00 ff 70 20 83 c0 38 50 ff b4 24 9c 00 00 00 ff 54 24 54 8b 84 24 8c 00 00 00 6a 04 56 ff 70 2c 53 ff 54 24 38 8b 8c 24 8c 00 00 00 89 84 24 98 00 00 00 ff 71 2c 50}  //weight: 3, accuracy: High
        $x_2_2 = "176.221.16.167" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

