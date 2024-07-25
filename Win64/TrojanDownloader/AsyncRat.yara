rule TrojanDownloader_Win64_AsyncRat_CEB_2147845754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRat.CEB!MTB"
        threat_id = "2147845754"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 0f 7f 4c 24 ?? 66 c7 44 24 [0-4] 66 0f 6f 0d ?? 20 00 00 f3 0f 7f 44 24 ?? c6 44 24 ?? ?? f3 0f 7f 4c 24 [0-3] c7 44 24 [0-10] 48 c7 44 24 20 00 00 00 00 ff}  //weight: 5, accuracy: Low
        $x_1_2 = "\\x64\\Release\\WechatAnd.pdb" ascii //weight: 1
        $x_1_3 = "\\code.bin" wide //weight: 1
        $x_1_4 = "WindowsProject1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

