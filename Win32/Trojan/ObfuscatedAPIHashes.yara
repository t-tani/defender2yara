rule Trojan_Win32_ObfuscatedAPIHashes_A_2147919388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ObfuscatedAPIHashes.A"
        threat_id = "2147919388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ObfuscatedAPIHashes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b ca 83 e1 7f 0f b6 0c 39 0f b6 [0-4] 32 c8 88 [0-8] 48 ff c2}  //weight: 10, accuracy: Low
        $x_10_2 = {0f be 11 b8 05 15 00 00 48 ff c1 85 d2 74 12 [0-2] 6b c0 21 48 8d 49 01 03 c2 0f be 51 ff 85 d2 75 ef c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

