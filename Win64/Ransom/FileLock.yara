rule Ransom_Win64_FileLock_AB_2147977896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileLock.AB!MTB"
        threat_id = "2147977896"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 2
        $x_2_2 = "After payment, you will receive the decryption key." ascii //weight: 2
        $x_2_3 = "Global\\{D8F7A3B1-2C4E-5F6A-7B8C-9D0E1F2A3B4C}" wide //weight: 2
        $x_2_4 = "To decrypt, send $100 USD worth of BTC to" ascii //weight: 2
        $x_2_5 = "DISCORD TAG = @7dsa" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

