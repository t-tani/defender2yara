rule Ransom_Win32_Redlock_AMTB_2147979589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Redlock!AMTB"
        threat_id = "2147979589"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-C000-PClock" ascii //weight: 1
        $x_1_2 = "C:\\Documents and Settings\\Administrator\\cl_data_#.bak" ascii //weight: 1
        $x_1_3 = "Your files are locked !.txt" ascii //weight: 1
        $x_1_4 = "Thanks, your payment is confirmed!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

