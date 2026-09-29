rule HackTool_Linux_OLoader_A_2147979224_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/OLoader.A"
        threat_id = "2147979224"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "OLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O_TMPFILE + execveat" ascii //weight: 1
        $x_1_2 = "spoof_name: argv[0] of loaded process (default: python3)" ascii //weight: 1
        $x_1_3 = "big_key not supported (CONFIG_BIG_KEYS not set)" ascii //weight: 1
        $x_1_4 = "%s stage  <elf>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

