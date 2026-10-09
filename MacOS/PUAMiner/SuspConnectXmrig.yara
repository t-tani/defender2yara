rule PUAMiner_MacOS_SuspConnectXmrig_A_496346_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUAMiner:MacOS/SuspConnectXmrig.A"
        threat_id = "496346"
        type = "PUAMiner"
        platform = "MacOS: "
        family = "SuspConnectXmrig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl " wide //weight: 1
        $x_3_2 = "github.com/xmrig/xmrig/releases/download/" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

