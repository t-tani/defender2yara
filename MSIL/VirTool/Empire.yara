rule VirTool_MSIL_Empire_Y_2147979740_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Empire.Y"
        threat_id = "2147979740"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Empire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_DecryptedData" ascii //weight: 1
        $x_1_2 = "packetData" ascii //weight: 1
        $x_1_3 = "StartAgentJob" ascii //weight: 1
        $x_1_4 = "get_PsHostExec" ascii //weight: 1
        $x_1_5 = "GetAgentId" ascii //weight: 1
        $x_1_6 = "InvokeShellCommand" ascii //weight: 1
        $x_1_7 = "CredentialCache" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

