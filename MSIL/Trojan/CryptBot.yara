rule Trojan_MSIL_CryptBot_PSJA_2147844777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptBot.PSJA!MTB"
        threat_id = "2147844777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cevenolAraceae" ascii //weight: 1
        $x_1_2 = "infestsAraceae" ascii //weight: 1
        $x_1_3 = "ReadAsyncEUCJPEncoding" ascii //weight: 1
        $x_1_4 = "latAraceae" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "SkipVerification" ascii //weight: 1
        $x_1_7 = "SymmetricAlgorithm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CryptBot_PABN_2147893869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptBot.PABN!MTB"
        threat_id = "2147893869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OiBTdGFydCBCb3QgU3VjY2VzcyE=" wide //weight: 1
        $x_1_2 = "OiBCb3QgUnVuIFN1Y2Nlc3MgLSBOb3QgRmluZCBWaXJ1cyAtIEdvb2RCeWUgOikp" wide //weight: 1
        $x_1_3 = "OiBCb3QgZGV0ZWN0ZWQgYXMgdmlydXMgLSBTb3JyeSBHb29ieWUgOigoCg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

