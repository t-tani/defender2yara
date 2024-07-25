rule Trojan_MSIL_Gamarue_A_2147781322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gamarue.A!MTB"
        threat_id = "2147781322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gamarue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "itter_sBO9ZhjoHB6ZU3eqZPKZwlfYqtVoDBKm5LXXkGFcWr0Lrex92C6liPmJduQFbwSCDoozFQMJkr4NPjJtONADkjZmRjDQisrPfgqIJ7RyEwAcK8tNEale9Q6mc" ascii //weight: 5
        $x_5_2 = "pzdhDOxRIfrchpmBZSBB3isnEaA" ascii //weight: 5
        $x_5_3 = "7uCfFvAFejuBu0uyBssuGGAy1MXcCYyXztMGuE8wQ4tvaLA9r0hNOTH88" ascii //weight: 5
        $x_5_4 = "MhJ5QsZjTcQzQYhYWXAN7LAkys" ascii //weight: 5
        $x_4_5 = "AppDataitter" ascii //weight: 4
        $x_4_6 = "URLitter_FILE" ascii //weight: 4
        $x_4_7 = "jlyBm3H2yk5UanXO65e8nSVYecp60t4bZbcOic0AHIA==itter" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

