rule Trojan_MSIL_Zilla_KA_2147849324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KA!MTB"
        threat_id = "2147849324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 06 e0 06 d2 9e 06 17 58 0a 06 20 ?? 00 00 00 36 ee}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMAB_2147853390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMAB!MTB"
        threat_id = "2147853390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 80 00 00 00 6f ?? 00 00 0a 06 11 04 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 11 04 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 13 05 de 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMAB_2147853390_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMAB!MTB"
        threat_id = "2147853390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 72 01 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 06 0c 73 ?? 00 00 0a 0d 08 73 ?? 00 00 0a 13 04 11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 06}  //weight: 5, accuracy: Low
        $x_1_2 = "ResourceManager" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAD_2147890146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAD!MTB"
        threat_id = "2147890146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "9f4dej///f//W" wide //weight: 10
        $x_10_2 = {20 31 97 f4 ff 13 14 20 13 eb ff ff 13 14 20 34 b0 ff ff 13 14 20 ed 41 06 00 13 15 20 be b0 00 00 13 15 20 4e 6e 08 00 13 16 20 c5 50 02 00 13 16 20 19 51 02 00 13 16 20 0e 21 fa ff 13 17 20 26 a9 00 00 13 17 20 e9 37 ff ff 13 17 20 8b 71 03 00 13 18 20 d7 21 01 00 13 18 16 13 19 16 13 19 20 ea 5a 02 00 13 1a 20 d8 e8 00 00 13 1a 20 0d 5f 02 00 13 1a 20 14 06 02 00 13 1a 20 ab 47 f8 ff 13 1b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMAA_2147890316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMAA!MTB"
        threat_id = "2147890316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 19 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "dasfasfasfaada" ascii //weight: 1
        $x_1_3 = "gsdddgsgddddddddhh" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMAD_2147892266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMAD!MTB"
        threat_id = "2147892266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 06 09 91 07 09 07 8e 69 5d 91 61 28 ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 58 0d 09 06 8e 69 32 d6}  //weight: 4, accuracy: Low
        $x_1_2 = "5wgEPVkH9H4=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAH_2147894570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAH!MTB"
        threat_id = "2147894570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 15 11 04 11 15 91 20 ?? 00 00 00 61 d2 9c 11 15 17 58 13 15 11 15 11 04 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMBA_2147895534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMBA!MTB"
        threat_id = "2147895534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 1e 8d ?? 00 00 01 25 16 7e ?? 00 00 0a 6f ?? 00 00 0a a2 25 17 72 ?? 00 00 70 a2 25 18 7e ?? 00 00 0a 6f ?? 00 00 0a a2 25 19 72 ?? 00 00 70 a2 25 1a 7e ?? 00 00 0a 6f ?? 00 00 0a a2 25 1b 72 ?? 00 00 70 a2 25 1c 7e ?? 00 00 0a 6f ?? 00 00 0a a2 25 1d 72 ?? 00 00 70 a2 28 ?? 00 00 0a 18 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAE_2147896273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAE!MTB"
        threat_id = "2147896273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\GuidoAusili" wide //weight: 1
        $x_1_2 = "GuidoAusili.bak" wide //weight: 1
        $x_1_3 = "188.213.167.248" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMBE_2147896902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMBE!MTB"
        threat_id = "2147896902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 0a 12 0a fe ?? ?? 00 00 01 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 13 07 09 11 07 28 ?? 00 00 0a 13 08 09 11 07 28 ?? 00 00 0a 13 09 11 06 08 11 08 6f ?? 00 00 0a 00 11 09 28 ?? 00 00 0a 26 00 de 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 0d 07 28 ?? 00 00 0a 13 04 11 04 2c 1f 00 73 ?? 00 00 0a 13 05 11 05 6f ?? 00 00 0a 07 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 26 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "img.guildedcdn.com/ContentMediaGenericFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAI_2147897092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAI!MTB"
        threat_id = "2147897092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 43 00 3a 00 5c 00 46 00 79 00 00 15 5c 00 66 00 79 00 5f 00 6c 00 2e 00 64 00 61 00 74 00 61}  //weight: 1, accuracy: High
        $x_1_2 = "Fy.Exe" ascii //weight: 1
        $x_1_3 = "fyPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAJ_2147897390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAJ!MTB"
        threat_id = "2147897390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 09 00 00 fe 0c 02 00 fe 0c 01 00 6f ?? 00 00 0a fe 0e 03 00 fe 0c 00 00 fe 0c 02 00 fe 0c 01 00 fe 0c 03 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PTDK_2147898316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PTDK!MTB"
        threat_id = "2147898316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 0a e0 28 ?? 00 00 0a 6f 29 00 00 0a 13 06 02 16 9a 73 0d 00 00 06 13 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAK_2147898338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAK!MTB"
        threat_id = "2147898338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0b 08 07 11 05 1f 64 6f ?? 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 09 11 06 d6 0d 2b c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PTDV_2147898910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PTDV!MTB"
        threat_id = "2147898910"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 30 02 07 91 28 ?? 00 00 0a 0c 08 20 80 00 00 00 32 0a 08 20 80 00 00 00 59 0c 2b 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAL_2147901606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAL!MTB"
        threat_id = "2147901606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d 58 61 d2 13 20 11 23 16 91 11 23 18 91 1e 62 60 11 20 19 62 58 13 1d 16 13 18 16 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_GPA_2147902303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.GPA!MTB"
        threat_id = "2147902303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 93 61 11 ?? 11 ?? 11 ?? 58 1f ?? 58 11 ?? 5d 93 61 d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMMB_2147904571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMMB!MTB"
        threat_id = "2147904571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 02 1a 18 73 ?? 00 00 0a 13 06 11 06 ?? 11 05 28 08 00 00 06 00 11 06 6f ?? 00 00 0a 00 16 13 07 2b 00 11 07 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 16 9a 0a 06 6f ?? 00 00 0a 1a 17 73 ?? 00 00 0a 0b 07 20 ?? ?? ?? ?? 16 28 ?? 00 00 06 0c 07 6f ?? 00 00 0a 00 02 1a 17 73 ?? 00 00 0a 0d 09 6f ?? 00 00 0a 69}  //weight: 2, accuracy: Low
        $x_1_3 = "FileInfector" ascii //weight: 1
        $x_1_4 = "GetDirectories" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAQ_2147905518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAQ!MTB"
        threat_id = "2147905518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 03 07 6f ?? 00 00 0a 04 58 d1 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 2b 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_SG_2147905606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.SG!MTB"
        threat_id = "2147905606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 08 00 00 0a 6f 09 00 00 0a 7e 01 00 00 04 28 0a 00 00 0a 28 0b 00 00 0a 0a}  //weight: 1, accuracy: High
        $x_1_2 = {06 72 01 00 00 70 28 02 00 00 06 28 10 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_SDF_2147906198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.SDF!MTB"
        threat_id = "2147906198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 05 16 11 05 8e 69 11 06 16 6f ?? ?? ?? 0a 13 07 09 11 06 11 07 6f ?? ?? ?? 0a 26 de 1a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAT_2147908316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAT!MTB"
        threat_id = "2147908316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 02 08 02 8e b7 5d 91 07 08 07 8e b7 5d 91 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AE_2147909437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AE!MTB"
        threat_id = "2147909437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg delete \"HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting\" /f" wide //weight: 1
        $x_1_2 = "Software\\RK\\RKOptimizer" wide //weight: 1
        $x_1_3 = "wa.me/qr/AVRT6HXMG7N7B1" wide //weight: 1
        $x_1_4 = "kteranreyes@gmail.com" wide //weight: 1
        $x_1_5 = "WalletService" wide //weight: 1
        $x_1_6 = "paypal.me/ReyKratos?country.x=VE&locale.x=es_XC" wide //weight: 1
        $x_1_7 = "vmicshutdown" wide //weight: 1
        $x_1_8 = "vmicvmsession" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAU_2147910958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAU!MTB"
        threat_id = "2147910958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 17 59 6a 58 0a 03 6a 06 03 6a 5b 5a 0b 07 73 ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAV_2147910960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAV!MTB"
        threat_id = "2147910960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 5b 17 59 17 58 8d ?? 00 00 01 0c 06 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 59 8c ?? 00 00 01 17 8c ?? 00 00 01 12 01 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_RP_2147912761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.RP!MTB"
        threat_id = "2147912761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 5b 17 da 17 d6 8d ?? 00 00 01 0b 02 6f ?? 00 00 0a 17 da 0d 16 13 04 2b 1c 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_GXZ_2147913467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.GXZ!MTB"
        threat_id = "2147913467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fe 0a 00 00 28 ?? ?? ?? 0a fe 0a 00 00 28 ?? ?? ?? 0a fe 0c 0b 00 6a 58 fe 0c 0e 00 20 04 00 00 00 5a 6a 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 0f 00 fe 0c 0f 00 fe 09 01 00 20 05 00 00 00 6f ?? ?? ?? 0a fe 0e 10 00 fe 0c 10 00}  //weight: 10, accuracy: Low
        $x_1_2 = "TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_SLB_2147920864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.SLB!MTB"
        threat_id = "2147920864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 16 fe 01 39 03 00 00 00 00 17 0a 00 06 17 fe 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AZL_2147921667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AZL!MTB"
        threat_id = "2147921667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 2b 1c 07 08 9a 0d 09 72 ?? 0f 00 70 6f ?? 00 00 0a 2c 07 06 09 6f ?? 01 00 0a 08 17 58 0c 08 07 8e 69 32 de}  //weight: 2, accuracy: Low
        $x_1_2 = {2c 01 2a 00 73 ?? 00 00 0a 0c 08 07 06 6f ?? 00 00 0a de 0a 08 2c 06 08 6f}  //weight: 1, accuracy: Low
        $x_5_3 = "vip.123pan.cn/" wide //weight: 5
        $x_3_4 = "39.106.133.223" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AZL_2147921667_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AZL!MTB"
        threat_id = "2147921667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 25 16 6f ?? 00 00 0a 00 0a 06 28 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 00 72 59 00 00 70 28 ?? 00 00 06 26 28 ?? 00 00 06 0c 08 1b 28 ?? 00 00 06 26 08 28 ?? 00 00 06 00 1f 32 1f 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Welcome to DynX Corporation" wide //weight: 1
        $x_1_3 = "Emulator Detected" wide //weight: 1
        $x_1_4 = "VAZAAD CMD SECURE\\Downloader\\obj\\Debug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_YKAA_2147922432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.YKAA!MTB"
        threat_id = "2147922432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 2a 03 11 04 9a 28 ?? 00 00 0a 20 ?? 03 00 00 da 8c ?? 00 00 01 13 05 08 11 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 d1 08 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PFFH_2147923543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PFFH!MTB"
        threat_id = "2147923543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 1f 64 fe 01 2c 07 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 1f 1e fe 01 2c 14 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 1f 14 fe 01 2c 21 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 20 ff 00 00 00 fe 01 2c 27 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Zilla_GPN_2147925159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.GPN!MTB"
        threat_id = "2147925159"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 13 04 1d 13 05 00 11 05 19 fe 01 2c 0c 02 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AYA_2147925313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AYA!MTB"
        threat_id = "2147925313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$4fd3cb20-0d77-4774-9551-edf09ae42314" ascii //weight: 2
        $x_1_2 = "Toothless.exe" ascii //weight: 1
        $x_1_3 = "/c wmic path win32_computersystemproduct get uuid" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 1
        $x_1_5 = "eOvstoxSBbZGWsTtknc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_NL_2147926990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.NL!MTB"
        threat_id = "2147926990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 11 00 00 0a 02 6f 49 00 00 0a 0b 06 07 6f 4a 00 00 0a 0c 73 4b 00 00 0a 0d 28 46 00 00 06 13 04 2b 28 09 08 11 04 8f 4d 00 00 01 28 e4 05 00 06 28 bb 05 00 06 28 4c 00 00 0a 6f 4d 00 00 0a 26 11 04 28 47 00 00 06 58 13 04 11 04 08 8e 69 32 d1}  //weight: 3, accuracy: High
        $x_1_2 = "89.23.100.233" ascii //weight: 1
        $x_1_3 = "encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PQJH_2147928011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PQJH!MTB"
        threat_id = "2147928011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0a 0a 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c 38 ?? 00 00 00 00 28 ?? 00 00 06 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2c eb 07 08 16 08 8e 69 6f ?? 00 00 0a 0d}  //weight: 8, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_KAAL_2147928082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.KAAL!MTB"
        threat_id = "2147928082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 11 11 08 59 06 5d 13 12 11 05 11 12 7e ?? 00 00 04 11 11 91 11 06 11 11 11 07 5d 91 61 d2 9c 00 11 11 17 58 13 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PLGH_2147928920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PLGH!MTB"
        threat_id = "2147928920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 2d 11 08 07 1f 10 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2b 0f 08 07 1f 10 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 11 04 6f ?? 00 00 0a 13 07 de 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PLIH_2147929154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PLIH!MTB"
        threat_id = "2147929154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 00 70 0a 72 ?? 01 00 70 0b 72 ?? 01 00 70 0c 72 ?? 01 00 70 0d 72 ?? 01 00 70 13 04 02 1b 8d ?? 00 00 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 25 19 09 a2 25 1a 11 04 a2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PLTH_2147929501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PLTH!MTB"
        threat_id = "2147929501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 06 08 7e ?? 00 00 04 28 ?? 04 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 01 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? 00 00 0a 0b de 11 de 0f}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PKVH_2147929935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PKVH!MTB"
        threat_id = "2147929935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 09 11 07 11 09 3b aa 00 00 00 11 07 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 11 09 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 59 11 07 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 11 09 6f ?? 00 00 06 13 05 12 05 28 ?? 00 00 0a 59 13 0a 25 5a 11 0a 11 0a 5a 58 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_PKYH_2147929936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.PKYH!MTB"
        threat_id = "2147929936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0a 07 04 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a de 0a}  //weight: 8, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zilla_AMDA_2147930973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zilla.AMDA!MTB"
        threat_id = "2147930973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 00 1e 8d ?? 00 00 01 0c 07 28 ?? 00 00 0a 05 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 16 08 16 1e 28 ?? 00 00 0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 16 04 8e 69 6f ?? 00 00 0a 13 04 de 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

