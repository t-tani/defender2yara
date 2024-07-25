rule Trojan_MSIL_Dapato_DA_2147780708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato.DA!MTB"
        threat_id = "2147780708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 02 6f ?? ?? ?? 0a 0c 2b 32 02 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 da 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 28 ?? ?? ?? 06 d6 0b 07 08 32 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dapato_2147825923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato!MTB"
        threat_id = "2147825923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {fa 25 33 00 16 00 00 01 00 00 00 3d 00 00 00 07 00 00 00 12}  //weight: 3, accuracy: High
        $x_1_2 = "BouncyCastle.Crypto" ascii //weight: 1
        $x_1_3 = "Org.BouncyCastle.Bcpg.OpenPgp" ascii //weight: 1
        $x_1_4 = "get_OSVersion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dapato_AD_2147846723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato.AD!MTB"
        threat_id = "2147846723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2c 13 07 2c 04 16 0b 2b 0c 72 f5 02 00 70 28 ?? ?? ?? 0a 16 2a 09 17 58 0d 09 08 8e 69 32 d3 72 1d 03 00 70}  //weight: 2, accuracy: Low
        $x_1_2 = "CallCoreInstall.exe" wide //weight: 1
        $x_1_3 = "alsopwnrun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dapato_AD_2147846723_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato.AD!MTB"
        threat_id = "2147846723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 2c 16 00 06 28 ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 2b 0d 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 00 de 05}  //weight: 2, accuracy: Low
        $x_1_2 = "source\\repos\\AnyDeskAdd.exe\\AnyDeskAdd.exe\\obj\\Debug\\AnyDeskAdd.exe.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dapato_ABQE_2147896717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato.ABQE!MTB"
        threat_id = "2147896717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {09 19 06 5a 6f ?? ?? ?? 0a 0b 07 1f 39 fe 02 13 07 11 07 2c 0b 07 1f 41 59 1f 0a 58 d1 0b 2b 06 07 1f 30 59 d1 0b 09 19 06 5a 17 58 6f ?? ?? ?? 0a 0c 08 1f 39 fe 02 13 08 11 08 2c 0b 08 1f 41 59 1f 0a 58 d1 0c 2b 06 08 1f 30 59 d1 0c 11 05 06 1f 10 07 5a 08 58 d2 9c 06 17 58 0a 06 11 04 fe 04 13 09 11 09 2d 98}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dapato_ARA_2147913776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dapato.ARA!MTB"
        threat_id = "2147913776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\WallpaperX.pdb" ascii //weight: 2
        $x_2_2 = "config.txt" ascii //weight: 2
        $x_2_3 = "ROOM_KEY" ascii //weight: 2
        $x_2_4 = "log.txt" ascii //weight: 2
        $x_2_5 = "DownloadFileFromURL" ascii //weight: 2
        $x_2_6 = "UploadData" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

