rule Trojan_AndroidOS_Iconosys_A_2147783556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.A!MTB"
        threat_id = "2147783556"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blackflyday.com/new" ascii //weight: 1
        $x_1_2 = "MeInJail" ascii //weight: 1
        $x_1_3 = "trickerdata.php" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "buzzgeodata.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iconosys_B_2147811835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.B!MTB"
        threat_id = "2147811835"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendPhoneData" ascii //weight: 1
        $x_1_2 = "getPhoneNumbers" ascii //weight: 1
        $x_1_3 = "blackflyday.com/new/" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "buzzgeodata.php" ascii //weight: 1
        $x_1_6 = "regandwelcome.php" ascii //weight: 1
        $x_1_7 = "SendPhoneGeoData" ascii //weight: 1
        $x_1_8 = "realphoneno" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_AndroidOS_Iconosys_A_2147812200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.A!xp"
        threat_id = "2147812200"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blackflyday.com" ascii //weight: 1
        $x_1_2 = "/FunnyJail/" ascii //weight: 1
        $x_1_3 = "trickerdata.php" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "iconosysemail@rocketmail.com" ascii //weight: 1
        $x_1_6 = "://details?id=com.santa.iconosys" ascii //weight: 1
        $x_1_7 = "startCameraActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Iconosys_C_2147829873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.C!MTB"
        threat_id = "2147829873"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_2 = "trickerdata.php" ascii //weight: 1
        $x_1_3 = "phonedatanew.php" ascii //weight: 1
        $x_1_4 = "sendlicence.php" ascii //weight: 1
        $x_1_5 = "SendBkp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

