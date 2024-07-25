rule Trojan_AndroidOS_RewardSteal_H_2147837255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.H"
        threat_id = "2147837255"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdjsskfdksfksdkfjkkshkfhkshk" ascii //weight: 1
        $x_1_2 = "com.abc898d.webmaster" ascii //weight: 1
        $x_1_3 = "+918637579741" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_F_2147839945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.F!MTB"
        threat_id = "2147839945"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/in/reward" ascii //weight: 1
        $x_1_2 = "rewards/Restarter" ascii //weight: 1
        $x_1_3 = "rewards/YourService" ascii //weight: 1
        $x_1_4 = "content://sms" ascii //weight: 1
        $x_1_5 = "deliverselfnotifications" ascii //weight: 1
        $x_1_6 = "CVV must be of 3 digits." ascii //weight: 1
        $x_1_7 = "@lucky.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_G_2147851298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.G!MTB"
        threat_id = "2147851298"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.rewardsapp" ascii //weight: 1
        $x_1_2 = "card_number" ascii //weight: 1
        $x_1_3 = "storeCardInfo" ascii //weight: 1
        $x_1_4 = "DEV_Reward_Pointss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_RewardSteal_H_2147901500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RewardSteal.H!MTB"
        threat_id = "2147901500"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RewardSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hello/uwer/hello/hello/google/is/the/best/MainActivity" ascii //weight: 1
        $x_1_2 = "getMessageBody" ascii //weight: 1
        $x_1_3 = "SaveMessageService" ascii //weight: 1
        $x_1_4 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

