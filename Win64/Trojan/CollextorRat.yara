rule Trojan_Win64_CollextorRat_CM_2147979885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CollextorRat.CM!MTB"
        threat_id = "2147979885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CollextorRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I am a hacker. Fear me." ascii //weight: 1
        $x_1_2 = "stun_debug.txt" ascii //weight: 1
        $x_1_3 = "[main] mutex ok" ascii //weight: 1
        $x_1_4 = "[main] ping done, starting webhook" ascii //weight: 1
        $x_1_5 = "\\AyuGram Desktop\\tdata" ascii //weight: 1
        $x_1_6 = "\\TelegramBeta\\tdata" ascii //weight: 1
        $x_3_7 = "Collextor Remote" ascii //weight: 3
        $x_1_8 = "powershell -WindowStyle Hidden -Command" ascii //weight: 1
        $x_1_9 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii //weight: 1
        $x_1_10 = "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_11 = "killbrowser" ascii //weight: 1
        $x_1_12 = "killdiscord" ascii //weight: 1
        $x_1_13 = "killav" ascii //weight: 1
        $x_2_14 = "New harvest" ascii //weight: 2
        $x_3_15 = "Collextor" ascii //weight: 3
        $x_1_16 = "Your files are mine now." ascii //weight: 1
        $x_1_17 = "\\cl.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

