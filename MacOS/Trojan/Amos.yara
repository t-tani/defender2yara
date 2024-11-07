rule Trojan_MacOS_Amos_A_2147845893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.A!MTB"
        threat_id = "2147845893"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".GrabFirefox" ascii //weight: 1
        $x_1_2 = ".FileGrabber" ascii //weight: 1
        $x_1_3 = ".GrabWallets" ascii //weight: 1
        $x_1_4 = "main.keychain_extract" ascii //weight: 1
        $x_1_5 = "main.sendlog" ascii //weight: 1
        $x_1_6 = "/Desktop/amos builds/Source AMOS/conf.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_D_2147852515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.D!MTB"
        threat_id = "2147852515"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 ec 02 00 00 e8 6a 28 00 00 e8 3f 2d 00 00 e8 7e 30 00 00 e8 a4 37 00 00 e8 ad 40 00 00 48 8d 35 bd 0f 01 00 48 8d 15 f3 79 01 00 48 8d 9d 78 ff ff ff 48 89 df}  //weight: 1, accuracy: High
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk" ascii //weight: 1
        $x_1_3 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_4 = "/FileGrabber/" ascii //weight: 1
        $x_1_5 = "Host: amos-malware.ru" ascii //weight: 1
        $x_1_6 = "POST /sendlog HTTP/1.1" ascii //weight: 1
        $x_1_7 = "activateIgnoringOtherApps:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MacOS_Amos_E_2147892920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.E!MTB"
        threat_id = "2147892920"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 63 6f 6e 66 69 67 2e 76 64 66 00 53 74 65 61 6d 2f 6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 00 53 74 65 61 6d 2f 63 6f 6e 66 69 67 2e 76 64 66}  //weight: 1, accuracy: High
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_3 = "deskwallets/atomic/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_F_2147893550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.F!MTB"
        threat_id = "2147893550"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deskwallets/Exodus/" ascii //weight: 1
        $x_1_2 = "FileGrabber/NoteStore.sqlite" ascii //weight: 1
        $x_1_3 = "/.config/filezilla/recentservers.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_N_2147894942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.N!MTB"
        threat_id = "2147894942"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Please enter your password" ascii //weight: 1
        $x_1_2 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_3 = "/dev/null find-generic-password -ga 'chrome'" ascii //weight: 1
        $x_1_4 = "/filegrabber/" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-21] 2f 73 65 6e 64 6c 6f 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MacOS_Amos_L_2147899672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.L!MTB"
        threat_id = "2147899672"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "post /sendlog http/1.1" ascii //weight: 1
        $x_1_2 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_3 = "find-generic-password -ga 'chrome" ascii //weight: 1
        $x_1_4 = "please enter your password" ascii //weight: 1
        $x_1_5 = "activateignoringotherapps:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_B_2147903370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.B!MTB"
        threat_id = "2147903370"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 69 69 38 eb 03 45 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 41 00 f1 41 ff ff 54 97 00 00 b0 f7 62 0e 91 e8 3e 40 39 09 1d 00 13 ea 02 40 f9 3f 01 00 71 55 b1 88 9a}  //weight: 5, accuracy: High
        $x_5_2 = {0a 69 69 38 ab 03 59 38 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 39 00 f1 41 ff ff 54 d6 00 00 d0 d6 a2 1e 91 d9 2f 8c 52 59 02 a0 72 c8 5e 40 39 09 1d 00 13 ca 06 40 f9 3f 01 00 71 54 b1 88 9a e0 03 13 aa}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Amos_C_2147903379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.C!MTB"
        threat_id = "2147903379"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 69 69 38 eb 83 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 55 00 f1 41 ff ff 54 68 00 00 d0 08 61 0d 91 09 3d 40 39 2a 1d 00 13 08 01 40 f9 5f 01 00 71 15 b1 89 9a e0 03 13 aa}  //weight: 5, accuracy: High
        $x_5_2 = {49 29 dc 49 ff c4 0f 84 df fe ff ff 4c 89 f7 44 89 fe 4c 89 e2 e8 b9 e4 00 00 48 85 c0 0f 84 c8 fe ff ff 49 89 c6 48 89 c7 48 8d b5 51 ff ff ff 48 89 da e8 a1 e4 00 00 85 c0 0f 84 db 00 00 00 49 ff c6 4d 89 ec 4d 29 f4 49 39 dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_Amos_P_2147903498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.P!MTB"
        threat_id = "2147903498"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "osascript -e 'display dialog" ascii //weight: 1
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'chrome' | awk '{print $2}'" ascii //weight: 1
        $x_1_3 = "osascript -e 'tell application \"Terminal\" to close first window' & exit" ascii //weight: 1
        $x_1_4 = "/Library/Cookies/Cookies.binarycookies" ascii //weight: 1
        $x_1_5 = "osascript -e 'set destinationFolderPath to (path to home folder as text)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_G_2147904437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.G!MTB"
        threat_id = "2147904437"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.walletwasabi/client/Wallets/" ascii //weight: 1
        $x_1_2 = "AMOS steals your passwords" ascii //weight: 1
        $x_1_3 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_H_2147907308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.H!MTB"
        threat_id = "2147907308"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 31 4d 89 f4 49 83 cc 0f 49 8d 7c 24 01 e8 f2 3a 00 00 48 89 43 10 49 83 c4 02 4c 89 23 4c 89 73 08 48 89 c3 48 89 df 4c 89 fe 4c 89 f2 e8 92 3b 00 00 42 c6 04 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 34 0f 57 c0 48 8b 51 f8 49 89 57 f8 0f 10 49 e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 41 e8 48 c7 41 f8 00 00 00 00 48 8d 51 e8 48 89 d1 48 39 c2 75 d3 4c 89 7d e0 48 8d 7d b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_J_2147908959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.J!MTB"
        threat_id = "2147908959"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c0 00 00 f0 00 20 0c 91 7c f9 ff 97 e1 03 00 aa f5 83 00 91 e0 83 00 91 cc 3b 00 94 e8 df 40 39 09 1d 00 13 3f 01 00 71 ea 27 42 a9 28 b1 88 9a 40 b1 95 9a 1f 15 00 f1 01 01 00 54 08 00 40 b9 08 01 14 4a 09 10 40 39 4a 0a 80 52 29 01 0a 4a 08 01 09 2a e8 00 00 34}  //weight: 5, accuracy: High
        $x_5_2 = {93 0d 00 b4 b4 48 8a 52 54 ea a9 72 c0 00 00 f0 00 38 0d 91 98 f9 ff 97 e1 03 00 aa f5 03 01 91 e0 03 01 91 e8 3b 00 94 e8 5f 41 39 09 1d 00 13 3f 01 00 71 ea 27 44 a9 28 b1 88 9a 40 b1 95 9a 1f 15 00 f1 01 01 00 54 08 00 40 b9 08 01 14 4a 09 10 40 39 4a 0a 80 52 29 01 0a 4a 08 01 09 2a e8 00 00 34}  //weight: 5, accuracy: High
        $x_2_3 = {74 34 0f 57 c0 48 8b 51 f8 49 89 57 f8 0f 10 49 e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 41 e8 48 c7 41 f8 00 00 00 00 48 8d 51 e8 48 89 d1 48 39 c2 75 d3 4c 89 7d e0 48 8d 7d b8}  //weight: 2, accuracy: High
        $x_3_4 = "system_profiler SPHardwareDataType" ascii //weight: 3
        $x_3_5 = "system_profiler spdisplaysdatatype" ascii //weight: 3
        $x_3_6 = "sw_vers" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Amos_I_2147910254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.I!MTB"
        threat_id = "2147910254"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 4d b8 30 4c 05 b8 48 ff c0 48 83 f8 03 75 f0 44 0f b6 ad 58 ff ff ff 44 89 eb 80 e3 01 74 52 4c 8b ad 60 ff ff ff eb 4c}  //weight: 2, accuracy: High
        $x_2_2 = {8a 8d 68 ff ff ff 30 8c 05 68 ff ff ff 48 ff c0 48 83 f8 03 75 ea 0f b6 1a f6 c3 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_M_2147912572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.M!MTB"
        threat_id = "2147912572"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 db 74 0c 48 ff cb 48 ff c7 41 8a 14 37 eb 04 31 d2 31 db 88 54 35 e5 48 ff c6 48 83 fe 03 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 83 e1 0f 8a 8c 0d 20 ff ff ff 41 30 0c 06 48 ff c0 49 39 c4 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_K_2147913315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.K!MTB"
        threat_id = "2147913315"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 83 01 d1 fa 67 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 f3 03 08 aa 1f 7d 00 a9 1f 09 00 f9 08 5c 40 39 09 1d 00 13 0a 2c 40 a9 3f 01 00 71 56 b1 80 9a 68 b1 88 9a e8 0a 00 b4}  //weight: 1, accuracy: High
        $x_1_2 = {15 00 80 d2 e8 37 40 39 09 7d 02 53 e9 27 00 39 e9 3b 40 39 2a 7d 04 53 0a 05 1c 33 ea 2b 00 39 e8 3f 40 39 0a 7d 06 53 2a 0d 1e 33 ea 2f 00 39 08 15 00 12 e8 33 00 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_S_2147913439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.S!MTB"
        threat_id = "2147913439"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 e6 19 02 00 89 c1 44 29 f9 31 db 48 83 f8 01 19 db 08 cb 0f be 75 d6 4c 89 ff}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b 05 9a 21 02 00 48 8b 00 48 3b 45 d0 75 31 31 c0 48 83 c4 78 5b 41 5c 41 5d 41 5e 41 5f 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Q_2147913718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Q!MTB"
        threat_id = "2147913718"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 49 89 fe bf 10 00 00 00 e8 90 45 00 00 48 89 c3 48 89 c7 4c 89 f6 e8 2e 00 00 00 48 8b 35 5f 79 00 00 48 8b 15 08 79 00 00 48 89 df e8 90 45 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb e8 4a 44 00 00 48 8b 05 53 79 00 00 48 83 c0 10 48 89 03 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_R_2147914111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.R!MTB"
        threat_id = "2147914111"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 45 84 48 83 f8 0f 0f 83 25 00 00 00 48 8b 85 58 ff ff ff 48 63 4d 84 8a 54 0d e2 48 63 4d 84 88 54 08 0a 8b 45 84 83 c0 01 89 45 84}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 0f be 04 08 48 8b 8d a0 ee ff ff 8b 09 83 c1 04 31 c8 88 c2 48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 88 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_U_2147914112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.U!MTB"
        threat_id = "2147914112"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d d0 30 4c 05 d0 48 ff c0 48 83 f8 04 75 ?? 44 0f b6 23 41 f6 c4 01 48 89 7d c8 74 ?? 4c 8b 73 10}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 88 d2 ff ff 48 85 c0 0f ?? ?? ?? ?? ?? f3 48 0f 2a c0 e9 ?? ?? ?? ?? 4c 39 f1 72 ?? 48 89 c8 31 d2 49 f7 f6 48 89 d1 48 8b 85 70 d2 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_V_2147915262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.V!MTB"
        threat_id = "2147915262"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 4d 63 f7 45 31 e4}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 85 08 fe ff ff 32 6e 6a 01 58 48 83 f8 0b 74 12 8a 8d 00 fe ff ff 30 8c 05 00 fe ff ff 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_X_2147915882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.X!MTB"
        threat_id = "2147915882"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 1c 18 4e 10 3c 18 4e 41 02 00 b0 24 f8 c1 3d e4 17 80 3d 04 44 e4 6e 01 00 66 9e 42 02 00 b0 40 00 c2 3d e0 0b 80 3d 20 44 e0 6e 02 3c 18 4e 4e 1c 40 b3}  //weight: 1, accuracy: High
        $x_1_2 = {b5 73 1a 38 15 9c 68 d3 b5 de 70 d3 b6 ea 00 52 b6 63 1a 38 56 bc 68 d3 82 0c 80 52 c2 02 02 4a a2 53 1a 38 02 bc 70 d3 57 9c 60 d3 e2 02 0e 4a a2 43 1a 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_W_2147915943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.W!MTB"
        threat_id = "2147915943"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 4c 02 02 48 83 c0 02 0f b6 4c 18 01 32 0d 85 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea 74 ?? 48 8b 95 70 fd ff ff 88 4c 02 01 48 3d ae 2d 00 00 74 ?? 0f b6 4c 18 02 32 0d 5b 57 00 00 f6 85 60 fd ff ff 01 4c 89 ea}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 4e 78 be 01 00 00 00 48 89 d7 4c 89 fa e8 f7 07 00 00 48 89 c1 b8 ff ff ff ff 4c 39 f9 0f 85 ?? ?? ?? ?? 4d 89 6e 30 4d 89 6e 28 4d 89 66 38 31 c0 83 fb ff 0f 45 c3 e9 1e ?? ?? ?? 89 5d bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Z_2147917120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Z!MTB"
        threat_id = "2147917120"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 7f 40 39 09 1d 00 13 eb ab 40 a9 3f 01 00 71 53 b1 88 9a 74 b1 94 9a 68 06 00 91 1f 41 00 b1 22 07 00 54 1f 5d 00 f1 a2 00 00 54 f5 83 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {e8 3f c1 39 08 ff ff 36 e0 1f 40 f9 4c 00 00 94 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 ff 03 02 91 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_Y_2147917132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.Y!MTB"
        threat_id = "2147917132"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d6 48 c1 ee 3e 48 31 d6 49 0f af f7 48 01 ce 48 ff ce 48 89 b4 cd a8 ef ff ff 48 81 f9 38 01 00 00 74 ?? ?? ?? ?? ?? 48 89 f7 48 c1 ef 3e 48 31 f7 49 0f af ff 48 01 fa 48 01 cf 48 89 bc cd b0 ef ff ff 48 83 c0 02 48 83 c1 02}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 48 c1 ea 1c 81 e2 00 ff 00 00 48 09 ca 48 89 c1 48 c1 e9 18 81 e1 00 00 ff 00 48 09 d1 48 89 c2 48 c1 ea 14 81 e2 00 00 00 ff 48 09 ca 48 89 c1 48 c1 e9 10 49 b8 00 00 00 00 ff 00 00 00 4c 21 c1 48 89 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AD_2147917134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AD!MTB"
        threat_id = "2147917134"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 6b 00 b9 28 00 80 52 29 6b 68 38 ea a3 41 39 29 01 0a 4a 29 6b 28 38 08 05 00 91 1f 11 00 f1 41 ?? ?? ?? e0 43 01 91 e1 13 40 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f7 03 02 aa f6 03 01 aa f4 03 00 aa 13 80 06 91 15 20 00 91 88 00 00 d0 08 e1 04 91 09 61 00 91 09 00 00 f9 08 01 01 91 08 d0 00 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AB_2147917785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AB!MTB"
        threat_id = "2147917785"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 40 f9 9f 02 15 eb 68 ?? ?? ?? 02 ?? ?? ?? a0 02 67 9e 00 58 20 0e 00 38 30 2e 08 00 26 1e 69 0e 40 f9 20 01 23 9e 61 22 40 bd 00 18 21 1e 00 00 29 9e bf 0e 00 f1 02 29 41 fa 69 ?? ?? ?? 19 04 00 94}  //weight: 1, accuracy: Low
        $x_1_2 = {f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 00 aa 28 04 00 f1 61 ?? ?? ?? 54 00 80 52 07 ?? ?? ?? f4 03 01 aa 3f 00 08 ea 80 ?? ?? ?? e0 03 14 aa 2b 04 00 94 f4 03 00 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AE_2147917786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AE!MTB"
        threat_id = "2147917786"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1c 21 6e 20 83 86 3c e0 bf 47 fd 48 e6 01 0f 00 1c 28 2e e0 bf 07 fd 09 1f 00 12 56 06 80 52 29 01 16 4a e9 03 3e 39 e8 4b 02 f9 48 0a 80 52 e8 0b 09 79 48 a6 88 52 c8 aa a8 72}  //weight: 1, accuracy: High
        $x_1_2 = {09 6a 82 52 b5 02 09 8b e8 03 02 f9 e1 23 10 91 e2 03 10 91 e0 03 15 aa c1 3e 00 94 e8 83 36 91 08 01 40 b2 c9 0a 80 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AJ_2147919057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AJ!MTB"
        threat_id = "2147919057"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a 41 00 51 eb 43 00 91 4b 0d 40 b3 0a 69 69 38 6b 01 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 49 02 f1}  //weight: 1, accuracy: High
        $x_1_2 = {bf 6a 34 38 e8 1f 46 39 09 1d 00 13 ea 2f 57 a9 3f 01 00 71 e9 c3 05 91 41 b1 89 9a 62 b1 88 9a e0 43 1f 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AN_2147919058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AN!MTB"
        threat_id = "2147919058"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 04 80 52 08 00 08 4a e8 83 02 39 2a fc 78 d3 48 09 1c 52 e8 7f 02 39 2b fc 70 d3 e9 0d 80 52 68 01 09 4a e8 7b 02 39 2c fc 68 d3 93 0e 80 52 88 01 13 4a e8 77 02 39 2d fc 60 d3 68 0e 80 52 ae 01 08 4a 68 0e 80 52 ee 73 02 39 2e fc 58 d3 cf 01 1b 52 ef 6f 02 39}  //weight: 1, accuracy: High
        $x_1_2 = {1f 21 00 f1 00 ?? ?? ?? 2a 01 08 8b 4b 01 40 39 4c 41 40 39 8b 01 0b 4a 4b 41 00 39 08 05 00 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AO_2147919063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AO!MTB"
        threat_id = "2147919063"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "walletwasabi/client/Wallets/" ascii //weight: 5
        $x_5_2 = "Exodus/exodus.wallet/" ascii //weight: 5
        $x_1_3 = "atomic/Local Stveldb/" ascii //weight: 1
        $x_1_4 = "Guarda/Local Storage/leveldb/" ascii //weight: 1
        $x_1_5 = {ff 43 01 d1 fd 7b 04 a9 fd 03 01 91 a0 83 1f f8 a8 83 5f f8 e8 07 00 f9 e0 83 00 91 e0 03 00 f9 61 00 00 f0 21 f8 06 91 6a ?? ?? ?? e1 03 40 f9 e2 07 40 f9 e0 03 02 aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Amos_T_2147919521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.T!MTB"
        threat_id = "2147919521"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f6 c7 01 48 8d 85 31 ef ff ff 48 0f 44 d8 4d 85 e4 74 ?? 48 8d 75 b1 41 f6 c5 01 74 ?? 48 8b 75 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 3d 02 01 00 4d 8d 3c 04 49 83 ff f0 0f 83 4d 0d 00 00 49 89 c6 49 83 ff 16 77 ?? 0f 57 c0 0f 29 85 30 ef ff ff 48 c7 85 40 ef ff ff 00 00 00 00 45 00 ff 44 88 bd 30 ef ff ff 31 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AQ_2147919678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AQ!MTB"
        threat_id = "2147919678"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 e0 02 89 ca c0 ea 04 80 e2 03 08 c2 88 55 d1 c0 e1 04 8a 45 d6 c0 e8 02 24 0f 08 c8 88 45 d2 8b 45 c8 83 f8 02 6a 01 41 5e 44 0f 4d f0 41 ff ce 45 31 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f 95 c0 0f b6 c0 5d c3 90 48 85 f6 74 13 55 48 89 e5 48 89 f0 0f be 32 48 89 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AC_2147920058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AC!MTB"
        threat_id = "2147920058"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 89 b4 94 60 01 00 00 41 0f b6 94 0c 4b 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 41 0f b6 94 0c 4c 8f 00 00 8b b4 94 60 01 00 00 ff c6 ?? ?? 89 b4 94 60 01 00 00 48 81 f9 1d 01 00 00 ?? ?? 41 0f b6 94 0c 4d 8f 00 00 8b b4 94 60 01 00 00 48 83 c1 03 ff c6 ?? ?? 67 0f b9}  //weight: 1, accuracy: Low
        $x_1_2 = {74 36 49 8b 45 f0 48 39 d8 ?? ?? 48 8d 68 e8 f6 40 e8 01 ?? ?? 48 8b 78 f8 e8 ed 03 00 00 48 89 e8 48 39 dd ?? ?? 49 8b 3c 24 ?? ?? 48 89 df 49 89 5d f0 e8 d3 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AH_2147920060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AH!MTB"
        threat_id = "2147920060"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 01 0b 6b a1 00 00 54 8a 00 00 b0 4a f1 43 79 2a 69 02 b9 1f 00 00 14 e9 2f 40 f9 6a 67 81 52 49 01 09 4b ea 2f 40 f9 eb 3f c1 39 29 7d 0a 1b ea 72 8a 52 2a 68 bd 72 29 29 0b 1b 8a 00 00 b0}  //weight: 1, accuracy: High
        $x_1_2 = {ad 3d 10 53 bf c1 57 71 2d 02 00 54 2a 6d 1c 53 4a 01 09 4b 8a 29 08 39 ea 4b 40 b9 ec 4b 40 b9 4a 31 0e 1b ea 4b 00 b9 10 00 00 14 8a 00 00 b0 4a 99 44 79 aa 01 00 34 ea 43 40 b9 0a 01 00 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AR_2147920163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AR!MTB"
        threat_id = "2147920163"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 56 40 49 8b be 80 00 00 00 49 8b 4e 60 48 01 d1 48 8b 07 4c 89 e6 ?? ?? ?? ?? ?? ?? ?? ff 50 28 89 c3 4c 8b ad 50 ff ff ff 49 8b 7e 40 49 8b 4e 78 49 29 fd 4c 89 fe 4c 89 ea e8 b4 2b 00 00 4c 39 e8 75 ?? 83 fb 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 09 c8 f3 0f 5e c1 66 0f 3a 0a c0 0a f3 48 0f 2c c8 48 89 ca 48 c1 fa 3f f3 0f 5c 05 8b 3c 00 00 f3 48 0f 2c f0 48 21 d6 48 09 ce 48 39 f0 48 0f 47 f0 4c 89 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AU_2147920165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AU!MTB"
        threat_id = "2147920165"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e8 48 8b 45 f0 88 45 e7 e8 fc ?? ?? ?? 8a 55 e7 48 8b 7d e8 8a 08 80 e2 7f c0 e2 01 80 e1 01 08 d1 88 08 e8 e1 ?? ?? ?? 8a 08 80 e1 fe 80 c9 00 88 08 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 f0 48 3b 45 e8 0f 84 ?? ?? ?? ?? 48 8b 7d c0 48 8b 75 f0 e8 e5 ?? ?? ?? 48 8b 45 f0 48 83 c0 01 48 89 45 f0 48 8b 45 c0 48 83 c0 01 48 89 45 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AV_2147921840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AV!MTB"
        threat_id = "2147921840"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0b f6 c1 01 75 36 48 89 c8 48 d1 e8 41 bf 16 00 00 00 48 8b 5d c0 3c 16 74 5e 80 e1 fe 80 c1 02}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 95 d8 fe ff ff 30 11 0f b6 95 d8 fe ff ff 30 51 01 30 51 02 0f b6 95 d8 fe ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1 75 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AS_2147923435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AS!MTB"
        threat_id = "2147923435"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 95 58 ff ff ff 30 11 0f b6 95 58 ff ff ff 30 51 01 30 51 02 0f b6 95 58 ff ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 4b f8 49 89 4f f8 0f 10 4b e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 43 e8 48 c7 43 f8 00 00 00 00 48 8d 4b e8 48 89 cb 4c 39 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AT_2147923436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AT!MTB"
        threat_id = "2147923436"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 08 aa 08 48 82 52 e8 1b 00 79 48 e2 88 52 28 e8 aa 72 e8 0b 00 b9 e8 23 00 91 00 01 40 b2 29 00 80 52}  //weight: 1, accuracy: High
        $x_1_2 = {08 a4 40 a9 1f 01 09 eb 22 ?? ?? ?? 20 00 c0 3d 29 08 40 f9 09 09 00 f9 00 85 81 3c 3f fc 00 a9 3f 00 00 f9 08 04 00 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AW_2147923439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AW!MTB"
        threat_id = "2147923439"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 07 40 f9 e9 03 00 aa e0 03 40 f9 e9 0f 00 f9 e9 03 01 aa e9 17 00 b9 01 21 00 91 e8 0f 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {ff c3 00 d1 fd 7b 02 a9 fd 83 00 91 88 00 00 d0 08 c1 0a 91 09 41 00 91 a0 83 1f f8 a8 83 5f f8 e8 03 00 f9 09 01 00 f9 00 01 01 91 a0 0f 00 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AX_2147923440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AX!MTB"
        threat_id = "2147923440"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 89 7d f8 48 8b 45 f8 48 8b 0d a5 a4 00 00 48 83 c1 10 48 89 08 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 20 48 89 7d f0 48 89 75 e8 48 8b 7d f0 48 8b 45 e8 48 89 45 e0 e8 ?? ?? ?? ?? 48 89 c1 48 8b 45 e0 48 39 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AA_2147923515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AA!MTB"
        threat_id = "2147923515"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 95 0a e7 ff ff 48 89 d6 41 80 f6 68 44 88 b5 09 e7 ff ff 88 9d 08 e7 ff ff 41 0f b6 d6 66 0f 3a 20 c2 07 48 8b 95 20 c6 ff ff 88 95 07 e7 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {40 0f b6 d6 66 0f 3a 20 c2 08 48 8b 95 50 c6 ff ff 88 95 06 e7 ff ff 40 0f b6 d7 66 0f 3a 20 c2 09 48 8b 95 48 c6 ff ff 88 95 05 e7 ff ff 41 0f b6 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AL_2147923516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AL!MTB"
        threat_id = "2147923516"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa e3 ff ff 97 e0 03 13 aa b9 05 00 94 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6}  //weight: 1, accuracy: High
        $x_1_2 = {e0 03 13 aa c8 00 00 94 f4 03 00 aa e0 03 13 aa 06 01 00 94 9f 02 00 eb 82 ?? ?? ?? 80 02 c0 39 04 01 00 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AF_2147923517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AF!MTB"
        threat_id = "2147923517"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ec 7f c1 39 ed 27 40 f9 6e 02 08 8b ce 05 40 39 2f 21 47 39 ce 01 0f 4a 9f 01 00 71 ac b1 8a 9a 8c 01 08 8b 8e 05 00 39 08 05 00 91 1f 01 0b eb 81 ?? ?? ?? 88 01 80 52 e8 1f 01 39 e8 e5 8d 52 88 0d af 72 e8 3b 00 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 73 40 f9 56 02 00 b4 e8 37 40 f9 08 19 40 f9 e0 03 14 aa 00 01 3f d6 f5 03 00 aa e0 03 16 aa 10 07 00 94 f6 03 00 aa ff 73 00 f9 e8 37 40 f9 08 0d 40 f9 e0 03 14 aa 01 00 80 d2 02 00 80 d2 00 01 3f d6 c8 02 15 2a 08 ?? ?? ?? e8 33 40 f9 08 81 5e f8 e9 83 01 91 20 01 08 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AI_2147923831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AI!MTB"
        threat_id = "2147923831"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 13 eb 00 48 89 c3 48 8d bd 78 ff ff ff e8 f7 1e 00 00 eb 03 48 89 c3 48 8d bd 60 fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {75 28 31 c0 48 81 c4 f8 00 00 00 5b 41 5c 41 5d 41 5e 41 5f 5d c3 8b 85 6c ff ff ff 04 07 88 45 9e 31 ff e8 87 17 00 00 0f 0b e8 7a 17 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AM_2147923832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AM!MTB"
        threat_id = "2147923832"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 f9 41 ff c7 88 44 0d d5 41 83 ff 03 75 69 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 89 c2 c0 ea 06 c0 e1 02 08 d1 80 e1 3f}  //weight: 1, accuracy: High
        $x_1_2 = {89 c1 c6 44 0d d5 00 ff c0 83 f8 03 75 f2 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 45 85 ff 78 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AP_2147923833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AP!MTB"
        threat_id = "2147923833"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 09 48 8b 7d e0 e8 ea 04 00 00 48 89 df e8 e2 04 00 00 31 c0 48 83 c4 38 5b 41 5e 41 5f 5d c3 48 8d 35 ac 07 00 00 e8 9d 00 00 00 48 89 c7 e8 c5 00 00 00 bf 01 00 00 00 e8 db 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 7d c0 4d 01 fe 41 81 e5 b0 00 00 00 41 83 fd 20 4c 89 fa 49 0f 44 d6 44 0f be c8 4c 89 fe 4c 89 f1 4d 89 e0 e8 9e 00 00 00 48 85 c0 75 17 48 8b 03 48 8b 40 e8 48 8d 3c 03 8b 74 03 20 83 ce 05 e8 82 02 00 00 48 8d 7d b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AZ_2147923964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AZ!MTB"
        threat_id = "2147923964"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 3f c1 39 68 00 f8 36 e0 1f 40 f9 41 00 00 94 e0 03 14 aa 3f 00 00 94 e0 03 13 aa 3d 00 00 94 e0 03 15 aa 2c 00 00 94 e0 07 40 f9 39 00 00 94 e8 df c0 39 68 fe ff 36}  //weight: 1, accuracy: High
        $x_1_2 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb 01 fe ff 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AK_2147924459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AK!MTB"
        threat_id = "2147924459"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 89 fb e8 81 f1 ff ff 48 89 df e8 07 16 00 00 5b 41 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d7 00 48 8d 75 d7 48 89 df e8 a8 fc ff ff 48 83 c4 18 5b 41 5c 41 5d 41 5e 41 5f 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_AY_2147924462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.AY!MTB"
        threat_id = "2147924462"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 b8 88 0c 08 48 89 c8 31 d2 49 f7 f5 49 8b 04 24 8a 04 10 48 8b 55 88 88 04 0a 48 ff c1 48 81 f9 00 01 00 00 75 ?? 31 c0 31 c9 4c 8b bd 78 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 57 c0 4c 8b 75 c8 41 0f 11 06 49 c7 46 10 00 00 00 00 45 31 ff 4c 8d 2d ff 8c 00 00 31 db 45 31 e4 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BB_2147924810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BB!MTB"
        threat_id = "2147924810"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 01 c7 46 88 2c 30 4c 39 e3 0f ?? ?? ?? ?? ?? 49 83 fe 08 0f ?? ?? ?? ?? ?? 48 89 ca 48 89 de 89 f7 44 29 e7 4c 89 e1 48 f7 d1 48 01 f1 48 83 e7 07}  //weight: 1, accuracy: Low
        $x_1_2 = {44 89 e9 c1 e1 05 48 89 c6 48 09 ce 41 83 fe 03 0f ?? ?? ?? ?? ?? 44 89 f1 83 c1 fd 41 89 f5 89 4d d4 41 d3 ed 49 8b 44 24 10 48 39 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BC_2147924811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BC!MTB"
        threat_id = "2147924811"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 7e 10 48 8b 75 a8 40 8a 34 16 40 32 34 17 f6 03 01 48 89 cf 74 ?? 48 8b 7b 10 40 88 34 17 48 ff c2}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 41 56 53 48 83 ec 10 0f 57 c0 48 83 67 10 00 0f 11 07 48 89 7d e0 c6 45 e8 00 48 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CA_2147925277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CA!MTB"
        threat_id = "2147925277"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 01 12 00 00 0f be f0 48 89 df e8 b7 12 00 00 48 89 df e8 b5 12 00 00 48 89 d8 48 83 c4 08 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 8b 06 48 89 07 48 8b 4e 40 48 8b 40 e8 48 89 0c 07 48 8b 46 48 48 89 47 10 48 83 c7 18 e8 7a 00 00 00 48 83 c3 08 4c 89 f7 48 89 de 5b 41 5e 5d e9 b0 11 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CB_2147925279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CB!MTB"
        threat_id = "2147925279"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d bd 60 ff ff ff e8 5f 14 00 00 48 8d bd 48 ff ff ff e8 53 14 00 00 48 8d 7d a8 e8 4a 14 00 00 31 c0 48 81 c4 b0 00 00 00 5b 41 5e 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 6d 13 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 03 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_BQ_2147925438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.BQ!MTB"
        threat_id = "2147925438"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 5e c0 39 ca 02 40 f9 3f 01 00 71 49 b1 96 9a 29 69 68 38 ea 07 40 f9 4a 69 68 38 49 01 09 4a aa 5e c0 39 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 49 69 28 38 08 05 00 91 ff 02 08 eb}  //weight: 1, accuracy: High
        $x_1_2 = {4a 05 00 11 4a 1d 40 92 6b 6a 6a 38 69 01 09 0b 2c 1d 40 92 6d 6a 6c 38 6d 6a 2a 38 6b 6a 2c 38 6c 6a 6a 38 8b 01 0b 0b 6b 1d 40 92 6b 6a 6b 38 ec 07 40 f9 8b 69 28 38 08 05 00 91 ff 02 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Amos_CC_2147925625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Amos.CC!MTB"
        threat_id = "2147925625"
        type = "Trojan"
        platform = "MacOS: "
        family = "Amos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 c0 40 8a 34 0a 40 00 f0 48 8b 7d 90 02 04 0f 0f b6 f8 44 8a 04 3a 44 88 04 0a 40 88 34 3a 48 ff c1}  //weight: 1, accuracy: High
        $x_1_2 = {49 39 cf 74 ?? 49 8b 36 48 8b 55 a8 8a 14 0a 32 14 0e f6 03 01 48 89 c6 74 ?? 48 8b 73 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

