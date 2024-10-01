rule Trojan_Win32_CredentialFlusher_CCJD_2147922439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialFlusher.CCJD!MTB"
        threat_id = "2147922439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialFlusher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SLEEP ( 2000 )" ascii //weight: 1
        $x_5_2 = "RUN ( $EDGEPATHX86 & \" --kiosk \" & $URL )" ascii //weight: 5
        $x_5_3 = "RUN ( $EDGEPATHX64 & \" --kiosk \" & $URL )" ascii //weight: 5
        $x_1_4 = "CHECKFULLSCREEN ( $BROWSERTYPE )" ascii //weight: 1
        $x_1_5 = "MONITORBROWSER ( \"Chrome\" )" ascii //weight: 1
        $x_1_6 = "MONITORBROWSER ( \"Edge\" )" ascii //weight: 1
        $x_1_7 = "HOTKEYSET ( \"{ESC}\" , \"IgnoreKey\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialFlusher_CCJE_2147922440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialFlusher.CCJE!MTB"
        threat_id = "2147922440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialFlusher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SLEEP ( 2000 )" ascii //weight: 1
        $x_5_2 = "$EDGEPATHX86 & \" --kiosk --edge-kiosk-type=fullscreen --no-first-run --disable-popup-blocking" ascii //weight: 5
        $x_5_3 = "$EDGEPATHX64 & \" --kiosk --edge-kiosk-type=fullscreen --no-first-run --disable-popup-blocking" ascii //weight: 5
        $x_1_4 = "WINGETHANDLE ( \"[CLASS:Chrome_WidgetWin_1]\" )" ascii //weight: 1
        $x_1_5 = "HOTKEYSET ( \"{ESC}\" , \"IgnoreKey\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

