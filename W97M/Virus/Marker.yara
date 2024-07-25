rule Virus_W97M_Marker_AH_2147662227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Marker.AH"
        threat_id = "2147662227"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Marker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "codemodule.Find(\"niahiyigebendan\"" ascii //weight: 1
        $x_1_2 = "Shell (\"\\\\jdq\\cc$\\b.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_W97M_Marker_KI_2147742146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Marker.KI"
        threat_id = "2147742146"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Marker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kill Options.DefaultFilePath(8) & \"\\*.doc\"" ascii //weight: 1
        $x_1_2 = "Kill Options.DefaultFilePath(8) & \"\\*.dot\"" ascii //weight: 1
        $x_1_3 = "Options.VirusProtection = False" ascii //weight: 1
        $x_1_4 = "Application.EnableCancelKey = wdCancelDisabled" ascii //weight: 1
        $x_2_5 = "If (System.PrivateProfileString(\"\", \"HKEY_CURRENT_USER\\Software\\Microsoft\\MS Setup (ACME)\\User Info\", _\"LogData in\") = False) Then GoSub LoggingIn If Weekday(Now()) = 1 Then GoSub ShowMe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

