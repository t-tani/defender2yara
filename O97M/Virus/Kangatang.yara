rule Virus_O97M_Kangatang_2147932807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Kangatang!MTB"
        threat_id = "2147932807"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kangatang"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subauto_open()'ifthisworkbook.path<>application.path&\"\\xlstart\"thenthisworkbook.saveasfilename:=application.path&\"\\xlstart\\mypersonel1.xls\"" ascii //weight: 1
        $x_1_2 = "Application.OnSheetActivate = \"mypersonnel1.xls!allocated\"" ascii //weight: 1
        $x_1_3 = "ifactiveworkbook.sheets(1).name<>\"kangatang\"thenapplication.screenupdating=trueapplication.displaystatusbar=truecurrentsh=activesheet.name" ascii //weight: 1
        $x_1_4 = "thisworkbook.sheets(\"kangatang\").copybefore:=activeworkbook.sheets(1)activeworkbook.sheets(currentsh).selectapplication.screenupdating=trueendifendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

