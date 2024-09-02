rule Trojan_Win32_AutoitInject_BC_2147741469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BC!MTB"
        threat_id = "2147741469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756e50452840486f6d654472697665202620275c57696e646f77735c4d6963726f736f66742e4e45545c" ascii //weight: 1
        $x_1_2 = "4672616d65776f726b5c76342e302e33303331395c52656741736d2e657865272c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BD_2147741556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BD!MTB"
        threat_id = "2147741556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756e50452840486f6d654472697665202620275c57696e646f77735c4d6963726f736f66742e4e45545c" ascii //weight: 1
        $x_1_2 = "4672616D65776F726B5C76322E302E35303732375C52656741736D2E657865272C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BE_2147741586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BE!MTB"
        threat_id = "2147741586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756E50452840486F6D654472697665202620537472696E6752657665727365" ascii //weight: 1
        $x_1_2 = "28276578652E736376536765525C39313330332E302E34765C6B726F77656D6172465C54454E2E74666F736F7263694D5C73776F646E69575C27292C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BF_2147741642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BF!MTB"
        threat_id = "2147741642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\"vboxtray.exe\"" ascii //weight: 10
        $x_10_2 = "\"vmtoolsd.exe\"" ascii //weight: 10
        $x_10_3 = "\"@AutoItExe\"" ascii //weight: 10
        $x_10_4 = "\"kernel32.dll\"" ascii //weight: 10
        $x_1_5 = "EXECUTE ( BINARYTOSTRING ( \"0x52756E504528" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BG_2147742026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BG!MTB"
        threat_id = "2147742026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = " = BINARYTOSTRING ( \"0x" ascii //weight: 10
        $x_10_2 = " = @APPDATADIR & \"\\" ascii //weight: 10
        $x_10_3 = "CRYPTINTERNALDATA" ascii //weight: 10
        $x_10_4 = "( $WPATH , $LPFILE , $PROTECT , $PERSIST )" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BH_2147742101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BH!MTB"
        threat_id = "2147742101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " ( $URL , $PATH )" ascii //weight: 1
        $x_1_2 = " ( \"ShellExecute\" )" ascii //weight: 1
        $x_1_3 = " = EXECUTE ( \"@HomeDrive & " ascii //weight: 1
        $x_1_4 = " = BINARYTOSTRING ( \"0x" ascii //weight: 1
        $x_1_5 = "$ARRAY = [ \"vmtoolsd.exe\" , \"vbox.exe\" ]" ascii //weight: 1
        $x_1_6 = " = @USERPROFILEDIR & \"\\" ascii //weight: 1
        $x_1_7 = " = @APPDATADIR & \"\\" ascii //weight: 1
        $x_10_8 = " = EXECUTE (" ascii //weight: 10
        $x_10_9 = "CRYPTINTERNALDATA" ascii //weight: 10
        $x_10_10 = " ( $WPATH , $LPFILE , $PROTECT , $PERSIST )" ascii //weight: 10
        $x_10_11 = " ( $FILE , $STARTUP , $RES , $RUN = " ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_BI_2147742536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BI!MTB"
        threat_id = "2147742536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" ascii //weight: 10
        $x_10_2 = "GETPASSWORD1" ascii //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 10
        $x_1_4 = {53 65 74 75 70 3d [0-10] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 75 70 3d [0-10] 2e 76 62 65}  //weight: 1, accuracy: Low
        $x_10_6 = "Path=%temp%\\" ascii //weight: 10
        $x_10_7 = "ARarHtmlClassName" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AR_2147742918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AR!MTB"
        threat_id = "2147742918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "1D1J1P1Z1a1" ascii //weight: 20
        $x_1_2 = "FILEWRITE" wide //weight: 1
        $x_1_3 = "SHELLEXECUTE" wide //weight: 1
        $x_1_4 = "STRINGREGEXPREPLACE" wide //weight: 1
        $x_1_5 = "STRINGREPLACE" wide //weight: 1
        $x_1_6 = "STRINGREVERSE" wide //weight: 1
        $x_1_7 = "TCPACCEPT" wide //weight: 1
        $x_1_8 = "TCPCLOSESOCKET" wide //weight: 1
        $x_1_9 = "TCPCONNECT" wide //weight: 1
        $x_1_10 = "TCPNAMETOIP" wide //weight: 1
        $x_1_11 = "UBOUND" wide //weight: 1
        $x_1_12 = "UDPBIND" wide //weight: 1
        $x_1_13 = "UDPCLOSESOCKET" wide //weight: 1
        $x_1_14 = "WINWAITACTIVE" wide //weight: 1
        $x_1_15 = "STARTMENUCOMMONDIR" wide //weight: 1
        $x_1_16 = "STARTUPCOMMONDIR" wide //weight: 1
        $x_1_17 = "LOCALAPPDATADIR" wide //weight: 1
        $x_1_18 = "APPDATADIR" wide //weight: 1
        $x_20_19 = "adprovider.exe" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_SP_2147743243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SP!MTB"
        threat_id = "2147743243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "290x446C6C43616C6C2824646C6C68616E646C652C2022626F6F6C222C2022" wide //weight: 1
        $x_8_2 = "FUNC _NAMEDPIPES_CALLNAMEDPIPE ( $" wide //weight: 8
        $x_8_3 = "= DLLCALL ( \"kernel32.dll\" , \"bool\" , \"CallNamedPipeW\"" wide //weight: 8
        $x_8_4 = "= DLLCALL ( \"kernel32.dll\" , \"bool\" , \"ConnectNamedPipe\"" wide //weight: 8
        $x_8_5 = "= BITOR ( $IOPENMODE , $__ACCESS_SYSTEM_SECURITY )" wide //weight: 8
        $x_8_6 = "= EXECUTE ( \"binarytostring\" )" wide //weight: 8
        $x_8_7 = "( \"riptDir@Sc\" , 3 )" wide //weight: 8
        $x_8_8 = "( \"r@TempDi\" , 7 )" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RA_2147744389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!eml"
        threat_id = "2147744389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appsruprov.exe" wide //weight: 1
        $x_1_2 = "APHostClient.exe" wide //weight: 1
        $x_1_3 = "FSoftware\\AutoIt v3\\AutoIt" wide //weight: 1
        $x_1_4 = "\\\\[\\\\nrt]|%%|%[-+ 0#]?([0-9]*|\\*)?(\\.[0-9]*|\\.\\*)?[hlL]?[diouxXeEfgGs]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_J_2147744486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.J!ibt"
        threat_id = "2147744486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "logagentE" ascii //weight: 1
        $x_1_2 = "$STARTUPDIR = @USERPROFILEDIR & \"\\RDVGHelper\"" ascii //weight: 1
        $x_1_3 = "( \"runas\" , \"at.exe\" )" ascii //weight: 1
        $x_1_4 = {22 00 2e 00 65 00 78 00 [0-2] 65 00 76 00 6d 00 [0-2] 74 00 6f 00 6f 00 [0-2] 6c 00 73 00 64 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 2e 65 78 [0-2] 65 76 6d [0-2] 74 6f 6f [0-2] 6c 73 64 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_PJ_2147744487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PJ!ibt"
        threat_id = "2147744487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$STARTUPDIR = @APPDATADIR & " ascii //weight: 1
        $x_1_2 = "\\RegAsm.exe" ascii //weight: 1
        $x_1_3 = {69 00 6d 00 65 00 4f 00 75 00 74 00 20 00 [0-2] 31 00 [0-2] 20 00 26 00 [0-2] 20 00 [0-2] 44 00 65 00 6c 00 20 00 2f 00 [0-2] 46 00 20 00 [0-2] 20 00 [0-2] 2f 00 63 00 [0-2] 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6d 65 4f 75 74 20 [0-2] 31 [0-2] 20 26 [0-2] 20 [0-2] 44 65 6c 20 2f [0-2] 46 20 [0-2] 20 [0-2] 2f 63 [0-2] 20}  //weight: 1, accuracy: Low
        $x_1_5 = {22 00 2e 00 65 00 78 00 [0-2] 65 00 76 00 6d 00 [0-2] 74 00 6f 00 6f 00 [0-2] 6c 00 73 00 64 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {22 2e 65 78 [0-2] 65 76 6d [0-2] 74 6f 6f [0-2] 6c 73 64 22}  //weight: 1, accuracy: Low
        $x_1_7 = {22 00 65 00 78 00 65 00 76 00 [0-2] 62 00 6f 00 78 00 2e 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {22 65 78 65 76 [0-2] 62 6f 78 2e 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_GJ_2147744488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GJ!ibt"
        threat_id = "2147744488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$STARTUPDIR = @APPDATADIR & " ascii //weight: 1
        $x_1_2 = "@HOMEDRIVE & \"\\Windows\\Microsoft.NET" ascii //weight: 1
        $x_1_3 = "FILEWRITE ( $EXEPATH , $BYTES )" ascii //weight: 1
        $x_1_4 = "FILEWRITE ( $VBSPATH , $VBS )" ascii //weight: 1
        $x_1_5 = "FILEWRITE ( $URLPATH , $URL )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PA_2147745489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PA!MTB"
        threat_id = "2147745489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "( $FILE , $STARTUP , $RES )" ascii //weight: 1
        $x_1_2 = "( $VBSNAME , $FILENAME )" ascii //weight: 1
        $x_1_3 = "$XOR = BITXOR ( $XOR , $LEN + $II )" ascii //weight: 1
        $x_1_4 = "LOCAL $STARTUPDIR = @TEMPDIR & \"\\Narrator\"" ascii //weight: 1
        $x_1_5 = "( \"pcalua\" , \"appmgr.exe\" )" ascii //weight: 1
        $x_1_6 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 52 00 75 00 6e 00 50 00 45 00 28 00 40 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 75 00 6c 00 6c 00 50 00 61 00 74 00 68 00 2c 00 24 00 [0-32] 2c 00 46 00 61 00 6c 00 73 00 65 00 2c 00 46 00 61 00 6c 00 73 00 65 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {45 58 45 43 55 54 45 20 28 20 22 52 75 6e 50 45 28 40 53 63 72 69 70 74 46 75 6c 6c 50 61 74 68 2c 24 [0-32] 2c 46 61 6c 73 65 2c 46 61 6c 73 65 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_9 = "LOCAL $VBSPATH =" ascii //weight: 1
        $x_1_10 = "LOCAL $EXEPATH =" ascii //weight: 1
        $x_1_11 = "LOCAL $BOOL = @SCRIPTDIR = $STARTUPDIR \"True\" \"False\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_AutoitInject_AN_2147748089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AN!MSR"
        threat_id = "2147748089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jokM.com" wide //weight: 1
        $x_1_2 = "rlUVZ.exe" wide //weight: 1
        $x_1_3 = "gRGt.exe" wide //weight: 1
        $x_1_4 = "UmfKb.exe" wide //weight: 1
        $x_1_5 = "jfipolko.exe" wide //weight: 1
        $x_1_6 = "Really cancel the installation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HAZ_2147750353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HAZ!MTB"
        threat_id = "2147750353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 55 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 26 00 20 00 22 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 20 00 26 00 20 00 24 00 [0-48] 20 00 5b 00 20 00 33 00 20 00 5d 00 20 00 26 00 20 00 22 00 2e 00 65 00 78 00 65 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 24 00 [0-48] 20 00 5b 00 20 00 32 00 20 00 5d 00 20 00 26 00 20 00 22 00 22 00 22 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 20 00 26 00 20 00 [0-48] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = {29 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-48] 3d 00 20 00 22 00 30 00 78 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 54 00 55 00 52 00 4e 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 00 4f 00 52 00 20 00 24 00 49 00 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 24 00 49 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 49 00 53 00 49 00 4e 00 54 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_9 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2d 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JK_2147754380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JK!MTB"
        threat_id = "2147754380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://trxcheats.com/buy.php?key=" ascii //weight: 1
        $x_1_2 = "http://trxcheats.com/valida.php" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE ( $MYURL & MACHINEID ( ) )" ascii //weight: 1
        $x_1_4 = "$HFILECHECK2 = @WORKINGDIR & \"\\TRX.dll\"" ascii //weight: 1
        $x_1_5 = "STEMPFILE = @TEMPDIR & \"\\temp\" & HEX ( RANDOM ( 0 , 65535 ) , 4 )" ascii //weight: 1
        $x_1_6 = "CRYPTINTERNALDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JK_2147754380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JK!MTB"
        threat_id = "2147754380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 22 00 50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 64 00 65 00 6c 00 20 00 27 00 22 00 20 00 26 00 20 00 24 00 53 00 4d 00 4f 00 44 00 55 00 4c 00 45 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 27 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 00 49 00 4c 00 45 00 4d 00 4f 00 56 00 45 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 70 00 65 00 69 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 20 00 2d 00 6c 00 69 00 74 00 65 00 72 00 61 00 6c 00 70 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 20 00 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 41 00 72 00 63 00 68 00 69 00 76 00 65 00 20 00 2d 00 4c 00 69 00 74 00 65 00 72 00 61 00 6c 00 50 00 61 00 74 00 68 00 20 00 27 00 22 00 20 00 26 00 20 00 24 00 53 00 4d 00 4f 00 44 00 55 00 4c 00 45 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 27 00 20 00 2d 00 44 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SBR_2147770425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SBR!MSR"
        threat_id = "2147770425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.myexternalip.com/raw" wide //weight: 1
        $x_1_2 = "http://bot.whatismyipaddress.com" wide //weight: 1
        $x_1_3 = "AGETIPURL" wide //weight: 1
        $x_1_4 = "SLEEP ( GETPING" wide //weight: 1
        $x_1_5 = "M_AGENT = GETAGENTBYID " wide //weight: 1
        $x_1_6 = "SYSTEM_USESKILLBYSKILLID_FUNC_ISENABLED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MR_2147789279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MR!MTB"
        threat_id = "2147789279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$CMDLINE [ 1 ] = \"-viewer\" OR $CMDLINE [ 1 ] = \"-server\"" ascii //weight: 1
        $x_1_2 = "@TEMPDIR & \"\\JFS_Screen_Mirroring" ascii //weight: 1
        $x_1_3 = "$CMDLINE [ 0 ] >= 1 AND $CMDLINE [ 1 ] = \"-viewer" ascii //weight: 1
        $x_1_4 = "RUN ( @TEMPDIR & \"\\JFS_Screen_Mirroring\\\" & \"winvnc_server_32.exe\" & \" \" & \"-connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRR_2147789280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRR!MTB"
        threat_id = "2147789280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( \"https://mm8591.com" ascii //weight: 1
        $x_1_2 = "$VBCODE &= \"    H = (x Xor y Xor z)\" & @CRLF" ascii //weight: 1
        $x_1_3 = "$VBCODE &= \"    I = (y Xor (x Or (Not z)))\" & @CRLF" ascii //weight: 1
        $x_1_4 = "$VBCODE &= \"        lResult = lResult Xor &H80000000 Xor lX8 Xor lY8\" & @CRLF" ascii //weight: 1
        $x_1_5 = "STRINGREGEXPREPLACE ( $_THE_URL , \"https://|http://\" , \"\" )" ascii //weight: 1
        $x_1_6 = "_XXTEA_ENCRYPT" ascii //weight: 1
        $x_1_7 = "5589E5FF7514535657E8410000004142434445464748494A4B4C4D4E4F505152535455565758595A61626364" ascii //weight: 1
        $x_1_8 = "RUN ( \"regsvr32\" & CHR ( 32 ) & \"/s\" & CHR ( 32 ) & $FILE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRR_2147789280_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRR!MTB"
        threat_id = "2147789280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CHR ( 549 + -501 ) & CHR ( 621 + -501 ) & CHR ( 602 + -501 ) & CHR ( 558 + -501 ) & CHR ( 558 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 10
        $x_1_2 = "CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 1
        $x_1_3 = "CHR ( 554 + -501 ) & CHR ( 554 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 602 + -501 ) & CHR ( 600 + -501 )" ascii //weight: 1
        $x_1_4 = "CHR ( 554 + -501 ) & CHR ( 555 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 556 + -501 ) & CHR ( 554 + -501 )" ascii //weight: 1
        $x_1_5 = "CHR ( 549 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 598 + -501 ) & CHR ( 552 + -501 ) & CHR ( 555 + -501 )" ascii //weight: 1
        $x_1_6 = "CHR ( 549 + -501 ) & CHR ( 599 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RV_2147792958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RV!MTB"
        threat_id = "2147792958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DIM $PBSEQVVXI [ 2 ] = [ \"YIuFpRjcD.exe\"" ascii //weight: 3
        $x_2_2 = "YEXPNYEPQ ( $PBSEQVVXI [ 0 ]" ascii //weight: 2
        $x_1_3 = "CONSOLEWRITEERROR <> BITXOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DDF_2147793124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DDF!MTB"
        threat_id = "2147793124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "FILEINSTALL" ascii //weight: 1
        $x_1_3 = "TEMPDIR" ascii //weight: 1
        $x_1_4 = "EXECUTE" ascii //weight: 1
        $x_1_5 = "STRINGREPLACE" ascii //weight: 1
        $x_1_6 = "( 8519 + -8420 )" ascii //weight: 1
        $x_1_7 = "( 8473 + -8420 )" ascii //weight: 1
        $x_1_8 = "( 8475 + -8420 )" ascii //weight: 1
        $x_1_9 = "( 8474 + -8420 )" ascii //weight: 1
        $x_1_10 = "( 8472 + -8420 )" ascii //weight: 1
        $x_1_11 = "( 8522 + -8420 )" ascii //weight: 1
        $x_1_12 = "( 8521 + -8420 )" ascii //weight: 1
        $x_1_13 = "( 8468 + -8420 )" ascii //weight: 1
        $x_1_14 = "( 8518 + -8420 )" ascii //weight: 1
        $x_1_15 = "( 8520 + -8420 )" ascii //weight: 1
        $x_1_16 = "( 8477 + -8420 )" ascii //weight: 1
        $x_1_17 = "( 8476 + -8420 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DDFG_2147793569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DDFG!MTB"
        threat_id = "2147793569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINEXISTS" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_3 = "PROCESSEXISTS" ascii //weight: 1
        $x_1_4 = "PROCESSCLOSE" ascii //weight: 1
        $x_1_5 = "53,50,60,58,59,5,60,60,59,3,59,3,59,6,60,53,59,60,55,4,59,59,60,2,59,59" ascii //weight: 1
        $x_1_6 = "REGWRITE" ascii //weight: 1
        $x_1_7 = "ISADMIN" ascii //weight: 1
        $x_1_8 = "BITXOR" ascii //weight: 1
        $x_1_9 = "SLEEP" ascii //weight: 1
        $x_1_10 = "TEMPDIR" ascii //weight: 1
        $x_1_11 = "ISBINARY" ascii //weight: 1
        $x_1_12 = "53,50,59,59,60,58,59,59,59,4,60,60,60,58,60,57,60,54" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DA_2147795882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DA!MTB"
        threat_id = "2147795882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "GUISETSTATE" ascii //weight: 1
        $x_1_3 = "SW_SHOW" ascii //weight: 1
        $x_1_4 = "GUICREATE" ascii //weight: 1
        $x_1_5 = "EXECUTE" ascii //weight: 1
        $x_1_6 = "( 549 + -501 )" ascii //weight: 1
        $x_1_7 = "( 552 + -501 )" ascii //weight: 1
        $x_1_8 = "( 601 + -501 )" ascii //weight: 1
        $x_1_9 = "( 554 + -501 )" ascii //weight: 1
        $x_1_10 = "( 553 + -501 )" ascii //weight: 1
        $x_1_11 = "( 603 + -501 )" ascii //weight: 1
        $x_1_12 = "( 602 + -501 )" ascii //weight: 1
        $x_1_13 = "( 558 + -501 )" ascii //weight: 1
        $x_1_14 = "( 557 + -501 )" ascii //weight: 1
        $x_1_15 = "( 599 + -501 )" ascii //weight: 1
        $x_1_16 = "( 600 + -501 )" ascii //weight: 1
        $x_1_17 = "( 550 + -501 )" ascii //weight: 1
        $x_1_18 = "( 556 + -501 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RT_2147796505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RT!MTB"
        threat_id = "2147796505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "GUISETSTATE" ascii //weight: 1
        $x_1_3 = "EXECUTE" ascii //weight: 1
        $x_1_4 = "615 + -501" ascii //weight: 1
        $x_1_5 = "600 + -501" ascii //weight: 1
        $x_1_6 = "552 + -501" ascii //weight: 1
        $x_1_7 = "556 + -501" ascii //weight: 1
        $x_1_8 = "557 + -501" ascii //weight: 1
        $x_1_9 = "549 + -501" ascii //weight: 1
        $x_1_10 = "599 + -501" ascii //weight: 1
        $x_1_11 = "612 + -501" ascii //weight: 1
        $x_1_12 = "611 + -501" ascii //weight: 1
        $x_1_13 = "602 + -501" ascii //weight: 1
        $x_1_14 = "608 + -501" ascii //weight: 1
        $x_1_15 = "618 + -501" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule Trojan_Win32_AutoitInject_RW_2147796507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RW!MTB"
        threat_id = "2147796507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= DLLSTRUCTGETDATA ( DLLSTRUCTCREATE" ascii //weight: 1
        $x_1_2 = "&= CHR ( DEC ( STRINGLEFT (" ascii //weight: 1
        $x_1_3 = " EXECUTE ( BINARYTOSTRING ( \"0x536C65657028313029\" ) )" ascii //weight: 1
        $x_1_4 = "455845435554452842494E415259544F535452494E47282230783436343934433435343334433446" ascii //weight: 1
        $x_1_5 = "455845435554452842494E415259544F535452494E47282230783436343934433435343434353443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRF_2147808922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRF!MTB"
        threat_id = "2147808922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE" ascii //weight: 1
        $x_1_2 = "$VCRYPTKEY" ascii //weight: 1
        $x_1_3 = "FUNC RUNPE" ascii //weight: 1
        $x_1_4 = "$BIN_SHELLCODE &= GDWUXSZCJXJX" ascii //weight: 1
        $x_1_5 = "$EXEPATH" ascii //weight: 1
        $x_1_6 = "$VBS" ascii //weight: 1
        $x_1_7 = "$VBSPATH" ascii //weight: 1
        $x_1_8 = "$URLPATH" ascii //weight: 1
        $x_1_9 = "BINARYTOSTRING" ascii //weight: 1
        $x_1_10 = "$XOR = BITXOR" ascii //weight: 1
        $x_1_11 = "$STARTUPDIR = @USERPROFILEDIR & \"\\MdRes" ascii //weight: 1
        $x_1_12 = "\"RmClient\" , \"klist.exe\"" ascii //weight: 1
        $x_1_13 = "RunPE(@ScriptFullPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MA_2147819022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MA!MTB"
        threat_id = "2147819022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GUICTRLSETPOS ( 658 , 666 , 187 , 31 , 101 )" ascii //weight: 1
        $x_1_2 = "FILERECYCLEEMPTY ( )" ascii //weight: 1
        $x_1_3 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 47 00 45 00 58 00 50 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 22 00 [0-15] 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 54 52 49 4e 47 52 45 47 45 58 50 52 45 50 4c 41 43 45 20 28 20 22 [0-15] 22}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 49 00 4e 00 4b 00 49 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-15] 22 00 20 00 2c 00 20 00 22 00 [0-15] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 4b 49 4c 4c 20 28 20 22 [0-15] 22 20 2c 20 22 [0-15] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "INIRENAMESECTION ( " ascii //weight: 1
        $x_1_8 = "FILEDELETE ( " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_MA_2147819022_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MA!MTB"
        threat_id = "2147819022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "116"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "NERRUC_YEK" wide //weight: 50
        $x_30_2 = "usa02.info/wp-content/uploads" wide //weight: 30
        $x_30_3 = "sdaolpu/tnetnoc-pw/ofni.20asu" wide //weight: 30
        $x_20_4 = "USER\\Software\\ComCyparisSoftDev" wide //weight: 20
        $x_20_5 = "foSsirapyCmoC\\erawtfoS\\RESU" wide //weight: 20
        $x_1_6 = "UnmapViewOfFile" wide //weight: 1
        $x_1_7 = "HTTPSETUSERAGENT" wide //weight: 1
        $x_1_8 = "TAGNMHDR" wide //weight: 1
        $x_1_9 = "STRINGTRIMRIGHT" wide //weight: 1
        $x_1_10 = "STRINGTRIMLEFT" wide //weight: 1
        $x_1_11 = "STRINGREVERSE" wide //weight: 1
        $x_1_12 = "SW_HIDE" wide //weight: 1
        $x_1_13 = "SHELLEXECUTE" wide //weight: 1
        $x_1_14 = "STRINGREPLACE" wide //weight: 1
        $x_1_15 = "iplogger" wide //weight: 1
        $x_1_16 = "DecryptFileW" wide //weight: 1
        $x_1_17 = "_WINAPI_GETDISKFREESPACEEX" wide //weight: 1
        $x_1_18 = "_WINAPI_CREATEFILEEX" wide //weight: 1
        $x_1_19 = "SBACKUPFILE" wide //weight: 1
        $x_1_20 = "STRINGSTRIPWS" wide //weight: 1
        $x_1_21 = "STRINGMID" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 2 of ($x_20_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RPK_2147821595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPK!MTB"
        threat_id = "2147821595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateSemaphore" ascii //weight: 1
        $x_1_2 = "GetLastError" ascii //weight: 1
        $x_1_3 = "DISABLEUAC" ascii //weight: 1
        $x_1_4 = "EnableLUA" ascii //weight: 1
        $x_1_5 = "SLEEP ( 500 )" ascii //weight: 1
        $x_1_6 = "_BASE64DECODE" ascii //weight: 1
        $x_1_7 = "CallWindowProc" ascii //weight: 1
        $x_1_8 = "TVqQAAMAAAAEAAAA" ascii //weight: 1
        $x_1_9 = "TEMPDIR" ascii //weight: 1
        $x_1_10 = "FILEOPEN" ascii //weight: 1
        $x_1_11 = "BINARYTOSTRING" ascii //weight: 1
        $x_1_12 = "FILEWRITE" ascii //weight: 1
        $x_1_13 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_14 = "DIRREMOVE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DC_2147825234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DC!MTB"
        threat_id = "2147825234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\CxIZWvhst\\WHalVEWxc.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPV_2147826598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPV!MTB"
        threat_id = "2147826598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pfaOPkAvO.exe" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
        $x_1_3 = "FOR $KTJZSPTVAN = 0 TO 1" ascii //weight: 1
        $x_1_4 = "IF STRINGTOBINARY = SLEEP" ascii //weight: 1
        $x_1_5 = "KTJZSPTVAN" ascii //weight: 1
        $x_1_6 = "Nueva carpeta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DE_2147828941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DE!MTB"
        threat_id = "2147828941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pgpxipefmymj.exe" wide //weight: 10
        $x_10_2 = "xjumponafstf.exe" wide //weight: 10
        $x_1_3 = "ShellExecuteW" wide //weight: 1
        $x_1_4 = "DllCall" wide //weight: 1
        $x_1_5 = "WindowSpy.ahk" wide //weight: 1
        $x_1_6 = "AU3_Spy.exe" wide //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RA_2147839884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!MTB"
        threat_id = "2147839884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stealdonex" ascii //weight: 2
        $x_2_2 = "stealchromer" ascii //weight: 2
        $x_2_3 = "stealoperaer" ascii //weight: 2
        $x_2_4 = "loxoperax" ascii //weight: 2
        $x_2_5 = "loxFFoxer" ascii //weight: 2
        $x_1_6 = "filezilla\\recentservers.xml" ascii //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default" ascii //weight: 1
        $x_1_8 = "Opera Software\\Opera Stable" ascii //weight: 1
        $x_1_9 = "SharedAccess\\Parameters\\FirewallPolicy" ascii //weight: 1
        $x_1_10 = "CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_11 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RA_2147839884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!MTB"
        threat_id = "2147839884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\ASUA.exe\" , @TEMPDIR & \"\\MMtest\\ASUA.exe\" , 1 )" ascii //weight: 1
        $x_1_2 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\ATKEX.dll\" , @TEMPDIR & \"\\MMtest\\ATKEX.dll\" , 1 )" ascii //weight: 1
        $x_1_3 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\EppManifest.dll\" , @TEMPDIR & \"\\MMtest\\EppManifest.dll\" , 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RM_2147849020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RM!MTB"
        threat_id = "2147849020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINGETCLIENTSIZE ( \"ml98vCEDP\" , \"Nq57fp\" )" ascii //weight: 1
        $x_1_2 = "STRINGRIGHT ( \"EwQpPCvmBB\" , 504 )" ascii //weight: 1
        $x_1_3 = "FILEWRITELINE ( 271 , \"Fpl8oJxYf\" )" ascii //weight: 1
        $x_1_4 = "WINSETTITLE ( \"\" , \"jcbKdYWGE\" , \"1IH2BJl\" )" ascii //weight: 1
        $x_1_5 = "INIWRITESECTION ( \"lWSeV85a\" , \"HQ88\" ," ascii //weight: 1
        $x_1_6 = "STRINGREGEXPREPLACE ( \"PzcWuY3qYH\" , \"HOmRFWRzel\" ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 a7 1e 6e 01 05 ca 6f 25 67 0c 03 cb c3 65 5a 5d 4b 3e e7 d3 50 21 93 ef 5c fd 8c 0f 33 06 7b}  //weight: 1, accuracy: High
        $x_1_2 = {97 87 3c b4 33 40 9e 6a 97 71 27 c1 e9 4f fd ae 03 4f 4b 82 88 e1 71 ea a1 3d 7f 5a 80 4c 2e f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUNC EJXQUZVOUXNPFKT ( )" ascii //weight: 1
        $x_1_2 = "AUTOITSETOPTION <> BITOR" ascii //weight: 1
        $x_1_3 = "DIM $XLNDESXNP [ 2 ] = [ \"fQoOFhrIo.exe\" ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[ 2 ] = [ \"PUmgHoIBc\\PUmgHoIBc.exe\" , \"PUmgHoIBc" ascii //weight: 5
        $x_1_2 = "TCPSEND <> @WINDOWSDIR" ascii //weight: 1
        $x_1_3 = "DRIVEGETDRIVE <> TCPSHUTDOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RPY_2147892876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPY!MTB"
        threat_id = "2147892876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN SHELLEXECUTE ( @WORKINGDIR & CHR (" wide //weight: 1
        $x_1_2 = ".mp3.exe" wide //weight: 1
        $x_1_3 = "BITSHIFT <> RUN" wide //weight: 1
        $x_1_4 = "ASSIGN <> STRINGSPLIT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPA_2147892931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPA!MTB"
        threat_id = "2147892931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {54 23 05 58 45 20 11 32 54 23 05 58 45 20 11 32 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad 00 00 e1 bb 3a 21 a5 29 e3 ec e7 0b 98 2e 40 bd e1 9a}  //weight: 2, accuracy: High
        $x_2_2 = {64 95 61 e7 b6 4d 74 f8 00 00 e5 1a 58 35 81 34 92 a0 6c ac 25 4b 12 38 cb 35 db 1f 22 fd 40 23 79 e0 20 ce ca ea 1e 0b 89 9f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPX_2147893063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPX!MTB"
        threat_id = "2147893063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"Fi\" & \"leRe" wide //weight: 1
        $x_1_2 = "ad(FileO\" & \"pen" wide //weight: 1
        $x_1_3 = "@Tem\" & \"pD\" & \"ir" wide //weight: 1
        $x_1_4 = "& \"\"\\nouses\"\")" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPX_2147893063_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPX!MTB"
        threat_id = "2147893063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN SHELLEXECUTE ( @WORKINGDIR & CHR (" wide //weight: 1
        $x_1_2 = "WHILE DLLCALLBACKGETPTR" wide //weight: 1
        $x_1_3 = "Los prisioneros" wide //weight: 1
        $x_1_4 = ".mp3" wide //weight: 1
        $x_1_5 = "CONTROLHIDE <> ASIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[ 2 ] = [ \"pfaOPkAvO.exe\" , \"" ascii //weight: 3
        $x_1_2 = "DRIVEGETSERIAL" ascii //weight: 1
        $x_1_3 = "FILECREATESHORTCUT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BITAND <> BITXOR" ascii //weight: 1
        $x_1_2 = "CONTROLSHOW <> BITXOR" ascii //weight: 1
        $x_4_3 = "DIM $STTGTWPDQ [ 2 ] = [ \"QhIcjewKt.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINGETCLIENTSIZE ( $Y3134KYL , \"TuD3rVEmgfWo\" )" ascii //weight: 1
        $x_1_2 = "WINWAITACTIVE ( $Z3338OV0YC , \"nbSuWsG9i\" , 2555 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= [ \"LmwIJMGUM\\LmwIJMGUM.exe\" , \"LmwIJMGUM\\" ascii //weight: 1
        $x_1_2 = "TCPSTARTUP <> TCPNAMETOIP" ascii //weight: 1
        $x_1_3 = "DRIVEGETDRIVE <> SHELLEXECUTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\CurrentVersion\\Explorer\\Advanced\" , \"HideFileExt\"" ascii //weight: 1
        $x_1_2 = "RUN ( @WINDOWSDIR & \"\\svhost.exe\" ) )" ascii //weight: 1
        $x_1_3 = "STRING ( RANDOM ( 1 , 10 ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$A31333431SKZD [ 6 ] = [ 170 / 2 , 33 + 33 , 188 + -77 , 84 + 33 , 1650 / 15 , 34 + 66 ]" ascii //weight: 1
        $x_1_2 = "= STRINGFROMASCIIARRAY ( $A31333431SKZD )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIRCREATE ( \"KyzfoPECz0\" )" ascii //weight: 1
        $x_1_2 = "STRINGREGEXPREPLACE ( \"uuiNN4Bl8\" , \"dFyKBLBi\" , \"Z9kL7WKZbk\" )" ascii //weight: 1
        $x_1_3 = "WINMOVE ( \"2APCvd3NXj\" , \"64\" , 641 , 561 , 199 , 612 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$STEMPNAME &= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( $F )" ascii //weight: 1
        $x_1_3 = "$DOWNLOAD_URL = \"http://172.104.65.137/explorer.exe" ascii //weight: 1
        $x_1_4 = "$EX = @TEMPDIR & \"\\explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUNC TOUMATGQXUNGMDO ( )" ascii //weight: 1
        $x_1_2 = "BITROTATE <> BITXOR" ascii //weight: 1
        $x_1_3 = "ZQTGYAQBJ ( $QRJXDNIAA [ 0 ] , $QRJXDNIAA [ $STJRUKKWB ] )" ascii //weight: 1
        $x_1_4 = "FOR $STJRUKKWB = 0 TO 1" ascii //weight: 1
        $x_1_5 = "BITSHIFT <> SPLASHTEXTON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RG_2147901484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RG!MTB"
        threat_id = "2147901484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIM $LMOYRITOI [ 2 ] = [ \"tUjZjRkQo.exe\"" ascii //weight: 1
        $x_1_2 = "BITROTATE <> BINARY" ascii //weight: 1
        $x_1_3 = "PVMKXXPOQ ( $LMOYRITOI [ 0 ]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RG_2147901484_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RG!MTB"
        threat_id = "2147901484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGREGEXPREPLACE ( \"udH\" , \"3mWA95Amnd\" , \"JoPuRsy4F\" )" ascii //weight: 1
        $x_1_2 = "INIDELETE ( \"AOtNZ6qGWz\" , \"A8c0G9WMg7\" , \"yM6DmlfXS6\" )" ascii //weight: 1
        $x_1_3 = "WINMENUSELECTITEM ( \"MiKhuZq2\" , \"rQT4UZQsHs\" , \"default\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RH_2147901485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RH!MTB"
        threat_id = "2147901485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 95 70 1c f1 48 6d fa ab 82 0c dd e4 31 68 46 bc 77 a1 09 af d8 d0 85 05 fa 8d 48 b5 77 09 85}  //weight: 1, accuracy: High
        $x_1_2 = {fd 71 bc c3 f2 48 c7 9e e8 f2 f8 8d b0 f5 3e f6 5b f0 ed 42 9b f2 7e 1a be 26 aa 35 84 e6 ec 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_KAA_2147902504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAA!MTB"
        threat_id = "2147902504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 94 98 79 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMBG_2147902654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMBG!MTB"
        threat_id = "2147902654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 38 6e a5 c9 a1 2f b0 88 a6 fd a2 89 6f e6 6b a0 28 ee 92 37 c4 a3 ae 9b 5d 72 b3 cd 21 0e 4f de ed 27 0a 91 15 e8 b6 b0 57 6a 8b 0c 39 41 91}  //weight: 1, accuracy: High
        $x_1_2 = {79 f8 1d bc 70 ef 9a 68 74 6f 21 44 38 a8 a7 a3 fe fe ca 11 a9 98 3c ba 92 b2 e2 54 b9 da 69 2f e5 aa 92 22 e9 b4 34 43 78 16 0a e6 69 4a 1c 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RJ_2147903140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RJ!MTB"
        threat_id = "2147903140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILESETTIME ( \"y78JvjaH\" , \"hVWzAeQ\" , 145 )" ascii //weight: 1
        $x_1_2 = "FILESAVEDIALOG ( \"MtPkWi\" , \"i\" , \"CYV0Nwm\" , \"vraQt\"" ascii //weight: 1
        $x_1_3 = "FILEWRITELINE ( 414 , \"ah90WDgUx\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RK_2147903141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RK!MTB"
        threat_id = "2147903141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEMOVE ( \"8DQhilug\" , \"9elx\" , 554 )" ascii //weight: 1
        $x_1_2 = "WINWAITNOTACTIVE ( \"hTTNh\" , \"LrO\" , 809 )" ascii //weight: 1
        $x_1_3 = "DIRCOPY ( \"fIWCGBiuok\" , \"MnekZj\" , 557 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RL_2147903142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RL!MTB"
        threat_id = "2147903142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TOOLTIP ( \"lipYb2vE\" , 579 , 969 , \"mkGG23\" )" ascii //weight: 1
        $x_1_2 = "FILESELECTFOLDER ( \"vZvjMT6i\" , \"jU2riM\" , 379 , \"Epass\" )" ascii //weight: 1
        $x_1_3 = "WINGETPROCESS ( \"KiCp6R6C\" , \"BA1ft24k\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ASA_2147903146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASA!MTB"
        threat_id = "2147903146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " STRINGREGEXPREPLACE ( $C3030RIEQAZ , \"ZqaxuT\" , $M33ATKX4 )" ascii //weight: 1
        $x_1_2 = " $X32373831CP0 = DLLCALL ( U3130F2EA ( \"mgtpgn54\" , 2 )" ascii //weight: 1
        $x_1_3 = " $X32373831CP0 = EXECUTE ( \"$X32373831CP0\" & U3130F2EA ( \"]2_\" , 2 ) )" ascii //weight: 1
        $x_1_4 = " $J32373738GGTHRH = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\sulfhydric\" ) )" ascii //weight: 1
        $x_1_5 = " STRINGREGEXPREPLACE ( \"rsiai\" , $F3189KCR3Q , \"TvnOuz5YiJ\" )" ascii //weight: 1
        $x_1_6 = " $U323438369O = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\Grinnellia\" ) )" ascii //weight: 1
        $x_1_7 = " $N32343931S6NZAM6 = EXECUTE ( \"$N32343931s6NZam6[0]\" )" ascii //weight: 1
        $x_1_8 = " LOCAL $N32343931S6NZAM6 = DLLCALL ( BINARYTOSTRING ( \"0x6B65726E656C3332\" ) " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASB_2147903147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASB!MTB"
        threat_id = "2147903147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " $M313138380K = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\emboweling\" ) )" ascii //weight: 1
        $x_1_2 = " $V31313737KQWPP1W &= EXECUTE ( \"Chr($L313138308bMKVg)\" )" ascii //weight: 1
        $x_1_3 = " DLLCALL ( F341HF ( \"tn{wnu<;\" , 9 ) " ascii //weight: 1
        $x_1_4 = " $K31383430TUY = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\subpredication\" ) )" ascii //weight: 1
        $x_1_5 = " LOCAL $C31383437CD4C = DLLCALL ( R37WFON0L ( \"uo|xov=<\" , 10 )" ascii //weight: 1
        $x_1_6 = " $C31383437CD4C = EXECUTE ( \"$C31383437cd4C[0]\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASC_2147903150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASC!MTB"
        threat_id = "2147903150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " DIRCOPY ( \"tPX5\" , $V31EDFZDNFV , 550 )" ascii //weight: 1
        $x_1_2 = " REGDELETE ( \"WFhRMWHexn\" , \"xAyLL4874o\" )" ascii //weight: 1
        $x_1_3 = " FILEMOVE ( \"GDFZp5JS\" , \"qdqOKcP\" , 218 )" ascii //weight: 1
        $x_1_4 = " DLLCALL ( W377HYKP ( \"qkxtkr98\" , 6 ) , W377HYKP ( \"vzx\" , 6 )" ascii //weight: 1
        $x_1_5 = " DLLCALL ( H39NZSX ( \"cmjv]t+:\" , 8 ) , H39NZSX ( \"h|j\" , 8 ) , H39NZSX ( \"Nqj|midIdtgk\" , 8 )" ascii //weight: 1
        $x_1_6 = " DIRCOPY ( \"vvzJo4nb\" , \"H2yNHayk9J\" , 645 )" ascii //weight: 1
        $x_1_7 = " FILEMOVE ( \"nUNSTg\" , \"rwM3Pn\" , 923 )" ascii //weight: 1
        $x_1_8 = " STRINGREGEXPREPLACE ( \"SFB9C\" , \"wiu5GTuPib\" , $K30KANA )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASD_2147903151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASD!MTB"
        threat_id = "2147903151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " STRINGREGEXPREPLACE ( \"HJk6NXK0N\" , \"l6xMrQnYD\" , \"OqzJm6\" )" ascii //weight: 1
        $x_1_2 = " DLLCALL ( B387PQ ( \"smzvmt;:\" , 8 ) , B387PQ ( \"x|z\" , 8 ) , B387PQ ( \"^qz|}itIttwk\" , 8 )" ascii //weight: 1
        $x_1_3 = " FILEWRITELINE ( 205 , \"j3mb7jONh\" )" ascii //weight: 1
        $x_1_4 = " FILESETTIME ( \"vMsF\" , \"g\" , 61 )" ascii //weight: 1
        $x_1_5 = " DLLCALL ( V37TL64 ( \"qkxtkr98\" , 6 ) , V37TL64 ( \"vzx\" , 6 ) , V37TL64 ( \"\\oxz{grGrrui\" , 6 )" ascii //weight: 1
        $x_1_6 = " FILEWRITELINE ( 498 , \"dYSq9b9\" )" ascii //weight: 1
        $x_1_7 = " FILESETTIME ( \"SAtNFQsjl9\" , \"FR6iBN\" , 421 )" ascii //weight: 1
        $x_1_8 = " DIRCREATE ( \"VdVqk5W\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_GPAA_2147903248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPAA!MTB"
        threat_id = "2147903248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( \"http" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( \"msedge.exe\" , \"https" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE ( \"chrome.exe\" , \"https" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( \"firefox.exe\" , \"http" ascii //weight: 1
        $x_1_5 = "SLEEP ( 60 * 20 * 1000 )" ascii //weight: 1
        $x_1_6 = "SLEEP ( 60 * 10 * 1000 )" ascii //weight: 1
        $x_1_7 = "UNTIL 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPB_2147904686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPB!MTB"
        threat_id = "2147904686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "wotkl.ru/wp-content/cache/blogs/imagem01.exe" ascii //weight: 5
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPD_2147904687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPD!MTB"
        threat_id = "2147904687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "115,99,114,105,112,116,46,83,108,101,101,112" ascii //weight: 1
        $x_1_2 = "114,101,97,116,101,79,98,106,101,99,116,40,34,87,83,99,114,105,112,116,46,83,104,101,108,108,34,41,46,82,117,110" ascii //weight: 1
        $x_5_3 = "104,116,116,112,58,47,47,119,119,119,46,57,54,56,56,46,108,97,47,63,120,99,99" ascii //weight: 5
        $x_5_4 = "runner=runner&chr(strs" ascii //weight: 5
        $x_5_5 = "Execute runner" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_KAB_2147906224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAB!MTB"
        threat_id = "2147906224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGSPLIT" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR & CHR" ascii //weight: 1
        $x_1_3 = "TO ( STRINGLEN" ascii //weight: 1
        $x_1_4 = "& CHR ( 92 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JNAA_2147906439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JNAA!MTB"
        threat_id = "2147906439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sdxitong.exe" ascii //weight: 2
        $x_1_2 = "BITXOR ( $A03A4B13659 , 512 )" ascii //weight: 1
        $x_1_3 = "BITXOR ( $A03A4B13659 , 1024 )" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( @TEMPDIR )" ascii //weight: 1
        $x_1_5 = "://xiaohei.xiuchufang.com/config.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_KTAA_2147908315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KTAA!MTB"
        threat_id = "2147908315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( \"chrome.exe\" , \"https://www" ascii //weight: 2
        $x_2_2 = "SLEEP ( 2000 )" ascii //weight: 2
        $x_2_3 = "SLEEP ( 500 )" ascii //weight: 2
        $x_1_4 = "STRINGSPLIT (" ascii //weight: 1
        $x_1_5 = "BITOR ( BITSHIFT" ascii //weight: 1
        $x_1_6 = "00EB0231C021C07502EB07B801000000EB0231C021C0740731C0E969010000C7" ascii //weight: 1
        $x_1_7 = "EB05B80100000021C07502EB07B801000000EB0231C021C07502EB07B8010000" ascii //weight: 1
        $x_1_8 = "TRACKMOUSEEVENT (" ascii //weight: 1
        $x_1_9 = "OPT ( \"MouseCoordMode\" ," ascii //weight: 1
        $x_1_10 = "REGREAD ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_LYAA_2147909346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.LYAA!MTB"
        threat_id = "2147909346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EXECUTE ( \"@tempdir\" )" ascii //weight: 2
        $x_2_2 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(F\" & \"il\" & \"e\" & \"O\" & \"p\" & \"e\" & \"n\" & \"(\" & " ascii //weight: 2
        $x_2_3 = "t\" & \"e\" & \"m\" & \"p\" & \"d\" & \"i\" & \"r" ascii //weight: 2
        $x_2_4 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"pl\" & \"ac\" & \"e" ascii //weight: 2
        $x_1_5 = "( 216 + -109 )" ascii //weight: 1
        $x_1_6 = "( 977 + -876 )" ascii //weight: 1
        $x_1_7 = "( 511 + -397 )" ascii //weight: 1
        $x_1_8 = "( 460 + -350 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MPAA_2147910169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MPAA!MTB"
        threat_id = "2147910169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PUmgHoIBc\\PUmgHoIBc.exe" ascii //weight: 2
        $x_1_2 = "PUmgHoIBc\\y2mate.com" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SZ_2147910546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SZ!MTB"
        threat_id = "2147910546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 74 00 65 00 6d 00 70 00 64 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 74 65 6d 70 64 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-47] 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 46 49 4c 45 52 45 41 44 20 28 20 46 49 4c 45 4f 50 45 4e 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-47] 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 4f 00 52 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 4f 52 20 24 [0-47] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_NTAA_2147911490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NTAA!MTB"
        threat_id = "2147911490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(A\" & \"s\" & \"c(St\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO\" & \"pen(@\" & \"te\" & \"mp\" & \"dir" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"S\" & \"tr\" & \"ing\" & \"Re\" & \"pla\" & \"ce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ODAA_2147911933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ODAA!MTB"
        threat_id = "2147911933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO\" & \"pen(@\" & \"te\" & \"mp\" & \"dir" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"p\" & \"l\" & \"a\" & \"c\" & \"e" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(A\" & \"s\" & \"c(St\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_OKAA_2147912176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.OKAA!MTB"
        threat_id = "2147912176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "[ 2 ] = [ \"PUmgHoIBc\\PUmgHoIBc.exe\" , \"PUmgHoIBc" ascii //weight: 4
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_OWAA_2147912500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.OWAA!MTB"
        threat_id = "2147912500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENVGET ( \"TEMP\" ) &" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"FileRead(FileOpen(EnvGet(\"\"TEMP\"\")  &" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l" ascii //weight: 1
        $x_1_4 = "&= CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PFAA_2147912752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PFAA!MTB"
        threat_id = "2147912752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&= CHR ( ASC ( STRINGMID" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"Stri\" & \"ngLe\" & \"ft" ascii //weight: 1
        $x_1_3 = "@TEMPDIR &" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"Fil\" & \"eRe\" & \"ad(Fil\" & \"eOp\" & \"en(@Tem\" & \"pDir &" ascii //weight: 1
        $x_1_5 = "EXECUTE ( \"DllC\" & \"all" ascii //weight: 1
        $x_1_6 = "EXECUTE ( \"DllStruc\" & \"tCreate" ascii //weight: 1
        $x_1_7 = "EXECUTE ( \"DllS\" & \"tru\" & \"ctSe\" & \"tDat\" & \"a" ascii //weight: 1
        $x_1_8 = "EXECUTE ( \"Dl\" & \"lCall\" & \"Add\" & \"ress(\"\"in\"\" & \"\"t\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PKAA_2147913667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PKAA!MTB"
        threat_id = "2147913667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= @TEMPDIR" ascii //weight: 1
        $x_1_2 = "&= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 1
        $x_1_3 = "= \"Crnaptica2!\"" ascii //weight: 1
        $x_1_4 = "MSGBOX ( 0 , \"Flow's Encryption\" , \"Your files has been encrypted, contact me on discord for more info: flow#1337\" )" ascii //weight: 1
        $x_1_5 = "_CRYPT_ENCRYPTFILE ( $FILE , $FILE & \".flowEncryption\" , $KEY , $CALG_AES_256 )" ascii //weight: 1
        $x_1_6 = "= DRIVEGETDRIVE" ascii //weight: 1
        $x_1_7 = "( @USERPROFILEDIR & \"\\Downloads\" )" ascii //weight: 1
        $x_1_8 = "( @USERPROFILEDIR & \"\\Pictures\" )" ascii //weight: 1
        $x_1_9 = "( @USERPROFILEDIR & \"\\Music\" )" ascii //weight: 1
        $x_1_10 = "( @USERPROFILEDIR & \"\\Videos\" )" ascii //weight: 1
        $x_1_11 = "( @USERPROFILEDIR & \"\\Documents\" )" ascii //weight: 1
        $x_1_12 = "( @USERPROFILEDIR & \"\\AppData\" )" ascii //weight: 1
        $x_1_13 = "( @USERPROFILEDIR & \"\\\" )" ascii //weight: 1
        $x_1_14 = "( \"C:\\\" & \"\\\" )" ascii //weight: 1
        $x_1_15 = "( @DESKTOPDIR )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMAD_2147915080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMAD!MTB"
        threat_id = "2147915080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @COMSPEC & \" /c \" & \"taskkill /f /im svchost.exe\" , \"\" , @SW_HIDE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PHAA_2147915226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PHAA!MTB"
        threat_id = "2147915226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BITOR (" ascii //weight: 1
        $x_1_2 = "STRINGSPLIT ( $URLS , \",\" , 2 )" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE (" ascii //weight: 1
        $x_1_4 = "_DOWNLOADFILE ( $" ascii //weight: 1
        $x_1_5 = "STRINGREGEXPREPLACE ( $SURL , \"^.*/\" , \"\" )" ascii //weight: 1
        $x_1_6 = "@TEMPDIR & \"/\" & $SFILE" ascii //weight: 1
        $x_1_7 = "INETGET ( $SURL , $SDIRECTORY , 17 , 1 )" ascii //weight: 1
        $x_1_8 = "INETCLOSE (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAUY_2147915594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAUY!MTB"
        threat_id = "2147915594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= BITOR ( $FILE_SHARE_READ , $FILE_SHARE_WRITE , $FILE_SHARE_DELETE )" ascii //weight: 1
        $x_1_2 = ".GenerateExecutable = ( STRINGRIGHT ( $SFILENAME , 4 ) = \".exe\" )" ascii //weight: 1
        $x_1_3 = "\"054831C0EB0748C7C0010000004821C07502EB0948C7C001000000EB034831C0\" & \"4821C074084831C04863C0EB7748C744242800000000" ascii //weight: 1
        $x_1_4 = "( STRINGLEFT ( $SHEX , 2 ) == \"0x\" ) THEN $SHEX = \"0x\" & $SHEX" ascii //weight: 1
        $x_1_5 = {3d 00 20 00 5f 00 48 00 45 00 58 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 5f 48 45 58 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 [0-63] 22 20 26 20 22 [0-63] 22 20 26 20 22 [0-63] 22 20 26 20 22 [0-63] 22}  //weight: 1, accuracy: Low
        $x_1_7 = "\"3B7C24287C4F4C8B7C24604C037C24284C897C2430488B6C2430807D00007405\" & \"4831C0EB0748C7C0010000004821C0741C4C8B7C2468" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_SKAI_2147915990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKAI!MTB"
        threat_id = "2147915990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 [0-10] 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 57 52 49 54 45 [0-10] 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-42] 22 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-46] 20 00 2c 00 20 00 22 00 [0-46] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-46] 20 2c 20 22 [0-46] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 28 00 [0-47] 2c 00 20 00 [0-47] 20 00 2b 00}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 42 69 74 58 4f 52 28 [0-47] 2c 20 [0-47] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_RVAA_2147916311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RVAA!MTB"
        threat_id = "2147916311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$TEMPFOLDER & \"\\s\"" ascii //weight: 1
        $x_1_2 = "$TEMPFOLDER & \"\\Tx.pif\"" ascii //weight: 1
        $x_1_3 = "DOWNLOADTEXTFROMURL ( $URL )" ascii //weight: 1
        $x_2_4 = "https://nkprotect.net/Ho.txt" ascii //weight: 2
        $x_2_5 = "https://nkprotect.net/Tx.pif" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAU_2147916387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAU!MTB"
        threat_id = "2147916387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 [0-10] 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 57 52 49 54 45 [0-10] 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-42] 22 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-46] 22 00 20 00 2c 00 20 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 [0-46] 22 20 2c 20 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 28 00 [0-47] 2c 00 20 00 [0-47] 20 00 2b 00}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 42 69 74 58 4f 52 28 [0-47] 2c 20 [0-47] 20 2b}  //weight: 1, accuracy: Low
        $x_1_13 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 22 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 22 00 22 00 2c 00 20 00 22 00 22 00 70 00 74 00 72 00 22 00 22 00 2c 00 20 00 22 00 22 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 22 00 22 00 2c 00 20 00 22 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 22 00 2c 00 20 00 22 00 22 00 30 00 22 00 22 00 2c 00 20 00 22 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 22 00 2c 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00 4c 00 65 00 6e 00 28 00 24 00 [0-47] 29 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_14 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 22 22 6b 65 72 6e 65 6c 33 32 22 22 2c 20 22 22 70 74 72 22 22 2c 20 22 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 22 22 2c 20 22 22 64 77 6f 72 64 22 22 2c 20 22 22 30 22 22 2c 20 22 22 64 77 6f 72 64 22 22 2c 20 42 69 6e 61 72 79 4c 65 6e 28 24 [0-47] 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_AutoitInject_KAD_2147917511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAD!MTB"
        threat_id = "2147917511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 [0-40] 22 00 20 00 29 00 20 00 26 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "&= CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SKL_2147917643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKL!MTB"
        threat_id = "2147917643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 43 68 22 20 26 20 22 72 28 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-42] 20 2c 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_TEAA_2147917672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.TEAA!MTB"
        threat_id = "2147917672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\iyGRDanyb\\dYIoaczdR.exe\" )" ascii //weight: 2
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR & \"\\iyGRDanyb\\" ascii //weight: 1
        $x_1_3 = "- Raccourci.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAV_2147918776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAV!MTB"
        threat_id = "2147918776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 [0-47] 2c 00 20 00 [0-47] 2c 00 20 00 24 00 [0-47] 2c 00 20 00 [0-42] 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 [0-47] 2c 20 [0-47] 2c 20 24 [0-47] 2c 20 [0-42] 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_NB_2147919154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NB!MTB"
        threat_id = "2147919154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rblxhubdeploy.rand744.nl" ascii //weight: 3
        $x_1_2 = "ExecQuery ( \"Select * from Win32_OperatingSystem\" )" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTEWAIT ( \"powershell\" , \"start-process -verb runas 'cmd.exe' -argumentlist" ascii //weight: 1
        $x_1_4 = "webserver\\apache\\www" ascii //weight: 1
        $x_1_5 = "c:\\Windows\\System32\\Drivers\\etc\\hosts &&" ascii //weight: 1
        $x_1_6 = "_BINARYCALL_BASE64DECODE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NE_2147920143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NE!MTB"
        threat_id = "2147920143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = {3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 [0-48] 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 33 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 31 20 54 4f 20 [0-48] 20 28 20 24 [0-48] 20 29 20 53 54 45 50 20 33}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-48] 20 2c 20 24 [0-48] 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {28 00 20 00 22 00 63 00 68 00 61 00 72 00 5b 00 22 00 20 00 26 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 2b 00 20 00 31 00 20 00 26 00 20 00 22 00 5d 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {28 20 22 63 68 61 72 5b 22 20 26 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-48] 20 29 20 2b 20 31 20 26 20 22 5d 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 [0-48] 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {26 3d 20 43 48 52 20 28 20 [0-48] 20 28 20 24 [0-48] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-48] 20 2c 20 31 20 2c 20 24 [0-48] 20 29}  //weight: 1, accuracy: Low
        $x_1_13 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 3d 00 20 00 22 00 [0-16] 22 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_14 = {49 46 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-48] 20 2c 20 32 20 29 20 3d 20 22 [0-16] 22 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_15 = "= DLLCALL ( DLLOPEN (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

