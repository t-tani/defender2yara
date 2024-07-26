rule Trojan_Win64_Zusy_RB_2147840019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RB!MTB"
        threat_id = "2147840019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c9 66 90 8d 41 a5 30 04 0a 48 ff c1 48 83 f9 0c 72 f1 c6 42 0d 00}  //weight: 1, accuracy: High
        $x_1_2 = "poofer_update.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RK_2147842776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RK!MTB"
        threat_id = "2147842776"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avtest\\projects\\RedTeam\\c2implant\\implant" ascii //weight: 1
        $x_1_2 = "yarttdn.de" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\tnalpmi.exe" ascii //weight: 1
        $x_1_4 = "A Zee Too Im-Plant" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_BV_2147845936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.BV!MTB"
        threat_id = "2147845936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Popsegkfwoieswgjiwoehgioerj" ascii //weight: 2
        $x_2_2 = "Vrheroigjw4oiughjser" ascii //weight: 2
        $x_2_3 = "CreateMutexW" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_BW_2147845937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.BW!MTB"
        threat_id = "2147845937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UisgoseioijegioweAosjeghioesjh" ascii //weight: 2
        $x_2_2 = "YioprgoipwrQoogjisejgies" ascii //weight: 2
        $x_2_3 = "kflgskrgopseopihsejhij" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RG_2147889353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RG!MTB"
        threat_id = "2147889353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c7 48 89 5c 24 30 c7 44 24 28 e8 03 00 00 c7 44 24 20 02 00 00 00 48 89 c1 ba 0a 04 00 00 45 31 c0 45 31 c9 ff 15 73 c2 45 00 48 81 7d e0 0a 04 00 00 75 2b c7 85 20 02 00 00 00 00 00 00 48 8d 95 20 02 00 00 48 89 f9 ff 15 d7 c1 45 00}  //weight: 1, accuracy: High
        $x_1_2 = "E:\\Projects\\multiloader\\bin\\Release\\inj.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_YAB_2147896915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.YAB!MTB"
        threat_id = "2147896915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 41 8b d1 c1 ea 10 89 05 7f 04 04 00 49 63 88 ?? ?? ?? ?? 49 8b 80 ?? ?? ?? ?? 88 14 01 41 8b d1 48 8b 05 5c 03 04 00 c1 ea 08 ff 80 88 00 00 00 48 8b 05 4c 03 04 00 48 63 88 88 00 00 00 48 8b 80 b0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMBC_2147898998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMBC!MTB"
        threat_id = "2147898998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 41 58 30 44 0d a8 48 ff c1 48 83 f9 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AUZ_2147899195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AUZ!MTB"
        threat_id = "2147899195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 15 66 af 03 00 48 8b cb 48 89 05 14 30 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 67 af 03 00 48 8b cb 48 89 05 05 30 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 70 af 03 00 48 8b cb 48 89 05 f6 2f 14 00 ff 15 ?? ?? ?? ?? 48 8d 15 71 af 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZA_2147901505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZA!MTB"
        threat_id = "2147901505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e8 10 57 00 00 33 d2 48 8d 8c 24 ?? ?? ?? ?? e8 69 1c 00 00 48 8b 8c 24 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 89 41 40 48 8d 8c 24 50 01}  //weight: 3, accuracy: Low
        $x_3_2 = {eb 10 33 db 89 9c 24 ?? ?? ?? ?? 48 8d 35 a2 37 fd ff bf ?? ?? ?? ?? 8b cf e8 16 36}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hus Loader.pdb" ascii //weight: 1
        $x_1_2 = "Key doesnt exist !" ascii //weight: 1
        $x_1_3 = "dsc.gg/rive" ascii //weight: 1
        $x_1_4 = "HusClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start cmd /C" ascii //weight: 1
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "ReadProcessMemory" ascii //weight: 1
        $x_1_4 = "VeriSignMPKI-2-3950" ascii //weight: 1
        $x_1_5 = "OR_1P4RP41" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NZ_2147901866_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NZ!MTB"
        threat_id = "2147901866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HiveNightmare.pdb" ascii //weight: 2
        $x_2_2 = "list snapshots with vssadmin list shadows" ascii //weight: 2
        $x_2_3 = "permission issue rather than vulnerability issue, make sure you're running from a folder where you can write to" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RX_2147903573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RX!MTB"
        threat_id = "2147903573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 ca 49 8b c0 80 e1 07 c0 e1 03 48 d3 e8 42 30 04 0a 48 ff c2 48 81 fa 0b 27 00 00 72 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GZZ_2147905373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GZZ!MTB"
        threat_id = "2147905373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im ProcessHacker.exe" ascii //weight: 1
        $x_1_2 = "taskkill /f /im FiddlerEverywhere.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f /im OllyDbg.exe" ascii //weight: 1
        $x_1_4 = "taskkill /f /im Ida64.exe" ascii //weight: 1
        $x_1_5 = "\\\\.\\kprocesshacker" ascii //weight: 1
        $x_1_6 = "cdn.discordapp.com/attachments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 d0 48 c1 e8 02 48 31 d0 48 89 c2 48 c1 ea 15 48 31 c2 48 89 d0 48 c1 e8 16 48 31 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_EC_2147905565_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.EC!MTB"
        threat_id = "2147905565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Balling!" ascii //weight: 2
        $x_2_2 = "79.174.92.22" ascii //weight: 2
        $x_2_3 = "Fatal error in host name resolving" ascii //weight: 2
        $x_1_4 = {48 89 44 24 30 48 c7 44 24 48 87 69 00 00 48 c7 44 24 40 84 03 00 00 b9 02 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_NC_2147908386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.NC!MTB"
        threat_id = "2147908386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell -NoProfile -ExecutionPolicy bypass -windowstyle hidden -Command" ascii //weight: 5
        $x_5_2 = "-NoProfile -windowstyle hidden -ExecutionPolicy bypass -Command " ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RM_2147908400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RM!MTB"
        threat_id = "2147908400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NeekroAgain\\Desktop\\esp + aim meu ultimo\\esp final testar coisas - Copia - Copia - Copia - Copia\\Valorant-External-main\\x64\\Release" ascii //weight: 1
        $x_1_2 = "rasfdtyasdas.pdb" ascii //weight: 1
        $x_1_3 = "sdfgdfgfd.pdb" ascii //weight: 1
        $x_1_4 = "iasuidosdf.pdb" ascii //weight: 1
        $x_1_5 = "im MESTEResp final testar coisas - Copia - Copia - Copia - CopiaValorant - External - mainValorantOptimusPrinceps.ttf" ascii //weight: 1
        $x_1_6 = "\\temple.rar" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Zusy_AJJ_2147910064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AJJ!MTB"
        threat_id = "2147910064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 0f 1f 40 ?? 8d 48 58 41 30 0c 00 48 ff c0 48 83 f8 0b 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 0f 1f 84 00 ?? ?? ?? ?? 8d 50 58 30 14 08 48 ff c0 48 83 f8 43 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AMAA_2147912509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AMAA!MTB"
        threat_id = "2147912509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 ff e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fe e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fd e8}  //weight: 2, accuracy: Low
        $x_2_2 = "v5.mrmpzjjhn3sgtq5w.pro" ascii //weight: 2
        $x_1_3 = "isapi/isapiv5.dll/v5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AR_2147913081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AR!MTB"
        threat_id = "2147913081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 48 8b f9 b9 ?? ?? 00 00 ff 15 ?? ?? 00 00 b9 ?? ?? 00 00 48 8d 54 24 ?? 48 8b f0 ff 15 ?? ?? 00 00 48 8b 4f 08 0f b7 09 ff 15 ?? ?? 00 00 48 8b 0f 48 8b 09 ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 4c 8b ?? 48 8b 49 08 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 48 8b 09 ff 15 ?? ?? 00 00 b9 01 01 00 00 48 8d 54 24 ?? ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 ?? ?? 00 00 4c 8b ?? 48 8d 54 24 ?? b9 01 01 00 00 ff 15 ?? ?? 00 00 49 8b ?? 08 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 48 8b 09 ff 15 ?? ?? 00 00 ba 02 00 00 00 8b ca 44 8d 42 0f ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Zusy_CCIZ_2147913302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.CCIZ!MTB"
        threat_id = "2147913302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shy Product+" ascii //weight: 1
        $x_1_2 = "Dont Crack My Program" ascii //weight: 1
        $x_1_3 = "KsDumperClient.exe" wide //weight: 1
        $x_1_4 = "x64dbg.exe" wide //weight: 1
        $x_1_5 = "cheatengine - x86_64" wide //weight: 1
        $x_1_6 = "Fiddler.exe" wide //weight: 1
        $x_1_7 = "Wireshark.exe" wide //weight: 1
        $x_1_8 = "idaq64.exe" wide //weight: 1
        $x_1_9 = "idaq.exe" wide //weight: 1
        $x_1_10 = "ollydbg.exe" wide //weight: 1
        $x_1_11 = "HxD.exe" wide //weight: 1
        $x_1_12 = "procmon.exe" wide //weight: 1
        $x_1_13 = "\\\\.\\KsDumper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_GP_2147913590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.GP!MTB"
        threat_id = "2147913590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 61 d4 66 41 0f db d0 66 0f 67 ca 66 0f ef c8 0f 11 09 4c 39 c1}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 da 49 89 d8 48 c1 fa 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_CCIG_2147913639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.CCIG!MTB"
        threat_id = "2147913639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NDMzYTVjNTc2OTZlNjQ2Zjc3NzM1YzUzNzk3Mzc0NjU2ZDMzMzI1Yw==" ascii //weight: 1
        $x_1_2 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzJlNzc3Mzc2NjM1Yw==" ascii //weight: 1
        $x_1_3 = "NTM2ODY1NmM2YzVjNGY3MDY1NmU1YzYzNmY2ZDZkNjE2ZTY0" ascii //weight: 1
        $x_1_4 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1YzQzNzU3MjU2NjU3Mg==" ascii //weight: 1
        $x_1_5 = "NjY2ZjY0Njg2NTZjNzA2NTcy" ascii //weight: 1
        $x_1_6 = "NDg0YjQzNTUzYTVjNTM2ZjY2NzQ3NzYxNzI2NTVjNDM2YzYxNzM3MzY1NzM1YzZkNzMyZDczNjU3NDc0Njk2ZTY3NzM1Yw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_RE_2147914636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.RE!MTB"
        threat_id = "2147914636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 b0 02 00 00 33 c9 ff 15 dd 14 00 00 48 8b c8 ff 15 e4 14 00 00 48 8d 05 f5 15 00 00 48 89 44 24 48 48 c7 44 24 60 ?? ?? 00 00 c6 44 24 40 00 48 c7 44 24 58 00 04 00 00 b9 02 02 00 00 48 8d 94 24 10 01 00 00 ff 15 6e 13 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_ASG_2147914787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ASG!MTB"
        threat_id = "2147914787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 da 1b d2 83 c2 02 ff 15 ?? ?? 00 00 49 8b 4e 18 4c 8b e0 66 89 7c 24 30 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 44 8d 43 10 49 8b cc 48 8d 54 24 30 89 44 24 34 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 48 48 c7 44 24 58 87 69 00 00 c6 44 24 40 00 48 c7 44 24 50 00 04 00 00 b9 02 01 00 00 48 8d 94 24 30 01 00 00 ff 15 ?? ?? 00 00 48 8b 4c 24 48 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_3 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 54 24 50 48 c7 44 24 ?? 87 69 00 00 c6 44 24 40 00 48 c7 44 24 68 00 04 00 00 48 8b ?? ?? 20 00 00 e8 ?? ?? ff ff 48 8d 15 ?? ?? ff ff 48 8b c8 ff 15 ?? ?? 00 00 b9 02 01 00 00 48 8d 55 30 ff 15 ?? ?? 00 00 48 8b 4c 24 50 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_4 = {48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 58 48 c7 44 24 70 87 69 00 00 c6 44 24 50 00 48 c7 44 24 68 00 04 00 00 b9 02 02 00 00 48 8d 55 40 ff 15 ?? ?? 00 00 48 8b 4c 24 58 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0}  //weight: 2, accuracy: Low
        $x_2_5 = {48 2b e0 48 8b 05 ?? ?? 00 00 48 33 c4 48 89 84 24 70 15 00 00 48 8b f1 48 8d 54 24 40 b9 01 01 00 00 ff 15 ?? ?? 00 00 bb 02 00 00 00 8b d3 8b cb 44 8d 43 0f ff 15 ?? ?? 00 00 48 8b 4e 18 4c 8b e0 66 89 5c 24 30 0f b7 09 ff 15 ?? ?? 00 00 48 8b 0e 66 89 44 24 32 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 34 44 8d 43 0e 48 8d 54 24 30 49 8b cc 33 c0 48 89 44 24 38 ff 15 ?? ?? 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_6 = "Send failure" ascii //weight: 1
        $x_1_7 = "Can't connect!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zusy_ASH_2147914994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.ASH!MTB"
        threat_id = "2147914994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 ff 15 ?? ?? 00 00 48 8b c8 ff 15 ?? ?? 00 00 48 8d 05 ?? ?? 00 00 48 89 44 24 48 48 c7 44 24 60 87 69 00 00 c6 44 24 40 00 48 c7 44 24 58 00 04 00 00 b9 02 02 00 00 48 8d 94 24 10 01 00 00 ff 15 ?? ?? 00 00 48 8b 4c 24 48 ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_2 = {44 8d 47 0f ff 15 ?? ?? 00 00 49 8b 4e 08 48 8b d8 66 89 7c 24 40 48 89 44 24 38 0f b7 09 ff 15 ?? ?? 00 00 49 8b 0e 66 89 44 24 42 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 44 44 8d 47 0e 48 8d 54 24 40 48 8b cb 33 c0 48 89 44 24 48 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zusy_AQ_2147916603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zusy.AQ!MTB"
        threat_id = "2147916603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 ce ff 15 ?? ?? 00 00 66 89 44 24 2a 48 8d 46 01 0f b7 f0 41 b8 10 00 00 00 48 8d 54 24 28 48 8b cd ff 15 ?? ?? 00 00 48 8b 47 10 33 db 48 8b 08 48 85 c9 74}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b7 09 ff 15 ?? ?? 00 00 48 8b 0f 66 89 44 24 ?? 48 8b 09 ff 15 ?? ?? 00 00 89 44 24 ?? 44 8d 43 0f 33 c0 8b d3 8b cb 48 89 44 24 ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

