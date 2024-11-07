rule Trojan_Win64_ZLoader_BA_2147766897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.BA!MTB"
        threat_id = "2147766897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\Voices" wide //weight: 1
        $x_1_2 = "SRGRAMMAR" wide //weight: 1
        $x_1_3 = "WindowsSDK7-Samples-master\\winui\\speech\\tutorial\\x64\\Release\\CoffeeShop6.pdb" ascii //weight: 1
        $x_1_4 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_F_2147912096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.F"
        threat_id = "2147912096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 61 64 65 72 44 6c 6c 2e 64 6c 6c 00 (41|2d|5a) [0-36] 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DA_2147924369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DA!MTB"
        threat_id = "2147924369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXCEPTION: Code=0x%08X" ascii //weight: 1
        $x_1_2 = "rax=0x%p, rbx=0x%p, rdx=0x%p, rcx=0x%p, rsi=0x%p, rdi=0x%p, rbp=0x%p, rsp=0x%p, rip=0x%p" ascii //weight: 1
        $x_1_3 = "[-] Request limit reached." ascii //weight: 1
        $x_1_4 = "{INJECTDATA}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DAA_2147925487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DAA!MTB"
        threat_id = "2147925487"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "EXCEPTION: Code=0x%" ascii //weight: 10
        $x_10_2 = "Flags=0x%" ascii //weight: 10
        $x_10_3 = "Address=0x%" ascii //weight: 10
        $x_10_4 = "expInfo=%" ascii //weight: 10
        $x_1_5 = "rip=0x%" ascii //weight: 1
        $x_1_6 = "rsp=0x%" ascii //weight: 1
        $x_1_7 = "rbp=0x%" ascii //weight: 1
        $x_1_8 = "rdi=0x%" ascii //weight: 1
        $x_1_9 = "rsi=0x%" ascii //weight: 1
        $x_1_10 = "rcx=0x%" ascii //weight: 1
        $x_1_11 = "rdx=0x%" ascii //weight: 1
        $x_1_12 = "rbx=0x%" ascii //weight: 1
        $x_1_13 = "rax=0x%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ZLoader_DB_2147925509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DB!MTB"
        threat_id = "2147925509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e6 04 01 ce 89 f9 29 f1 48 63 c9 46 0f b6 1c 01 44 32 1c 38 44 88 1c 3a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_YAB_2147925527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.YAB!MTB"
        threat_id = "2147925527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 15 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZLoader_DC_2147925602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DC!MTB"
        threat_id = "2147925602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 0f b6 44 0d ?? 43 32 04 22 49 83 c2 06 43 88 44 0a}  //weight: 10, accuracy: Low
        $x_10_2 = {48 c1 ea 04 48 6b c2 11 48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0b ff 41 88 41 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ZLoader_DD_2147925614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZLoader.DD!MTB"
        threat_id = "2147925614"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 58 a6 41 2c bc 6d d7 0d 3e be 4b 43 25 db cc 79 23 4a a4 ff e2 b2 80 00 c1 6b 75 70 18 0b 5f be}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

