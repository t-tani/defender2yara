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

