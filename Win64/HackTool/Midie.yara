rule HackTool_Win64_Midie_A_2147977879_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Midie.A!MTB"
        threat_id = "2147977879"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] SeDebugPrivilege ativado com sucesso" ascii //weight: 1
        $x_1_2 = "[-] Nao foi possivel abrir o processo. Execute como Admin." ascii //weight: 1
        $x_1_3 = "[*] Modulo encontrado em: %ls" ascii //weight: 1
        $x_1_4 = "[*] Suspending threads..." ascii //weight: 1
        $x_1_5 = "[*] Unmap realizado com sucesso." ascii //weight: 1
        $x_1_6 = "[*] Remapeamento realizado em: %p" ascii //weight: 1
        $x_1_7 = "[*] Threads resumidas." ascii //weight: 1
        $x_1_8 = "[+] Modulo %ls restaurado com sucesso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

