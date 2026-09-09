rule Trojan_MSIL_GodPotato_FF_2147848417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GodPotato.FF!MTB"
        threat_id = "2147848417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GodPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "18f70770-8e64-11cf-9af1-0020af6e72f4" wide //weight: 1
        $x_1_2 = "[\\pipe\\epmapper]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_GodPotato_AB_2147977787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GodPotato.AB!MTB"
        threat_id = "2147977787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GodPotato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "<Main>g__VirtualAllocExNuma|0_0" ascii //weight: 8
        $x_3_2 = "Reverse shell was unsuccessful" ascii //weight: 3
        $x_7_3 = "[+] New Command to Execute:" ascii //weight: 7
        $x_4_4 = "$RevShellClient = New-Object -TypeName System.Net.Sockets.TcpClient('{0}', {1})" ascii //weight: 4
        $x_2_5 = "$PromptString = $OutputBuffer.ToString() + 'PS ' + (PWD).Path + '>" ascii //weight: 2
        $x_6_6 = "$Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($DataBuffer,0,$i)" ascii //weight: 6
        $x_5_7 = "selbairav tnemnorivne lacol detirehni kcolb tnemnorivnE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

