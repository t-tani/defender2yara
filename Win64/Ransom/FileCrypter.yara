rule Ransom_Win64_FileCrypter_MA_2147764529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FileCrypter.MA!MTB"
        threat_id = "2147764529"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "as  at  fp= is  lr: of  on  pc= sp: sp=%x" ascii //weight: 1
        $x_1_3 = "Inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml" ascii //weight: 1
        $x_1_4 = "main.ransomNote" ascii //weight: 1
        $x_1_5 = ".encrypted" ascii //weight: 1
        $x_1_6 = "unreachableuserenv.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

