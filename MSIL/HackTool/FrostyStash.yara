rule HackTool_MSIL_FrostyStash_A_2147932410_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FrostyStash.A!dha"
        threat_id = "2147932410"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrostyStash"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "U4OgFs2opxnHKUUwf280DvUGxewgqlBJKzHZpWhg8NPr2Af0D9" wide //weight: 10
        $x_1_2 = "system_data_size" wide //weight: 1
        $x_1_3 = "time_scale" wide //weight: 1
        $x_1_4 = "interval_engine" wide //weight: 1
        $x_1_5 = "internal_id" wide //weight: 1
        $x_1_6 = "internal_key" wide //weight: 1
        $x_1_7 = "rate_control" wide //weight: 1
        $x_1_8 = "span_min" wide //weight: 1
        $x_1_9 = "span_max" wide //weight: 1
        $x_1_10 = "days_not_work" wide //weight: 1
        $x_1_11 = "TMR_Engine" ascii //weight: 1
        $x_1_12 = "TMR_CheckEvent" ascii //weight: 1
        $x_1_13 = "TMR_KeepAlive" ascii //weight: 1
        $x_1_14 = "TMR_GenKeys" ascii //weight: 1
        $x_1_15 = "TMR_CheckDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

