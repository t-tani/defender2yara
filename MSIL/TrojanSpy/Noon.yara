rule TrojanSpy_MSIL_Noon_MA_2147782764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.MA!MTB"
        threat_id = "2147782764"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JU09tVPGc32NW7" ascii //weight: 3
        $x_3_2 = "U4FWLAtMCj" ascii //weight: 3
        $x_3_3 = "YoMQ2ONUqh5PQV" ascii //weight: 3
        $x_3_4 = "Xenelk.Properties" ascii //weight: 3
        $x_3_5 = "Random" ascii //weight: 3
        $x_3_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SK_2147837075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SK!MTB"
        threat_id = "2147837075"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 e5 00 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SL_2147837077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SL!MTB"
        threat_id = "2147837077"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 75 00 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SM_2147837778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SM!MTB"
        threat_id = "2147837778"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 06 11 06 9a 1f 10 28 18 01 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SP_2147849588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SP!MTB"
        threat_id = "2147849588"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 cd 09 00 70 28 ?? ?? ?? 06 1a 2d 03 26 de 06 0a 2b fb}  //weight: 4, accuracy: Low
        $x_1_2 = "fvua8tb4f77gdmfwqxgryjjw7e58638u" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SR_2147851335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SR!MTB"
        threat_id = "2147851335"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SR_2147851335_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SR!MTB"
        threat_id = "2147851335"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d ac}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SU_2147893560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SU!MTB"
        threat_id = "2147893560"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SV_2147897289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SV!MTB"
        threat_id = "2147897289"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 14 11 04 5d 13 15 11 14 17 58 13 16 07 11 15 91 13 17 07 11 15 11 17 08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 14 17 58 13 14 11 14 11 04 09 17 58 5a fe 04 13 18 11 18 2d b2}  //weight: 2, accuracy: High
        $x_2_2 = "ProQuota.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SW_2147897486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SW!MTB"
        threat_id = "2147897486"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 09 5d 13 04 06 1f 16 5d 13 0a 06 17 58 09 5d 13 0b 07 11 04 91 11 06 11 0a 91 61 13 0c 20 00 01 00 00 13 05 11 0c 07 11 0b 91 59 11 05 58 11 05 5d 13 0d 07 11 04 11 0d d2 9c 06 17 58 0a 06 09 11 07 17 58 5a fe 04 13 0e 11 0e 2d b2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SX_2147898758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SX!MTB"
        threat_id = "2147898758"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 6f 0d 00 00 0a 03 58 20 00 01 00 00 5d 0c 08 16 2f 08 08 20 00 01 00 00 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 0c 00 00 0a 32 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_ST_2147901750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.ST!MTB"
        threat_id = "2147901750"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 06 08 91 20 a7 20 3a 3a 28 27 00 00 06 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SY_2147902569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SY!MTB"
        threat_id = "2147902569"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 07 20 00 dc 00 00 5d 13 08 08 11 08 91 13 09 11 07 1f 16 5d 13 0a 08 11 08 11 09 1f 16 8d c5 00 00 01 25 d0 5d 00 00 04 28 e1 00 00 0a 11 0a 91 61 08 11 07 17 58 20 00 dc 00 00 5d 91 09 58 09 5d 59 d2 9c 00 11 07 17 58 13 07 11 07 20 00 dc 00 00 fe 04 13 0b 11 0b 2d a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SZ_2147905069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SZ!MTB"
        threat_id = "2147905069"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 06 09 6a 5d d4 07 11 06 09 6a 5d d4 91 08 11 06 08 8e 69 6a 5d d4 91 61 28 42 00 00 0a 07 11 06 17 6a 58 09 6a 5d d4 91 28 43 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 44 00 00 0a 9c 00 11 06 17 6a 58 13 06 11 06 09 17 59 6a fe 02 16 fe 01 13 07 11 07 2d a4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SA_2147906162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SA!MTB"
        threat_id = "2147906162"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 0c 17 58 11 07 5d 91 13 0d 07 11 0c 91 13 0e 08 11 0c 08 6f 44 00 00 0a 5d 6f 45 00 00 0a 13 0f 11 0e 11 0f 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07 11 0c 11 10 d2 9c 00 11 0c 17 58 13 0c 11 0c 11 07 fe 04 13 11 11 11 2d ad}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SB_2147906164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SB!MTB"
        threat_id = "2147906164"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 11 0c 91 07 11 07 17 58 11 06 5d 91 13 0d 08 11 07 08 6f 65 00 00 0a 5d 6f 66 00 00 0a 13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 11 07 11 0f d2 9c 11 07 17 58 13 07 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 b0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SC_2147906165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SC!MTB"
        threat_id = "2147906165"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 07 91 13 09 11 06 17 58 08 5d 13 0a 07 11 06 91 11 09 61 07 11 0a 91 59 20 00 01 00 00 58 13 0b 07 11 06 11 0b 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SC_2147906165_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SC!MTB"
        threat_id = "2147906165"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 07 91 07 11 04 17 58 09 5d 91 13 08 08 11 04 1f 16 5d 91 13 09 11 09 61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0a 07 11 04 11 0a d2 9c 11 04 17 58 13 04 11 07 17 58 13 07 11 07 11 06 8e 69 32 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_ARA_2147910756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.ARA!MTB"
        threat_id = "2147910756"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 11 10 07 11 10 91 17 8d ?? ?? ?? 01 25 16 20 c6 00 00 00 9c 11 10 17 5d 91 61 d2 9c 00 11 10 17 58 13 10 11 10 07 8e 69 fe 04 13 11 11 11 2d ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SH_2147917641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SH!MTB"
        threat_id = "2147917641"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 61 13 1a 07 09 17 58 08 5d 91 13 1b 11 1a 11 1b 59}  //weight: 2, accuracy: High
        $x_2_2 = "heidi_schwartz_C968.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Noon_SJ_2147917649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Noon.SJ!MTB"
        threat_id = "2147917649"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 09 11 07 09 8e 69 5d 91 13 08 07 11 07 91 11 08 61 13 09 11 07 17 58 08 5d 13 0a 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

