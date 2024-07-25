rule HackTool_Linux_SuspiciousKerberosCredentialAccess_A_2147889543_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspiciousKerberosCredentialAccess.A"
        threat_id = "2147889543"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspiciousKerberosCredentialAccess"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cat /tmp/krb5.keytab" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

