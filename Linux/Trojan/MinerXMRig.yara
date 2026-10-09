rule Trojan_Linux_MinerXMRig_DA_2147980040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MinerXMRig.DA!MTB"
        threat_id = "2147980040"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MinerXMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ")):\\n urllib.request.urlretrieve(url,dst)\\nos.chmod(dst,0o777)\\nimport subprocess as _s\\n_s.Popen([dst,'%s'],env=os.envir" ascii //weight: 10
        $x_10_2 = "138ebbf479e22de2b7813334bafb98d008af2hufgegiufegiufibraw.gi" ascii //weight: 10
        $x_10_3 = "0032d76926b6c40658029bd9138ebbf479e22de2b7813334bafb98d008af2" ascii //weight: 10
        $x_10_4 = "://raw.githubusercontent.com/ejejejdfbbebe/nodejs.org/refs/heads/main/packages/rehype-shiki/src/tra" ascii //weight: 10
        $x_10_5 = "pkill -x python3.1 2>/dev/null; pkill -f /tmp/xmrig 2>/dev/null" ascii //weight: 10
        $x_10_6 = "sed -i 's/xmr-ru.kryptex.network/%s/g' /tmp/.xmrig_rt.json" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

