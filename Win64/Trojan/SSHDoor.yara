rule Trojan_Win64_SSHDoor_P_2147978971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SSHDoor.P!MTB"
        threat_id = "2147978971"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SSHDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "# random login/password for remote access. Embedded inside ssh_setup.exe." ascii //weight: 1
        $x_1_2 = "# Sends the result to Telegram; if that's not possible, saves it to a text" ascii //weight: 1
        $x_1_3 = "# file on the Desktop instead. Non-critical steps (firewall rule, group" ascii //weight: 1
        $x_1_4 = "# membership) log a warning but don't stop the rest of the setup." ascii //weight: 1
        $x_1_5 = {49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64 20 2d 55 72 69 20 22 68 74 74 70 73 3a 2f 2f [0-25] 2f 62 6f 74 24 62 6f 74 54 6f 6b 65 6e 2f 73 65 6e 64 4d 65 73 73 61 67 65 22 20 2d 4d 65 74 68 6f 64 20 50 6f 73 74}  //weight: 1, accuracy: Low
        $x_1_6 = "$resultText = \"SSH is ready.`nUsername: $username`nPassword: $plainPassword`nIP: $ip`nConnect: ssh $username@$ip" ascii //weight: 1
        $x_1_7 = "-Body @{ chat_id = $chatId; text = $resultText } -TimeoutSec 10 | Out-Null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

