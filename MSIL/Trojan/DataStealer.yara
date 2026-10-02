rule Trojan_MSIL_DataStealer_MK_2147758522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DataStealer.MK!MSR"
        threat_id = "2147758522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DataStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://u2729.mh0.ru/" ascii //weight: 5
        $x_1_2 = "browserPasswords" ascii //weight: 1
        $x_1_3 = "Passwords.txt" ascii //weight: 1
        $x_1_4 = "FireFox\\logins.json" ascii //weight: 1
        $x_1_5 = "CreditCards.txt" ascii //weight: 1
        $x_1_6 = "Filezilla\\Passwords.txt" ascii //weight: 1
        $x_1_7 = "VPN\\ProtonVPN\\Passwords.txt" ascii //weight: 1
        $x_1_8 = "Psi\\Passwords.txt" ascii //weight: 1
        $x_1_9 = "Pidgin\\Passwords.txt" ascii //weight: 1
        $x_1_10 = "BitcoinCore\\wallet.dat" ascii //weight: 1
        $x_1_11 = "DashCore\\wallet.dat" ascii //weight: 1
        $x_1_12 = "LitecoinCore\\wallet.dat" ascii //weight: 1
        $x_1_13 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
        $x_1_14 = "SELECT * FROM Win32_BIOS" ascii //weight: 1
        $x_1_15 = "Select * from Win32_ComputerSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DataStealer_CJ_2147979667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DataStealer.CJ!MTB"
        threat_id = "2147979667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DataStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LOCKEMAIL" ascii //weight: 1
        $x_3_2 = "ATTACKER_WALLET" ascii //weight: 3
        $x_3_3 = "ATTACKER_ACCT_NUM" ascii //weight: 3
        $x_3_4 = "ATTACKER_BANK_NAME" ascii //weight: 3
        $x_1_5 = "CryptoScan" ascii //weight: 1
        $x_1_6 = "DisableAv" ascii //weight: 1
        $x_2_7 = "<HarvestCookies>" ascii //weight: 2
        $x_1_8 = "cryptoLogins" ascii //weight: 1
        $x_1_9 = "chrome" ascii //weight: 1
        $x_1_10 = "coccoc" ascii //weight: 1
        $x_2_11 = "\\SnakeBite_" ascii //weight: 2
        $x_1_12 = "LockActive" ascii //weight: 1
        $x_1_13 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_14 = "Telegram Desktop" ascii //weight: 1
        $x_2_15 = "*.lock" ascii //weight: 2
        $x_1_16 = "DisableLockWorkstation" ascii //weight: 1
        $x_1_17 = "HARVEST_LIVE" ascii //weight: 1
        $x_2_18 = "RUN_STEALER" ascii //weight: 2
        $x_1_19 = "Iridium" ascii //weight: 1
        $x_1_20 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii //weight: 1
        $x_1_21 = "odbfpeeihdkbihmopkbjmoonfanlbfcl" ascii //weight: 1
        $x_1_22 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 1
        $x_1_23 = "egjidjbpglichdcondbcbdwfbepigadp" ascii //weight: 1
        $x_3_24 = "wallet.dat" ascii //weight: 3
        $x_1_25 = "keystore" ascii //weight: 1
        $x_1_26 = ".key" ascii //weight: 1
        $x_1_27 = "mouseMoved" ascii //weight: 1
        $x_2_28 = "YOUR COMPUTER HAS BEEN LOCKED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

