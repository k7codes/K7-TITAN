/*
   K7 TITAN YARA ruleset
   Ransomware behaviour indicators.
*/
rule Ransom_Note_Encrypted {
    meta:
        description = "Detects a common ransomware extortion phrase"
        author = "K7 TITAN"
        severity = "high"
    strings:
        $a = "your files have been encrypted"
    condition:
        $a
}

rule Ransom_ShadowCopy_Deletion {
    meta:
        description = "Detects shadow copy or backup catalogue deletion"
        author = "K7 TITAN"
        severity = "high"
    strings:
        $vss = "vssadmin delete shadows"
        $wb = "wbadmin delete catalog"
        $bcd = "bcdedit /set"
    condition:
        any of them
}

rule Ransom_Extension_Stub {
    meta:
        description = "Detects typical locked-file extension markers"
        author = "K7 TITAN"
        severity = "medium"
    strings:
        $a = ".locked"
        $b = ".encrypted"
        $c = "readme_for_decrypt"
    condition:
        any of them
}
