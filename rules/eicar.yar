/*
   K7 TITAN YARA ruleset
   Rule: EICAR standard anti-malware test file
*/
rule EICAR_Test_File {
    meta:
        description = "Detects the EICAR anti-malware test file"
        author = "K7 TITAN"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
