/*
   K7 TITAN YARA ruleset
   Credential-theft and offensive tooling.
*/
rule HackTool_Mimikatz {
    meta:
        description = "Detects Mimikatz credential dumping strings"
        author = "K7 TITAN"
        severity = "high"
    strings:
        $a = "sekurlsa::logonpasswords"
        $b = "kerberos::golden"
        $c = "lsadump::sam"
    condition:
        any of them
}

rule Tool_Credential_Dump {
    meta:
        description = "Detects credential dumping command combinations"
        author = "K7 TITAN"
        severity = "high"
    strings:
        $a = "procdump" nocase
        $b = "lsass" nocase
    condition:
        $a and $b
}

rule Tool_Remote_Access {
    meta:
        description = "Detects common remote-access tooling markers"
        author = "K7 TITAN"
        severity = "medium"
    strings:
        $a = "ngrok" nocase
        $b = "reverse_tcp" nocase
        $c = "meterpreter" nocase
    condition:
        any of them
}
