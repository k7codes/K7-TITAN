/*
   K7 TITAN heuristic YARA ruleset
   Low-confidence rules used for scoring, not auto-quarantine.
*/
rule Suspicious_PowerShell_DownloadExec {
    meta:
        description = "PowerShell download-and-execute pattern (heuristic)"
        author = "K7 TITAN"
        severity = "medium"
        confidence = "low"
    strings:
        $ps1 = "powershell" nocase
        $iex = "IEX" nocase
        $dl = "DownloadString" nocase
        $web = "Net.WebClient" nocase
    condition:
        $ps1 and (($iex and $dl) or $web)
}

rule Suspicious_Base64_LongBlob {
    meta:
        description = "Very long base64-like blob (possible encoded payload)"
        author = "K7 TITAN"
        severity = "low"
        confidence = "low"
    strings:
        $b64 = /[A-Za-z0-9+\/]{800,}={0,2}/
    condition:
        $b64
}
