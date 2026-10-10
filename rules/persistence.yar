/*
   K7 TITAN YARA ruleset
   Persistence and autostart indicators.
*/
rule Persistence_RunKey {
    meta:
        description = "Detects Run key autostart persistence"
        author = "K7 TITAN"
        severity = "medium"
    strings:
        $a = "currentversion\\run" nocase
        $b = "reg add" nocase
    condition:
        $a and $b
}

rule Persistence_ScheduledTask {
    meta:
        description = "Detects scheduled task creation used for persistence"
        author = "K7 TITAN"
        severity = "medium"
    strings:
        $a = "schtasks /create" nocase
        $b = "schtasks.exe" nocase
    condition:
        any of them
}

rule Persistence_Service_Install {
    meta:
        description = "Detects service installation for persistence"
        author = "K7 TITAN"
        severity = "high"
    strings:
        $a = "sc create"
        $b = "binpath="
    condition:
        $a and $b
}
