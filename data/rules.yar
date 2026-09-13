rule WebShell_PHP_Generic {
    meta:
        description = "Detecta construcciones típicas de webshells en scripts"
        author = "Antivirus Local"
        severity = "High"
    strings:
        $p1 = "eval(base64_decode(" nocase
        $p2 = "assert(base64_decode(" nocase
        $p3 = "passthru($_POST[" nocase
        $p4 = "shell_exec($_GET[" nocase
    condition:
        any of them
}

rule Suspicious_Memory_Allocation {
    meta:
        description = "Detecta APIs de inyección de código combinadas"
        author = "Antivirus Local"
        severity = "Critical"
    strings:
        $s1 = "VirtualAllocEx" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
    condition:
        all of them
}