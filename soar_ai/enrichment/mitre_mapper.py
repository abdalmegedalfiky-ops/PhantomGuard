"""
Enrichment: mapping سريع من keywords في اسم/وصف الـ rule لتقنيات MITRE ATT&CK.
ده lookup table بسيط (heuristic) — مش بديل عن detection logic حقيقي، بس بيساعد
الـ AI triage engine يبني سياق أدق وأسرع.

ADDED: keywords ناقصة كانت مش موجودة:
  - c2 / beacon / cobalt strike / sliver → Command & Control
  - mimikatz / lsass / ntds → Credential Dumping
  - pass-the-hash / pass-the-ticket → Lateral Movement
  - dll injection / dll side-loading → Defense Evasion
  - process hollowing / process injection → Defense Evasion
  - reverse shell / webshell / web shell → Execution
  - data staging / archive collected → Collection
  - living off the land / lolbin / wmic → Defense Evasion
"""
from __future__ import annotations

# keyword (lowercase) -> (technique_id, technique_name)
_KEYWORD_MAP: dict[str, tuple[str, str]] = {
    # Credential Access
    "brute force":          ("T1110",       "Brute Force"),
    "password spray":       ("T1110.003",   "Password Spraying"),
    "credential dumping":   ("T1003",       "OS Credential Dumping"),
    "mimikatz":             ("T1003.001",   "LSASS Memory"),
    "lsass":                ("T1003.001",   "LSASS Memory"),
    "ntds":                 ("T1003.003",   "NTDS"),
    "kerberoast":           ("T1558.003",   "Kerberoasting"),
    "dcsync":               ("T1003.006",   "DCSync"),
    # Persistence
    "valid account":        ("T1078",       "Valid Accounts"),
    "create account":       ("T1136",       "Create Account"),
    "account removal":      ("T1531",       "Account Access Removal"),
    "scheduled task":       ("T1053",       "Scheduled Task/Job"),
    "registry run":         ("T1547.001",   "Registry Run Keys / Startup Folder"),
    "startup folder":       ("T1547.001",   "Registry Run Keys / Startup Folder"),
    # Privilege Escalation
    "privilege escalation": ("T1068",       "Exploitation for Privilege Escalation"),
    "token impersonation":  ("T1134.001",   "Token Impersonation/Theft"),
    # Defense Evasion
    "masquerading":         ("T1036.005",   "Masquerading: Match Legitimate Name"),
    "dll injection":        ("T1055.001",   "DLL Injection"),
    "dll side-load":        ("T1574.002",   "DLL Side-Loading"),
    "process hollowing":    ("T1055.012",   "Process Hollowing"),
    "process injection":    ("T1055",       "Process Injection"),
    "living off the land":  ("T1218",       "System Binary Proxy Execution"),
    "lolbin":               ("T1218",       "System Binary Proxy Execution"),
    "wmic":                 ("T1047",       "Windows Management Instrumentation"),
    "certutil":             ("T1140",       "Deobfuscate/Decode Files or Information"),
    # Execution
    "powershell":           ("T1059.001",   "Command and Scripting Interpreter: PowerShell"),
    "reverse shell":        ("T1059",       "Command and Scripting Interpreter"),
    "webshell":             ("T1505.003",   "Web Shell"),
    "web shell":            ("T1505.003",   "Web Shell"),
    "user execution":       ("T1204.001",   "User Execution: Malicious Link"),
    # Initial Access
    "phishing attachment":  ("T1566.001",   "Phishing: Spearphishing Attachment"),
    "phishing link":        ("T1598.003",   "Phishing for Information: Spearphishing Link"),
    # Lateral Movement
    "lateral movement":     ("T1021",       "Remote Services"),
    "pass-the-hash":        ("T1550.002",   "Pass the Hash"),
    "pass-the-ticket":      ("T1550.003",   "Pass the Ticket"),
    "remote desktop":       ("T1021.001",   "Remote Desktop Protocol"),
    "smb":                  ("T1021.002",   "SMB/Windows Admin Shares"),
    # Command & Control
    "command and control":  ("T1071.003",   "Application Layer Protocol: Mail Protocols"),
    "c2":                   ("T1071",       "Application Layer Protocol"),
    "beacon":               ("T1071",       "Application Layer Protocol"),
    "cobalt strike":        ("T1071",       "Application Layer Protocol"),
    "sliver":               ("T1071",       "Application Layer Protocol"),
    # Collection
    "data exfiltration":    ("T1041",       "Exfiltration Over C2 Channel"),
    "data staging":         ("T1074",       "Data Staged"),
    "archive collected":    ("T1560",       "Archive Collected Data"),
    # Impact
    "ransomware":           ("T1486",       "Data Encrypted for Impact"),
    "wiper":                ("T1485",       "Data Destruction"),
}


def map_alert_to_mitre(rule_name: str, description: str = "") -> list[dict[str, str]]:
    """يرجّع list من dicts {technique_id, technique_name} لكل تطابق — بدون تكرار."""
    text = f"{rule_name} {description}".lower()
    seen: set[str] = set()
    matches: list[dict[str, str]] = []
    for keyword, (tid, tname) in _KEYWORD_MAP.items():
        if keyword in text and tid not in seen:
            seen.add(tid)
            matches.append({"technique_id": tid, "technique_name": tname})
    return matches
