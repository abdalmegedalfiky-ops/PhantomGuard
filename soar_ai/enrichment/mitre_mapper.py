"""
Enrichment: mapping سريع من keywords في اسم/وصف الـ rule لتقنيات MITRE ATT&CK.
ده lookup table بسيط (heuristic) — مش بديل عن detection logic حقيقي، بس بيساعد
الـ AI triage engine يبني سياق أدق وأسرع.
"""
from __future__ import annotations

# keyword -> (technique_id, technique_name)
_KEYWORD_MAP: dict[str, tuple[str, str]] = {
    "brute force": ("T1110", "Brute Force"),
    "password spray": ("T1110.003", "Password Spraying"),
    "valid account": ("T1078", "Valid Accounts"),
    "privilege escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "create account": ("T1136", "Create Account"),
    "account removal": ("T1531", "Account Access Removal"),
    "phishing attachment": ("T1566.001", "Phishing: Spearphishing Attachment"),
    "phishing link": ("T1598.003", "Phishing for Information: Spearphishing Link"),
    "user execution": ("T1204.001", "User Execution: Malicious Link"),
    "command and control": ("T1071.003", "Application Layer Protocol: Mail Protocols"),
    "masquerading": ("T1036.005", "Masquerading: Match Legitimate Name"),
    "lateral movement": ("T1021", "Remote Services"),
    "data exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "credential dumping": ("T1003", "OS Credential Dumping"),
    "scheduled task": ("T1053", "Scheduled Task/Job"),
    "powershell": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
}


def map_alert_to_mitre(rule_name: str, description: str = "") -> list[dict[str, str]]:
    """يرجّع list من dicts {technique_id, technique_name} لكل تطابق."""
    text = f"{rule_name} {description}".lower()
    matches = []
    for keyword, (tid, tname) in _KEYWORD_MAP.items():
        if keyword in text:
            matches.append({"technique_id": tid, "technique_name": tname})
    return matches
