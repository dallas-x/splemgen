from dataclasses import dataclass

MITRE_TACTICS = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

OS_OPTIONS = ["Windows", "Linux", "Mac"]
RISK_SCORE_OPTIONS = ["1", "6", "12", "25", "100"]
SEVERITY_OPTIONS = [
    "indev",
    "pilot",
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]
FS_MODULE_OPTIONS = ["alert", "rba"]


@dataclass
class UserConfig:
    dev: str
    playbook: str = "Suspicious User Behavior"
    signal_tech: str = "microsoft_defender"
    correlation_search: str = "SH0_Microsoft Defender Custom Detection Notable"
    correlation_search_link: str = ""
    cim_compliance: str = "no"


@dataclass
class EventRecord:
    event_name: str
    event_definition: str
    event_id: str
    use_case_id: str
    mitre_tactic: str
    mitre_tech: str
    mitre_tactic_id: str
    mitre_tech_ids: str
    date_added_as_notable: str
    risk_score: str = "12"
    os_name: str = "Windows"
    severity: str = "medium"
    fs_module: str = "alert"
    search_name: str = ""
    runbook: str = ""
    action_id: str = "-"
    event_sub: str = ""
    notable_created_as_informational: str = "no"
    occurence: str = "0"
    operational_reviews_every_6_months: str = "no"
    status: str = "active"
    type: str = "event"
    use_case_id_orig: str = ""
    event_added_to_use_case_notable_date: str = ""
    date_added_informational: str | None = None
