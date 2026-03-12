from .models import EventRecord, UserConfig


def build_mitre_url(mitre_tech_ids: str) -> str:
    if "." in mitre_tech_ids:
        return f"https://attack.mitre.org/techniques/{mitre_tech_ids.replace('.', '/')}"
    return f"https://attack.mitre.org/techniques/{mitre_tech_ids}"


def sanitize_event_name(event_name: str) -> str:
    return event_name.replace(" ", "-")


def build_query(config: UserConfig, record: EventRecord) -> str:
    date_added_informational = record.date_added_informational or record.date_added_as_notable
    event = sanitize_event_name(record.event_name)
    use_case_name = f"{record.use_case_id}_{event}"
    mitre_url = build_mitre_url(record.mitre_tech_ids)

    return f"""
| makeresults
| eval cim_compliance="{config.cim_compliance}",
OS="{record.os_name}",
Developer="{config.dev}",
correlation_search="{config.correlation_search}",
correlation_search_link="{config.correlation_search_link}",
date_added_as_notable="{record.date_added_as_notable}",
date_added_informational="{date_added_informational}",
event="{event}",
event_added_to_use_case_notable_date="{record.event_added_to_use_case_notable_date}",
event_definition="{record.event_definition}",
event_id="{record.event_id}",
event_name="{record.event_name}",
event_sub="{record.event_sub}",
fs_module="{record.fs_module}",
mitre_tech="{record.mitre_tech}",
mitre_tactic="{record.mitre_tactic}",
mitre_tactic_id="{record.mitre_tactic_id}",
mitre_tech_ids="{record.mitre_tech_ids}",
mitre_url="{mitre_url}",
notable_created_as_informational="{record.notable_created_as_informational}",
occurence="{record.occurence}",
operational_reviews_every_6_months="{record.operational_reviews_every_6_months}",
playbook="{config.playbook}",
risk_score="{record.risk_score}",
runbook="{record.runbook}",
search_name="{record.search_name}",
severity="{record.severity}",
signal_tech="{config.signal_tech}",
status="{record.status}",
type="{record.type}",
use_case_id="{record.use_case_id}",
use_case_id_orig="{record.use_case_id_orig}",
action_id="{record.action_id}",
use_case_name="{use_case_name}"
| outputlookup append=true event_management.csv
""".strip()
