import argparse
import datetime

import pyperclip

from .config import load_config, save_config
from .models import (
    FS_MODULE_OPTIONS,
    MITRE_TACTICS,
    OS_OPTIONS,
    RISK_SCORE_OPTIONS,
    SEVERITY_OPTIONS,
    EventRecord,
    UserConfig,
)
from .query_builder import build_query


def prompt_text(label: str, default: str | None = None, required: bool = True) -> str:
    while True:
        prompt = f"{label}"
        if default:
            prompt += f" [{default}]"
        prompt += ": "

        value = input(prompt).strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return ""
        print("Value is required.")


def prompt_choice(label: str, options: list[str], default: str | None = None) -> str:
    options_display = ", ".join(options)

    while True:
        prompt = f"{label} ({options_display})"
        if default:
            prompt += f" [{default}]"
        prompt += ": "

        value = input(prompt).strip()
        if not value and default:
            return default

        for option in options:
            if value.lower() == option.lower():
                return option

        print("Invalid choice. Please select one of the listed options.")


def prompt_mitre_tactic() -> tuple[str, str]:
    tactics = list(MITRE_TACTICS.keys())

    print("\nMITRE Tactic Options:")
    for idx, tactic in enumerate(tactics, start=1):
        print(f"  {idx}. {tactic} ({MITRE_TACTICS[tactic]})")

    while True:
        value = input("Select MITRE tactic by number or name: ").strip()

        if value.isdigit():
            index = int(value) - 1
            if 0 <= index < len(tactics):
                tactic = tactics[index]
                return tactic, MITRE_TACTICS[tactic]

        for tactic in tactics:
            if value.lower() == tactic.lower():
                return tactic, MITRE_TACTICS[tactic]

        print("Invalid selection. Try again.")


def copy_to_clipboard(text: str) -> None:
    try:
        pyperclip.copy(text)
        print("Query copied to clipboard.")
    except Exception as exc:
        print(f"Could not copy to clipboard: {exc}")


def cmd_init() -> None:
    developer_name = prompt_text("Developer name")
    playbook = prompt_text("Default playbook", "Suspicious User Behavior")
    signal_tech = prompt_text("Default signal tech", "microsoft_defender")
    correlation_search = prompt_text(
        "Default correlation search",
        "SH0_Microsoft Defender Custom Detection Notable",
    )
    correlation_search_link = prompt_text("Default correlation search link", "", required=False)
    cim_compliance = prompt_text("Default CIM compliance", "no")

    config = UserConfig(
        dev=developer_name,
        playbook=playbook,
        signal_tech=signal_tech,
        correlation_search=correlation_search,
        correlation_search_link=correlation_search_link,
        cim_compliance=cim_compliance,
    )

    path = save_config(config)
    print(f"\nConfig saved to: {path}")


def cmd_generate() -> None:
    config = load_config()

    print("\nEnter event details:\n")

    event_name = prompt_text("Event name")
    event_definition = prompt_text("Event definition")
    event_id = prompt_text("Event ID")
    use_case_id = prompt_text("Use case ID")
    os_name = prompt_choice("Operating System", OS_OPTIONS, "Windows")
    mitre_tactic, mitre_tactic_id = prompt_mitre_tactic()
    mitre_tech = prompt_text("MITRE technique name")
    mitre_tech_ids = prompt_text("MITRE technique ID(s)")
    today = datetime.datetime.now().strftime("%m/%d/%Y")
    date_added_as_notable = prompt_text("Date added as notable (MM/DD/YYYY)", today)
    risk_score = prompt_choice("Risk score", RISK_SCORE_OPTIONS, "12")
    severity = prompt_choice("Severity", SEVERITY_OPTIONS, "pilot")
    fs_module = prompt_choice("FS module", FS_MODULE_OPTIONS, "alert")

    record = EventRecord(
        event_name=event_name,
        event_definition=event_definition,
        event_id=event_id,
        use_case_id=use_case_id,
        os_name=os_name,
        mitre_tactic=mitre_tactic,
        mitre_tech=mitre_tech,
        mitre_tactic_id=mitre_tactic_id,
        mitre_tech_ids=mitre_tech_ids,
        date_added_as_notable=date_added_as_notable,
        risk_score=risk_score,
        severity=severity,
        fs_module=fs_module,
    )

    query = build_query(config, record)
    print("\n************************************")
    print(query)
    print("************************************\n")
    copy_to_clipboard(query)


def main() -> None:
    parser = argparse.ArgumentParser(prog="event-mgmt")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize local user config")
    subparsers.add_parser("generate", help="Generate Splunk event management query")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "generate":
        cmd_generate()


if __name__ == "__main__":
    main()
