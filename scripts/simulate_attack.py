from datetime import datetime, timezone
import uuid

from agent.models.security_event import SecurityEvent
from database.event_store import initialize_database, save_alert, save_event
from detection.correlator import correlate_alerts
from detection.engine import analyze_event
from detection.mitre import get_mitre_mapping
from detection.risk import calculate_risk_score


def main():
    initialize_database()

    event = SecurityEvent(
        event_id=f"SIMULATED-ATTACK-{uuid.uuid4()}",
        timestamp=datetime.now(timezone.utc),
        event_type="process",
        hostname="TEST-PC",
        process_id=4242,
        parent_process_id=3131,
        process_name="powershell.exe",
        executable_path=(
            r"C:\Users\Test\AppData\Local\Temp\payload.exe"
        ),
        username="testuser",
        metadata={
            "command_line": (
                "powershell.exe -EncodedCommand "
                "SIMULATED_PAYLOAD"
            ),
            "parent_process_name": "winword.exe",
        },
    )

    print("=" * 60)
    print("       trustIssues Detection Simulation")
    print("=" * 60)
    print()

    print("[1] Simulated Security Event")
    print(f"    Process: {event.process_name}")
    print(f"    PID: {event.process_id}")
    print(f"    Parent: {event.metadata['parent_process_name']}")
    print(f"    Path: {event.executable_path}")
    print()

    alerts = analyze_event(event)

    save_event(event)

    print("[2] Detection Alerts")
    print(f"    Alerts generated: {len(alerts)}")
    print()

    for alert in alerts:
        print(
            f"    {alert.rule_id} | "
            f"{alert.severity} | "
            f"Risk {alert.risk_score}"
        )
        print(f"    {alert.title}")
        print()

    correlated_alerts = correlate_alerts(alerts)

    # Save each base and correlated alert exactly once.
    for alert in alerts + correlated_alerts:
        save_alert(alert)

    print("[3] Correlation")
    print(
        f"    Correlated alerts: "
        f"{len(correlated_alerts)}"
    )
    print()

    for alert in correlated_alerts:
        print(
            f"    {alert.rule_id} | "
            f"{alert.severity} | "
            f"Risk {alert.risk_score}"
        )
        print(f"    {alert.title}")
        print()

    all_alerts = alerts + correlated_alerts

    risk_score = calculate_risk_score(all_alerts)

    print("[4] Final Risk Score")
    print(f"    {risk_score}/100")
    print()

    print("[5] MITRE ATT&CK Mapping")

    seen = set()

    for alert in all_alerts:
        mapping = get_mitre_mapping(alert.rule_id)

        if mapping is None:
            continue

        technique = mapping["technique"]

        if technique in seen:
            continue

        seen.add(technique)

        print(
            f"    {technique} - "
            f"{mapping['name']}"
        )

    print()

    print("=" * 60)
    print("              Simulation Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()

