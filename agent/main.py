from agent.collectors.process_monitor import monitor_processes
from agent.pipeline.normalizer import normalize_process
from database.event_store import initialize_database, save_alert, save_event
from detection.engine import analyze_event
from detection.correlator import correlate_alerts
from detection.risk import calculate_risk_score


def main():
    initialize_database()

    print("========================================")
    print("        trustIssues Endpoint Agent")
    print("========================================")
    print()
    print("Monitoring process activity...")
    print()

    for process in monitor_processes(interval=2):
        event = normalize_process(process)

        save_event(event)

        print(
            f"[PROCESS CREATED] "
            f"{event.process_name} "
            f"(PID={event.process_id}, "
            f"PPID={event.parent_process_id})"
        )

        alerts = analyze_event(event)

        for alert in alerts:
            save_alert(alert)

            print()
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("[SECURITY ALERT]")
            print(f"Rule: {alert.rule_id}")
            print(f"Title: {alert.title}")
            print(f"Severity: {alert.severity}")
            print(f"Risk Score: {alert.risk_score}")
            print(f"Process: {alert.process_name}")
            print(f"PID: {alert.process_id}")
            print(f"Evidence: {alert.evidence}")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print()

        correlated_alerts = correlate_alerts(alerts)

        for alert in correlated_alerts:
            save_alert(alert)

            print()
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("[CORRELATED SECURITY ALERT]")
            print(f"Rule: {alert.rule_id}")
            print(f"Title: {alert.title}")
            print(f"Severity: {alert.severity}")
            print(f"Risk Score: {alert.risk_score}")
            print(f"Process: {alert.process_name}")
            print(f"PID: {alert.process_id}")
            print(f"Evidence: {alert.evidence}")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print()

        risk_score = calculate_risk_score(
            alerts + correlated_alerts
        )

        if risk_score > 0:
            print(f"[RISK SCORE] {risk_score}/100")


if __name__ == "__main__":
    main()