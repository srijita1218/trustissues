from detection.alert import DetectionAlert


def correlate_alerts(alerts: list[DetectionAlert]) -> list[DetectionAlert]:
    if not alerts:
        return []

    correlated_alerts = []

    rule_ids = {alert.rule_id for alert in alerts}

    if {"TI-001", "TI-002"}.issubset(rule_ids):
        correlated_alerts.append(
            DetectionAlert(
                alert_id=f"CORR-{alerts[0].alert_id}",
                event_id=alerts[0].event_id,
                timestamp=alerts[0].timestamp,
                rule_id="CORR-001",
                title="Suspicious Process Execution Chain",
                description=(
                    "A process was executed from a suspicious location "
                    "and used a suspicious command-line pattern."
                ),
                severity="CRITICAL",
                risk_score=90,
                process_name=alerts[0].process_name,
                process_id=alerts[0].process_id,
                evidence={
                    "triggered_rules": sorted(rule_ids),
                    "source_alerts": [
                        alert.alert_id for alert in alerts
                    ],
                },
            )
        )

    if {"TI-002", "TI-003"}.issubset(rule_ids):
        correlated_alerts.append(
            DetectionAlert(
                alert_id=f"CORR-{alerts[0].alert_id}-PARENT",
                event_id=alerts[0].event_id,
                timestamp=alerts[0].timestamp,
                rule_id="CORR-002",
                title="Office Spawned Suspicious Command",
                description=(
                    "A process spawned by a Microsoft Office application "
                    "also exhibited suspicious command-line activity."
                ),
                severity="CRITICAL",
                risk_score=95,
                process_name=alerts[0].process_name,
                process_id=alerts[0].process_id,
                evidence={
                    "triggered_rules": sorted(rule_ids),
                    "source_alerts": [
                        alert.alert_id for alert in alerts
                    ],
                },
            )
        )

    return correlated_alerts