import uuid
from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent
from detection.alert import DetectionAlert
from detection.rules import (
    suspicious_command_line,
    suspicious_execution_path,
    suspicious_parent,
)


def analyze_event(event: SecurityEvent) -> list[DetectionAlert]:
    alerts = []

    if suspicious_execution_path(event):
        alerts.append(
           DetectionAlert(
                alert_id=str(uuid.uuid4()),
                event_id=event.event_id,
                timestamp=datetime.now(timezone.utc),
                rule_id="TI-001",
                title="Process Executed From Suspicious Location",
                description=(
                    "A process was executed from a location "
                    "commonly associated with user-writable or "
                    "temporary files."
                ),
                severity="MEDIUM",
                risk_score=40,
                process_name=event.process_name,
                process_id=event.process_id,
                evidence={
                    "executable_path": event.executable_path,
                },
            )
        )

    if suspicious_command_line(event):
        alerts.append(
            DetectionAlert(
                alert_id=str(uuid.uuid4()),
                event_id=event.event_id,
                timestamp=datetime.now(timezone.utc),
                rule_id="TI-002",
                title="Suspicious Command-Line Activity",
                description=(
                    "A process command line contained "
                    "a potentially suspicious execution pattern."
                ),
                severity="HIGH",
                risk_score=60,
                process_name=event.process_name,
                process_id=event.process_id,
                evidence={
                    "command_line": event.metadata.get("command_line"),
                },
            )
        )

    if suspicious_parent(event):
        alerts.append(
            DetectionAlert(
                alert_id=str(uuid.uuid4()),
                event_id=event.event_id,
                timestamp=datetime.now(timezone.utc),
                rule_id="TI-003",
                title="Suspicious Parent Process",
                description=(
                    "A process was spawned by a Microsoft Office "
                    "application, a parent-child relationship "
                    "commonly associated with malicious document activity."
                ),
                severity="HIGH",
                risk_score=70,
                process_name=event.process_name,
                process_id=event.process_id,
                evidence={
                    "parent_process_name": event.metadata.get(
                        "parent_process_name"
                    ),
                },
            )
        )

    return alerts