from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent
from detection.engine import analyze_event
from detection.correlator import correlate_alerts
from detection.risk import calculate_risk_score


def make_suspicious_event():
    return SecurityEvent(
        event_id="pipeline-test",
        timestamp=datetime.now(timezone.utc),
        event_type="process",
        hostname="TEST-PC",
        process_id=1234,
        parent_process_id=5678,
        process_name="powershell.exe",
        executable_path=r"C:\Users\Test\AppData\Local\Temp\test.exe",
        username="testuser",
        metadata={
            "command_line": "powershell.exe -EncodedCommand suspicious",
            "parent_process_name": "winword.exe",
        },
    )


def test_full_detection_pipeline():
    event = make_suspicious_event()

    alerts = analyze_event(event)

    assert len(alerts) == 3

    correlated = correlate_alerts(alerts)

    assert len(correlated) == 2

    risk_score = calculate_risk_score(
        alerts + correlated
    )

    assert risk_score == 100