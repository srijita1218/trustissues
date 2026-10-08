from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent
from detection.engine import analyze_event


def make_event(
    executable_path=None,
    command_line=None,
    parent_process_name=None,
):
    metadata = {}

    if command_line:
        metadata["command_line"] = command_line

    if parent_process_name:
        metadata["parent_process_name"] = parent_process_name

    return SecurityEvent(
        event_id="test-event",
        timestamp=datetime.now(timezone.utc),
        event_type="process",
        process_name="test.exe",
        process_id=1234,
        executable_path=executable_path,
        username="testuser",
        hostname="TEST-PC",
        metadata=metadata,
    )


def test_suspicious_execution_path():
    event = make_event(
        executable_path=r"C:\Users\Test\AppData\Local\Temp\malware.exe"
    )

    alerts = analyze_event(event)

    assert any(alert.rule_id == "TI-001" for alert in alerts)


def test_suspicious_command_line():
    event = make_event(
        command_line="powershell.exe -EncodedCommand suspicious"
    )

    alerts = analyze_event(event)

    assert any(alert.rule_id == "TI-002" for alert in alerts)


def test_suspicious_parent_process():
    event = make_event(
        parent_process_name="winword.exe"
    )

    alerts = analyze_event(event)

    assert any(alert.rule_id == "TI-003" for alert in alerts)


def test_normal_process_creates_no_alerts():
    event = make_event(
        executable_path=r"C:\Program Files\Test\test.exe",
        command_line="test.exe --normal",
        parent_process_name="explorer.exe",
    )

    alerts = analyze_event(event)

    assert alerts == []