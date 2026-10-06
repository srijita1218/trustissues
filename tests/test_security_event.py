from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent


def test_security_event_creation():
    event = SecurityEvent(
        event_id="test-event",
        timestamp=datetime.now(timezone.utc),
        event_type="PROCESS_OBSERVED",
        hostname="test-machine",
        process_id=1234,
        parent_process_id=1000,
        process_name="python.exe",
    )

    assert event.event_type == "PROCESS_OBSERVED"
    assert event.process_id == 1234
    assert event.process_name == "python.exe"