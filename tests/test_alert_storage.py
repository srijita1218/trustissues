import sqlite3
from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent
from database.event_store import initialize_database, save_alert
from detection.engine import analyze_event


def test_detection_alert_is_stored(tmp_path, monkeypatch):
    database_path = tmp_path / "test_trustissues.db"

    monkeypatch.setattr(
        "database.event_store.DATABASE_PATH",
        str(database_path),
    )

    initialize_database()

    event = SecurityEvent(
        event_id="storage-test",
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

    alerts = analyze_event(event)

    assert len(alerts) == 3

    for alert in alerts:
        save_alert(alert)

    connection = sqlite3.connect(database_path)

    count = connection.execute(
        "SELECT COUNT(*) FROM detection_alerts"
    ).fetchone()[0]

    event_ids = connection.execute(
        "SELECT DISTINCT event_id FROM detection_alerts"
    ).fetchall()

    connection.close()

    assert count == 3
    assert event_ids == [("storage-test",)]