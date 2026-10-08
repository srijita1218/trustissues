import json
import sqlite3

from agent.models.security_event import SecurityEvent
from detection.alert import DetectionAlert


DATABASE_PATH = "trustissues.db"


def initialize_database():
    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            hostname TEXT NOT NULL,
            process_id INTEGER,
            parent_process_id INTEGER,
            process_name TEXT,
            executable_path TEXT,
            username TEXT,
            metadata TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_alerts (
            alert_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            process_name TEXT,
            process_id INTEGER,
            evidence TEXT
        )
        """
    )
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(detection_alerts)"
        )
    }

    if "event_id" not in columns:
        connection.execute(
            "ALTER TABLE detection_alerts ADD COLUMN event_id TEXT"
        )

    connection.commit()
    connection.close()


def save_event(event: SecurityEvent):
    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute(
        """
        INSERT INTO security_events (
            event_id,
            timestamp,
            event_type,
            hostname,
            process_id,
            parent_process_id,
            process_name,
            executable_path,
            username,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.event_id,
            event.timestamp.isoformat(),
            event.event_type,
            event.hostname,
            event.process_id,
            event.parent_process_id,
            event.process_name,
            event.executable_path,
            event.username,
            json.dumps(event.metadata),
        ),
    )

    connection.commit()
    connection.close()


def save_alert(alert: DetectionAlert):
    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute(
        """
        INSERT INTO detection_alerts (
            alert_id,
            event_id,
            timestamp,
            rule_id,
            title,
            description,
            severity,
            risk_score,
            process_name,
            process_id,
            evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            alert.event_id,
            alert.timestamp.isoformat(),
            alert.rule_id,
            alert.title,
            alert.description,
            alert.severity,
            alert.risk_score,
            alert.process_name,
            alert.process_id,
            json.dumps(alert.evidence),
        ),
    )

    connection.commit()
    connection.close()

def get_recent_events(limit: int = 100):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT *
        FROM security_events
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_recent_alerts(limit: int = 100):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT *
        FROM detection_alerts
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]

def get_event_by_id(event_id: str):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    row = connection.execute(
        """
        SELECT *
        FROM security_events
        WHERE event_id = ?
        """,
        (event_id,),
    ).fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


def get_alert_by_id(alert_id: str):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    row = connection.execute(
        """
        SELECT *
        FROM detection_alerts
        WHERE alert_id = ?
        """,
        (alert_id,),
    ).fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


def get_alerts_for_event(event_id: str):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT *
        FROM detection_alerts
        WHERE event_id = ?
        ORDER BY timestamp DESC
        """,
        (event_id,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_events_for_process(process_id: int, limit: int = 100):
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT *
        FROM security_events
        WHERE process_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (process_id, limit),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]