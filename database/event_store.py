import json
import sqlite3

from agent.models.security_event import SecurityEvent


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