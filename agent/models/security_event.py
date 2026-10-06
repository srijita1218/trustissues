"""
creating a common event schema for all security events to be sent to the server
"""

from datetime import datetime, timezone
from pydantic import BaseModel


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    hostname: str

    process_id: int | None = None
    parent_process_id: int | None = None

    process_name: str | None = None
    executable_path: str | None = None
    username: str | None = None

    metadata: dict = {}