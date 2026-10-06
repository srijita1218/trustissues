import socket
import uuid
from datetime import datetime, timezone

from agent.models.security_event import SecurityEvent

#normalization layer

def normalize_process(process_data: dict) -> SecurityEvent:
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type="PROCESS_OBSERVED",
        hostname=socket.gethostname(),

        process_id=process_data.get("pid"),
        parent_process_id=process_data.get("ppid"),

        process_name=process_data.get("name"),
        executable_path=process_data.get("exe"),
        username=process_data.get("username"),

        metadata={
            "cpu_percent": process_data.get("cpu_percent"),
            "memory_percent": process_data.get("memory_percent"),
        },
    )