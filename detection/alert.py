from datetime import datetime

from pydantic import BaseModel


class DetectionAlert(BaseModel):
    alert_id: str
    event_id: str | None = None
    timestamp: datetime

    rule_id: str
    title: str
    description: str

    severity: str
    risk_score: int

    process_name: str | None = None
    process_id: int | None = None

    evidence: dict = {}