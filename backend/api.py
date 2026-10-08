from fastapi import FastAPI, HTTPException
from detection.mitre import get_mitre_mapping

from database.event_store import (
    get_alert_by_id,
    get_alerts_for_event,
    get_event_by_id,
    get_events_for_process,
    get_recent_alerts,
    get_recent_events,
    initialize_database,
)

app = FastAPI(
    title="trustIssues EDR API",
    description="Endpoint Detection and Response backend",
    version="1.0.0",
)


initialize_database()

@app.get("/attack-techniques")
def get_attack_techniques():
    alerts = get_recent_alerts(1000)

    techniques = []

    for alert in alerts:
        mapping = get_mitre_mapping(alert["rule_id"])

        if mapping is None:
            continue

        techniques.append(
            {
                "alert_id": alert["alert_id"],
                "rule_id": alert["rule_id"],
                "technique": mapping["technique"],
                "name": mapping["name"],
            }
        )

    return {
        "count": len(techniques),
        "techniques": techniques,
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "trustIssues EDR API",
    }


@app.get("/events")
def get_events(limit: int = 100):
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    return {
        "count": len(get_recent_events(limit)),
        "events": get_recent_events(limit),
    }


@app.get("/alerts")
def get_alerts(limit: int = 100):
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    return {
        "count": len(get_recent_alerts(limit)),
        "alerts": get_recent_alerts(limit),
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = get_alert_by_id(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert


@app.get("/stats")
def get_stats():
    events = get_recent_events(1000)
    alerts = get_recent_alerts(1000)

    severity_counts = {}

    for alert in alerts:
        severity = alert["severity"]

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    return {
        "events_analyzed": len(events),
        "alerts_generated": len(alerts),
        "alerts_by_severity": severity_counts,
    }

@app.get("/investigations/event/{event_id}")
def investigate_event(event_id: str):
    event = get_event_by_id(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    alerts = get_alerts_for_event(event_id)

    risk_score = 0

    for alert in alerts:
        risk_score = max(
            risk_score,
            alert["risk_score"],
        )

    techniques = []

    for alert in alerts:
        mapping = get_mitre_mapping(alert["rule_id"])

        if mapping is None:
            continue

        techniques.append(
            {
                "rule_id": alert["rule_id"],
                "technique": mapping["technique"],
                "name": mapping["name"],
            }
        )

    return {
        "event": event,
        "alerts": alerts,
        "alert_count": len(alerts),
        "risk_score": risk_score,
        "mitre_techniques": techniques,
    }

@app.get("/processes/{process_id}")
def investigate_process(process_id: int):
    events = get_events_for_process(process_id)

    if not events:
        raise HTTPException(
            status_code=404,
            detail="No events found for this process",
        )

    return {
        "process_id": process_id,
        "event_count": len(events),
        "events": events,
    }