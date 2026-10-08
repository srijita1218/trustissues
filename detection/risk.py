from detection.alert import DetectionAlert


SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 60,
}


def calculate_risk_score(alerts: list[DetectionAlert]) -> int:
    if not alerts:
        return 0

    rule_score = sum(
        SEVERITY_WEIGHTS.get(alert.severity.upper(), 0)
        for alert in alerts
    )

    detection_score = sum(
        alert.risk_score
        for alert in alerts
    )

    score = max(rule_score, detection_score)

    return min(score, 100)