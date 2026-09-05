from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List


CORRELATION_WINDOW_SECONDS = 60
MIN_CORRELATED_EVENTS = 2

DETECTION_WEIGHTS = {
    "SQL_INJECTION": 30,
    "BOLA_IDOR": 25,
    "AUTH_ABUSE": 25,
    "RATE_ABUSE": 20,
    "SENSITIVE_DATA_EXPOSURE": 30,
    "SENSITIVE_DATA_PATTERN": 10,
    "EXCESSIVE_DATA_EXPOSURE": 20,
    "BEHAVIORAL_ANOMALY": 20,
}


def _parse_timestamp(timestamp: str) -> datetime:
    """
    Parse an ISO-8601 timestamp into a timezone-aware datetime.
    """

    parsed = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed


def _event_age_seconds(event: Dict[str, Any]) -> float:
    """
    Return the age of an event in seconds.
    """

    try:
        event_time = _parse_timestamp(
            event["timestamp"]
        )

        now = datetime.now(timezone.utc)

        return (
            now - event_time
        ).total_seconds()

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return float("inf")


def _get_client_ip(event: Dict[str, Any]) -> str:
    """
    Extract the client IP from a security event.
    """

    request = event.get(
        "request",
        {}
    )

    return (
        request.get("client_ip")
        or "unknown"
    )


def _get_detections(event: Dict[str, Any]) -> List[str]:
    """
    Extract detector names from a security event.
    """

    risk = event.get(
        "risk",
        {}
    )

    detections = risk.get(
        "detections",
        []
    )

    return list(
        dict.fromkeys(detections)
    )


def correlate_events(
    events: List[Dict[str, Any]],
    client_ip: str,
) -> Dict[str, Any] | None:
    """
    Correlate recent security events belonging
    to the same client.

    Returns an attack campaign when multiple
    distinct security signals occur within the
    correlation window.
    """

    recent_events = []

    for event in events:

        if _get_client_ip(event) != client_ip:
            continue

        age = _event_age_seconds(event)

        if age < 0:
            continue

        if age > CORRELATION_WINDOW_SECONDS:
            continue

        recent_events.append(event)

    if len(recent_events) < MIN_CORRELATED_EVENTS:
        return None

    detections = []

    for event in recent_events:
        detections.extend(
            _get_detections(event)
        )

    unique_detections = list(
        dict.fromkeys(detections)
    )

    if len(unique_detections) < MIN_CORRELATED_EVENTS:
        return None

    correlation_score = 0

    for detection in unique_detections:
        correlation_score += DETECTION_WEIGHTS.get(
            detection,
            10,
        )

    correlation_score = min(
        correlation_score,
        100,
    )

    if correlation_score >= 80:
        severity = "CRITICAL"

    elif correlation_score >= 60:
        severity = "HIGH"

    elif correlation_score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    event_summaries = []

    for event in recent_events:
        request = event.get(
            "request",
            {}
        )

        risk = event.get(
            "risk",
            {}
        )

        policy = event.get(
            "policy",
            {}
        )

        event_summaries.append(
            {
                "request_id": event.get(
                    "request_id"
                ),
                "timestamp": event.get(
                    "timestamp"
                ),
                "method": request.get(
                    "method"
                ),
                "path": request.get(
                    "path"
                ),
                "risk_score": risk.get(
                    "score",
                    risk.get(
                        "risk_score"
                    ),
                ),
                "action": policy.get(
                    "action"
                ),
                "detections": _get_detections(
                    event
                ),
            }
        )

    return {
        "type": "ATTACK_CAMPAIGN",
        "client_ip": client_ip,
        "window_seconds": CORRELATION_WINDOW_SECONDS,
        "event_count": len(recent_events),
        "unique_detections": unique_detections,
        "correlation_score": correlation_score,
        "severity": severity,
        "events": event_summaries,
    }


def correlate_latest_event(
    latest_event: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> Dict[str, Any] | None:
    """
    Correlate the latest security event against
    recently stored events from the same client.
    """

    client_ip = _get_client_ip(
        latest_event
    )

    return correlate_events(
        events,
        client_ip,
    )
