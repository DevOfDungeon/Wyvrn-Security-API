from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Set


# ============================================================
# RISK LEVELS
# ============================================================

LOW_THRESHOLD = 30
HIGH_THRESHOLD = 60
CRITICAL_THRESHOLD = 80


def get_risk_level(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= LOW_THRESHOLD:
        return "MEDIUM"
    return "LOW"


# ============================================================
# RISK HISTORY
# ============================================================

HISTORY_WINDOW_SECONDS = 60
MAX_HISTORY = 50
RISK_HISTORY = defaultdict(lambda: deque(maxlen=MAX_HISTORY))


def reset_risk_history() -> None:
    """Clear temporal risk state. Useful for tests and controlled resets."""
    RISK_HISTORY.clear()


def _record_history(history_key: str, score: int) -> None:
    RISK_HISTORY[history_key].append((time.time(), score))


def _temporal_bonus(history_key: str | None) -> int:
    """Return a small decayed bonus when recent risk already exists."""
    if not history_key:
        return 0

    now = time.time()
    history = RISK_HISTORY[history_key]
    recent = []

    for timestamp, score in history:
        age = now - timestamp
        if 0 <= age <= HISTORY_WINDOW_SECONDS:
            # Linear decay: a signal 60s old contributes almost nothing.
            weight = max(0.0, 1.0 - age / HISTORY_WINDOW_SECONDS)
            recent.append(score * weight)

    if not recent:
        return 0

    average = sum(recent) / len(recent)
    return min(15, round(average * 0.15))


# ============================================================
# CONTEXT WEIGHTS
# ============================================================

SENSITIVE_ENDPOINTS = (
    "/admin",
    "/auth",
    "/login",
    "/profile",
    "/account",
    "/users",
)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _context_bonus(context: Dict[str, Any] | None) -> tuple[int, List[Dict[str, Any]]]:
    if not context:
        return 0, []

    bonus = 0
    contributions: List[Dict[str, Any]] = []
    path = str(context.get("path") or "").lower()
    method = str(context.get("method") or "").upper()
    status_code = context.get("status_code")

    if any(path == endpoint or path.startswith(endpoint + "/") for endpoint in SENSITIVE_ENDPOINTS):
        bonus += 8
        contributions.append({
            "factor": "ENDPOINT_SENSITIVITY",
            "points": 8,
            "reason": "Request targets a security-sensitive API resource.",
        })

    if method in MUTATING_METHODS:
        bonus += 2
        contributions.append({
            "factor": "MUTATING_REQUEST",
            "points": 2,
            "reason": "Request can modify server-side state.",
        })

    try:
        status = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status = None

    if status is not None and 500 <= status <= 599:
        bonus += 8
        contributions.append({
            "factor": "SERVER_ERROR",
            "points": 8,
            "reason": f"Upstream endpoint returned HTTP {status}.",
        })

    return min(bonus, 15), contributions


# ============================================================
# ATTACK CORRELATION RULES
# ============================================================

CORRELATION_RULES = [
    {
        "name": "COORDINATED_INJECTION_ABUSE",
        "detections": {"SQL_INJECTION", "RATE_ABUSE"},
        "bonus": 20,
        "reason": (
            "SQL injection activity is combined with excessive request "
            "volume, indicating a potential automated attack."
        ),
    },
    {
        "name": "POTENTIAL_DATA_EXFILTRATION",
        "detections": {"BOLA_IDOR", "SENSITIVE_DATA_EXPOSURE"},
        "bonus": 20,
        "reason": (
            "Unauthorized object access is combined with sensitive data "
            "exposure, indicating potential data exfiltration."
        ),
    },
    {
        "name": "CREDENTIAL_ATTACK",
        "detections": {"AUTH_ABUSE", "RATE_ABUSE"},
        "bonus": 20,
        "reason": (
            "Repeated authentication failures are combined with excessive "
            "request volume, indicating a potential credential attack."
        ),
    },
    {
        "name": "INJECTION_WITH_DATA_EXPOSURE",
        "detections": {"SQL_INJECTION", "SENSITIVE_DATA_EXPOSURE"},
        "bonus": 20,
        "reason": (
            "Injection activity is combined with sensitive data exposure, "
            "indicating potential exploitation of a data-access vulnerability."
        ),
    },
]


def detect_correlations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    detections: Set[str] = {
        finding.get("detection")
        for finding in findings
        if finding.get("detection")
    }

    correlations = []
    for rule in CORRELATION_RULES:
        required = rule["detections"]
        if required.issubset(detections):
            correlations.append({
                "name": rule["name"],
                "bonus": rule["bonus"],
                "detections": sorted(required),
                "reason": rule["reason"],
            })
    return correlations


# ============================================================
# HELPERS
# ============================================================

def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _normalise_finding(finding: Dict[str, Any]) -> tuple[str, float, float]:
    detection = str(finding.get("detection") or "UNKNOWN")
    score = _clamp(float(finding.get("risk_score", 0) or 0), 0, 100)
    confidence = _clamp(float(finding.get("confidence", 1.0) or 0), 0, 1)

    # Confidence should reduce severity, but not erase it.
    # A 0% confidence finding retains 50% of its detector severity.
    adjusted = score * (0.50 + 0.50 * confidence)
    return detection, adjusted, confidence


# ============================================================
# OVERALL RISK CALCULATION
# ============================================================

def calculate_risk(
    findings: List[Dict[str, Any]],
    context: Dict[str, Any] | None = None,
    history_key: str | None = None,
    track_history: bool = False,
) -> Dict[str, Any]:
    """
    Calculate an explainable 0-100 risk score.

    Backwards compatible with the original ``calculate_risk(findings)`` API.
    Optional context/history enables richer scoring without requiring every
    caller to adopt Risk Engine v2 immediately.
    """

    if not findings:
        result = {
            "risk_score": 0,
            "risk_level": "LOW",
            "confidence": 1.0,
            "finding_count": 0,
            "detections": [],
            "correlations": [],
            "score_contributions": [],
            "temporal_bonus": 0,
        }
        if track_history and history_key:
            _record_history(history_key, 0)
        return result

    normalised = [_normalise_finding(finding) for finding in findings]
    normalised.sort(key=lambda item: item[1], reverse=True)

    # Strongest signal dominates. Additional independent signals contribute
    # progressively less so three weak findings cannot overpower one severe one.
    strongest = normalised[0][1]
    secondary = normalised[1][1] * 0.25 if len(normalised) >= 2 else 0
    tertiary = sum(item[1] for item in normalised[2:]) * 0.10

    base_score = strongest + secondary + tertiary

    contributions: List[Dict[str, Any]] = []
    for detection, adjusted, confidence in normalised:
        weight = 1.0 if adjusted == strongest else 0.25 if adjusted == normalised[1][1] and len(normalised) >= 2 else 0.10
        contributions.append({
            "factor": detection,
            "points": round(adjusted * weight, 2),
            "detector_score": round(adjusted, 2),
            "confidence": round(confidence, 2),
        })

    correlations = detect_correlations(findings)
    correlation_bonus = min(
        40,
        sum(correlation["bonus"] for correlation in correlations),
    )

    if correlation_bonus:
        contributions.append({
            "factor": "ATTACK_CORRELATION",
            "points": correlation_bonus,
            "reason": "Multiple detection signals form a known attack pattern.",
        })

    context_bonus, context_contributions = _context_bonus(context)
    contributions.extend(context_contributions)

    temporal_bonus = _temporal_bonus(history_key)
    if temporal_bonus:
        contributions.append({
            "factor": "RECENT_ACTIVITY",
            "points": temporal_bonus,
            "reason": "Recent risk from the same source is still decaying within the active window.",
        })

    final_score = min(
        100,
        round(base_score + correlation_bonus + context_bonus + temporal_bonus),
    )

    # Confidence is the average confidence of the signals, weighted toward
    # stronger detections.
    total_weight = sum(item[1] for item in normalised)
    if total_weight:
        overall_confidence = sum(item[1] * item[2] for item in normalised) / total_weight
    else:
        overall_confidence = 0.0

    result = {
        "risk_score": final_score,
        "risk_level": get_risk_level(final_score),
        "confidence": round(_clamp(overall_confidence, 0, 1), 2),
        "finding_count": len(findings),
        "detections": [finding.get("detection") for finding in findings],
        "correlations": correlations,
        "score_contributions": contributions,
        "temporal_bonus": temporal_bonus,
    }

    if track_history and history_key:
        _record_history(history_key, final_score)

    return result
