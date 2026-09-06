from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Risk configuration
# ---------------------------------------------------------------------------

RISK_THRESHOLDS = {
    "LOW": 30,
    "MEDIUM": 60,
    "HIGH": 80,
}

HISTORY_WINDOW_SECONDS = 60
MAX_HISTORY = 50

RISK_HISTORY = deque(maxlen=MAX_HISTORY)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _round_score(value: float) -> int:
    """
    Round risk scores using conventional half-up rounding.

    Python's built-in round() uses banker's rounding:
        round(55.5) == 56
        round(56.5) == 56

    For a security score, deterministic half-up rounding is easier to reason
    about:
        55.5 -> 56
        56.5 -> 57
    """
    return int(value + 0.51)


def _clamp(value: float, minimum: float = 0, maximum: float = 100) -> float:
    return max(minimum, min(value, maximum))


def _risk_level(score: int) -> str:
    if score >= RISK_THRESHOLDS["HIGH"]:
        return "CRITICAL"

    if score >= RISK_THRESHOLDS["MEDIUM"]:
        return "HIGH"

    if score >= RISK_THRESHOLDS["LOW"]:
        return "MEDIUM"

    return "LOW"


def _normalise_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a detector finding into an aggregate risk contribution.

    Detector severity remains the primary source of truth.

    Confidence modifies severity slightly rather than allowing a low
    confidence value to completely erase a serious detector finding.
    """

    raw_score = float(finding.get("risk_score", 0))
    confidence = float(finding.get("confidence", 1.0))

    confidence = _clamp(confidence, 0, 1)

    # Confidence has a deliberately narrow influence:
    #
    # 0% confidence  -> 85% of detector severity
    # 100% confidence -> 100% of detector severity
    #
    # This keeps detector severity meaningful while still accounting for
    # uncertainty.
    adjusted_score = raw_score * (
        0.85 + (0.15 * confidence)
    )

    return {
        "detection": finding.get("detection", "UNKNOWN"),
        "raw_score": raw_score,
        "confidence": confidence,
        "adjusted_score": adjusted_score,
    }


# ---------------------------------------------------------------------------
# Temporal history
# ---------------------------------------------------------------------------

def _record_history(
    timestamp: datetime,
    score: int,
) -> None:
    RISK_HISTORY.append(
        {
            "timestamp": timestamp,
            "score": score,
        }
    )


def _recent_history(
    now: datetime,
) -> List[Dict[str, Any]]:
    recent = []

    for entry in RISK_HISTORY:
        timestamp = entry["timestamp"]

        age = (now - timestamp).total_seconds()

        if age < 0:
            continue

        if age <= HISTORY_WINDOW_SECONDS:
            recent.append(entry)

    return recent


def _temporal_bonus(now: datetime) -> int:
    """
    Add a small bonus when suspicious activity is happening repeatedly.

    This is intentionally modest. Temporal activity should reinforce
    repeated attacks, not overwhelm the actual detector findings.

    We use a decayed activity value:

        very recent event ~= 1.0
        older event ~= smaller contribution

    Thresholds are intentionally forgiving so several immediate attacks
    consistently register as repeated activity despite tiny execution-time
    differences between events.
    """

    recent = _recent_history(now)

    if not recent:
        return 0

    weighted_activity = 0.0

    for entry in recent:
        age = (now - entry["timestamp"]).total_seconds()

        if age < 0 or age > HISTORY_WINDOW_SECONDS:
            continue

        score = float(entry.get("score", 0))

        if score <= 0:
            continue

        decay = max(
            0.0,
            1.0 - (age / HISTORY_WINDOW_SECONDS),
        )

        weighted_activity += decay

    # Four rapid suspicious events should clearly register as repeated
    # activity. We intentionally use 2.5 instead of 3.0 because the current
    # event is recorded after calculation and tiny execution delays can make
    # three previous events sum to slightly below 3.0.
    if weighted_activity >= 2.5:
        return 10

    if weighted_activity >= 1.5:
        return 6

    if weighted_activity > 0:
        return 3

    return 0


# ---------------------------------------------------------------------------
# Contextual risk
# ---------------------------------------------------------------------------

SENSITIVE_ENDPOINTS = (
    "/admin",
    "/users",
    "/profile",
    "/account",
    "/auth",
    "/login",
)


def _context_bonus(
    request_event: Dict[str, Any],
    response_event: Dict[str, Any] | None,
) -> int:
    """
    Add contextual risk based on what the request is doing.

    Context is deliberately capped so it cannot dominate detector findings.
    """

    bonus = 0

    path = request_event.get("path", "")
    method = request_event.get("method", "GET").upper()

    # Sensitive resources deserve a little additional scrutiny.
    if any(
        path == endpoint
        or path.startswith(endpoint + "/")
        for endpoint in SENSITIVE_ENDPOINTS
    ):
        bonus += 5

    # Mutating operations have a larger blast radius.
    if method in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        bonus += 3

    # Server errors can indicate exploitation or unstable backend behaviour.
    if response_event:
        status_code = response_event.get("status_code")

        try:
            status_code = int(status_code)

            if status_code >= 500:
                bonus += 5

        except (TypeError, ValueError):
            pass

    return min(bonus, 10)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _correlation_bonus(
    correlations: List[Dict[str, Any]] | None,
) -> int:
    """
    Add risk when multiple detections have already been correlated.

    Each correlated campaign signal contributes +10, capped at +20.
    """

    if not correlations:
        return 0

    bonus = 0

    for correlation in correlations:
        if not isinstance(correlation, dict):
            continue

        bonus += 10

    return min(bonus, 20)


# ---------------------------------------------------------------------------
# Main risk calculation
# ---------------------------------------------------------------------------

def calculate_risk(
    findings: List[Dict[str, Any]],
    request_event: Dict[str, Any] | None = None,
    response_event: Dict[str, Any] | None = None,
    correlations: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Calculate aggregate WYVRN risk.

    Design principles:

    1. The strongest detector finding dominates.
    2. Additional findings increase risk, but with diminishing influence.
    3. Confidence slightly modifies detector severity.
    4. Context adds only a small bounded amount.
    5. Correlation adds a bounded campaign signal.
    6. Recent repeated activity adds a small temporal bonus.
    7. Final score is always 0-100.

    This prevents a pile of weak findings from randomly producing huge scores
    while still allowing genuinely dangerous combinations to reach CRITICAL.
    """

    request_event = request_event or {}

    now = _now()

    # -----------------------------------------------------------------------
    # No findings
    # -----------------------------------------------------------------------

    if not findings:
        temporal_bonus = _temporal_bonus(now)

        contextual_bonus = _context_bonus(
            request_event,
            response_event,
        )

        correlation_bonus = _correlation_bonus(
            correlations,
        )

        score = _round_score(
            temporal_bonus
            + contextual_bonus
            + correlation_bonus
        )

        score = int(
            _clamp(score)
        )

        _record_history(now, score)

        return {
            "risk_score": score,
            "risk_level": _risk_level(score),
            "finding_count": 0,
            "detections": [],
            "confidence": 1.0,
        }

    # -----------------------------------------------------------------------
    # Normalise findings
    # -----------------------------------------------------------------------

    normalised = [
        _normalise_finding(finding)
        for finding in findings
    ]

    # Strongest finding first.
    normalised.sort(
        key=lambda item: item["adjusted_score"],
        reverse=True,
    )

    primary = normalised[0]

    score = primary["adjusted_score"]

    # -----------------------------------------------------------------------
    # Secondary findings
    # -----------------------------------------------------------------------

    #
    # Secondary findings contribute 20% of their adjusted severity.
    #
    # Each individual secondary contribution is capped at 15.
    #
    # Example:
    #
    # BOLA 60 + RATE_ABUSE 85
    #
    # primary ~= 58.5
    # secondary ~= 15
    #
    # => ~73.5 before context/correlation.
    #
    # This is intentionally much less explosive than simply summing detector
    # scores.
    #

    for secondary in normalised[1:]:
        contribution = secondary["adjusted_score"] * 0.20

        contribution = min(
            contribution,
            15,
        )

        score += contribution

    # -----------------------------------------------------------------------
    # Correlation
    # -----------------------------------------------------------------------

    score += _correlation_bonus(
        correlations
    )

    # -----------------------------------------------------------------------
    # Request/response context
    # -----------------------------------------------------------------------

    score += _context_bonus(
        request_event,
        response_event,
    )

    # -----------------------------------------------------------------------
    # Temporal activity
    # -----------------------------------------------------------------------

    score += _temporal_bonus(
        now
    )

    # -----------------------------------------------------------------------
    # Clamp + round
    # -----------------------------------------------------------------------

    score = _round_score(
        _clamp(score)
    )

    score = int(
        _clamp(score)
    )

    # -----------------------------------------------------------------------
    # Aggregate confidence
    # -----------------------------------------------------------------------

    #
    # The strongest finding dominates confidence too.
    #
    # Secondary findings contribute smaller amounts.
    #

    total_weight = 0.0
    weighted_confidence = 0.0

    for index, finding in enumerate(normalised):
        if index == 0:
            weight = 1.0
        else:
            weight = 0.25

        weighted_confidence += (
            finding["confidence"] * weight
        )

        total_weight += weight

    overall_confidence = (
        weighted_confidence / total_weight
        if total_weight
        else 1.0
    )

    overall_confidence = round(
        _clamp(overall_confidence),
        2,
    )

    # -----------------------------------------------------------------------
    # Result
    # -----------------------------------------------------------------------

    detections = [
        finding["detection"]
        for finding in normalised
    ]

    _record_history(
        now,
        score,
    )

    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "finding_count": len(findings),
        "detections": detections,
        "confidence": overall_confidence,
    }


# ---------------------------------------------------------------------------
# Convenience alias
# ---------------------------------------------------------------------------

def calculate_risk_score(
    findings: List[Dict[str, Any]],
    request_event: Dict[str, Any] | None = None,
    response_event: Dict[str, Any] | None = None,
    correlations: List[Dict[str, Any]] | None = None,
) -> int:
    """
    Return only the numeric risk score.

    Kept as a convenience helper for callers that do not need the complete
    risk result.
    """

    result = calculate_risk(
        findings=findings,
        request_event=request_event,
        response_event=response_event,
        correlations=correlations,
    )

    return result["risk_score"]