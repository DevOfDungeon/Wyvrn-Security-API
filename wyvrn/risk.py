from typing import Any, Dict, List, Set


# ============================================================
# RISK LEVELS
# ============================================================

def get_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# ATTACK CORRELATION RULES
# ============================================================
#
# These rules identify combinations of detections that are
# more meaningful together than individually.
#
# Each rule contains:
#
#   name
#       Human-readable attack description.
#
#   detections
#       Detection types required for the correlation.
#
#   bonus
#       Additional risk added when the combination appears.
#
# ============================================================

CORRELATION_RULES = [
    {
        "name": "COORDINATED_INJECTION_ABUSE",
        "detections": {
            "SQL_INJECTION",
            "RATE_ABUSE",
        },
        "bonus": 20,
        "reason": (
            "SQL injection activity is combined with "
            "excessive request volume, indicating a "
            "potential automated attack."
        ),
    },
    {
        "name": "POTENTIAL_DATA_EXFILTRATION",
        "detections": {
            "BOLA_IDOR",
            "SENSITIVE_DATA_EXPOSURE",
        },
        "bonus": 20,
        "reason": (
            "Unauthorized object access is combined with "
            "sensitive data exposure, indicating potential "
            "data exfiltration."
        ),
    },
    {
        "name": "CREDENTIAL_ATTACK",
        "detections": {
            "AUTH_ABUSE",
            "RATE_ABUSE",
        },
        "bonus": 20,
        "reason": (
            "Repeated authentication failures are combined "
            "with excessive request volume, indicating a "
            "potential credential attack."
        ),
    },
    {
        "name": "INJECTION_WITH_DATA_EXPOSURE",
        "detections": {
            "SQL_INJECTION",
            "SENSITIVE_DATA_EXPOSURE",
        },
        "bonus": 20,
        "reason": (
            "Injection activity is combined with sensitive "
            "data exposure, indicating potential exploitation "
            "of a data-access vulnerability."
        ),
    },
]


# ============================================================
# CORRELATION ENGINE
# ============================================================

def detect_correlations(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Identify meaningful combinations of security findings.
    """

    detections: Set[str] = {
        finding.get("detection")
        for finding in findings
        if finding.get("detection")
    }

    correlations = []

    for rule in CORRELATION_RULES:

        required_detections = rule[
            "detections"
        ]

        if required_detections.issubset(
            detections
        ):

            correlations.append(
                {
                    "name": rule["name"],
                    "bonus": rule["bonus"],
                    "detections": sorted(
                        required_detections
                    ),
                    "reason": rule["reason"],
                }
            )

    return correlations


# ============================================================
# OVERALL RISK CALCULATION
# ============================================================

def calculate_risk(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:

    # --------------------------------------------------------
    # No findings
    # --------------------------------------------------------

    if not findings:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "finding_count": 0,
            "detections": [],
            "correlations": [],
        }

    # --------------------------------------------------------
    # Individual finding scores
    # --------------------------------------------------------

    scores = []

    for finding in findings:

        score = finding.get(
            "risk_score",
            0,
        )

        confidence = finding.get(
            "confidence",
            1.0,
        )

        adjusted_score = (
            score * confidence
        )

        scores.append(
            adjusted_score
        )

    # --------------------------------------------------------
    # Strongest finding
    # --------------------------------------------------------

    strongest_score = max(
        scores
    )

    # --------------------------------------------------------
    # Generic multi-finding bonus
    #
    # This represents the fact that multiple independent
    # security signals increase confidence that something
    # suspicious is happening.
    #
    # Explicit correlation rules below provide additional
    # context-specific escalation.
    # --------------------------------------------------------

    additional_findings = max(
        0,
        len(scores) - 1,
    )

    generic_correlation_bonus = min(
        additional_findings * 5,
        10,
    )

    # --------------------------------------------------------
    # Explicit attack correlations
    # --------------------------------------------------------

    correlations = detect_correlations(
        findings
    )

    correlation_bonus = sum(
        correlation["bonus"]
        for correlation in correlations
    )

    # Never allow correlation bonuses themselves to
    # become disproportionately large.
    correlation_bonus = min(
        correlation_bonus,
        40,
    )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    final_score = (
        strongest_score
        + generic_correlation_bonus
        + correlation_bonus
    )

    final_score = min(
        100,
        round(final_score),
    )

    # --------------------------------------------------------
    # Detection names
    # --------------------------------------------------------

    detections = [
        finding.get("detection")
        for finding in findings
    ]

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "risk_score": final_score,

        "risk_level": get_risk_level(
            final_score
        ),

        "finding_count": len(
            findings
        ),

        "detections": detections,

        "correlations": correlations,
    }
