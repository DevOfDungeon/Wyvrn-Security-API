from typing import Any, Dict, List


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
# OVERALL RISK CALCULATION
# ============================================================

def calculate_risk(
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:

    if not findings:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "finding_count": 0,
            "detections": [],
        }

    # --------------------------------------------------------
    # Individual finding scores
    # --------------------------------------------------------

    scores = []

    for finding in findings:
        score = finding.get("risk_score", 0)
        confidence = finding.get("confidence", 1.0)

        adjusted_score = score * confidence

        scores.append(adjusted_score)

    # --------------------------------------------------------
    # Combine findings
    #
    # We don't simply add everything together because multiple
    # detectors can observe the same underlying attack.
    #
    # Instead:
    #   strongest finding
    #   + bonus for additional independent findings
    # --------------------------------------------------------

    strongest_score = max(scores)

    additional_findings = max(
        0,
        len(scores) - 1,
    )

    correlation_bonus = min(
        additional_findings * 10,
        20,
    )

    final_score = min(
        100,
        round(strongest_score + correlation_bonus),
    )

    detections = [
        finding.get("detection")
        for finding in findings
    ]

    return {
        "risk_score": final_score,
        "risk_level": get_risk_level(final_score),
        "finding_count": len(findings),
        "detections": detections,
    }
