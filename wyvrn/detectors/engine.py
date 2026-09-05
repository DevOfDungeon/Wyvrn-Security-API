from typing import Any, Dict, List


def make_finding(
    detection: str,
    confidence: float,
    risk_score: int,
    reason: str,
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:

    return {
        "detection": detection,
        "confidence": confidence,
        "risk_score": risk_score,
        "reason": reason,
        "metadata": metadata or {},
    }


def run_detectors(
    request_event: Dict[str, Any],
) -> List[Dict[str, Any]]:

    findings = []

    from wyvrn.detectors.bola import detect_bola
    from wyvrn.detectors.rate_limit import detect_rate_abuse
    from wyvrn.detectors.injection import detect_injection

    # -----------------------------------------------------------------------
    # Request-side detectors
    # -----------------------------------------------------------------------

    findings.extend(
        detect_bola(request_event)
    )

    findings.extend(
        detect_rate_abuse(request_event)
    )

    findings.extend(
        detect_injection(request_event)
    )

    return findings