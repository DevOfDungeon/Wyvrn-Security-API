import re

from wyvrn.detectors.engine import make_finding


USER_OBJECT_PATTERN = re.compile(r"^/users/(\d+)$")


def detect_bola(request_event):
    findings = []

    path = request_event["path"]
    method = request_event["method"]

    if method != "GET":
        return findings

    match = USER_OBJECT_PATTERN.match(path)

    if not match:
        return findings

    user_id = int(match.group(1))

    findings.append(
        make_finding(
            detection="BOLA_IDOR",
            confidence=0.70,
            risk_score=60,
            reason=(
                "Direct object access detected on a user resource. "
                "Authorization should be verified before returning "
                "the requested object."
            ),
            metadata={
                "object_type": "user",
                "object_id": user_id,
            },
        )
    )

    return findings