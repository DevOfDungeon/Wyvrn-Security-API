from collections import defaultdict
from wyvrn.detectors.engine import make_finding


FAILED_ATTEMPTS = defaultdict(int)

MAX_FAILED_ATTEMPTS = 5


def detect_auth_abuse(request_event):
    findings = []

    path = request_event["path"]
    method = request_event["method"]
    client_ip = request_event.get("client_ip") or "unknown"

    # Only monitor login/authentication endpoints.
    if method != "POST":
        return findings

    if path not in {"/login", "/auth/login"}:
        return findings

    # The response status isn't available at this stage,
    # so the middleware will update this detector later.
    #
    # For now, count login attempts.
    FAILED_ATTEMPTS[client_ip] += 1

    attempts = FAILED_ATTEMPTS[client_ip]

    if attempts >= MAX_FAILED_ATTEMPTS:
        findings.append(
            make_finding(
                detection="AUTH_ABUSE",
                confidence=0.90,
                risk_score=75,
                reason=(
                    f"Repeated authentication attempts from "
                    f"{client_ip}: {attempts} attempts"
                ),
                metadata={
                    "client_ip": client_ip,
                    "attempts": attempts,
                },
            )
        )

    return findings