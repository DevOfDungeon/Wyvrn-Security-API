import json
import time

from collections import defaultdict, deque

from wyvrn.detectors.engine import make_finding


# ---------------------------------------------------------------------------
# Authentication abuse configuration
# ---------------------------------------------------------------------------

AUTH_FAILURE_WINDOW_SECONDS = 60
MAX_FAILED_ATTEMPTS = 5

# Protected paths used for bearer-token validation.
#
# This is intentionally small and explicit for the demo.
# In production, these would come from an API specification,
# gateway configuration, or authentication policy.
PROTECTED_PATHS = {
    "/admin",
    "/users",
    "/profile",
    "/account",
}


# Track failed authentication timestamps.
#
# Key:
#     (client_ip, username)
#
# Value:
#     deque of timestamps
#
FAILED_ATTEMPTS = defaultdict(deque)


def extract_username(request_event):
    """
    Extract the username involved in an authentication request.

    Supports:
    - query parameters
    - JSON request bodies
    """

    query_params = request_event.get(
        "query_params",
        {},
    )

    username = query_params.get(
        "username"
    )

    if username:
        return str(username)

    body = request_event.get("body")

    if not body:
        return None

    # Body may already be a dictionary.
    if isinstance(body, dict):

        username = body.get(
            "username"
        )

        if username:
            return str(username)

        return None

    # Try JSON body.
    try:

        parsed_body = json.loads(
            body
        )

        if isinstance(
            parsed_body,
            dict,
        ):

            username = parsed_body.get(
                "username"
            )

            if username:
                return str(username)

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        pass

    return None


def extract_authorization(request_event):
    """
    Extract the Authorization header.

    Header lookup is case-insensitive in normal
    HTTP requests, but request_event headers may be
    represented as a normal dictionary.
    """

    headers = request_event.get(
        "headers",
        {},
    )

    if not isinstance(
        headers,
        dict,
    ):
        return None

    for key, value in headers.items():

        if str(key).lower() == "authorization":

            if value:
                return str(value)

    return None


def _get_failure_history(
    client_ip,
    username,
):
    """
    Return the failure history for an IP + username pair.
    """

    return FAILED_ATTEMPTS[
        (
            client_ip,
            username,
        )
    ]


def _remove_expired_attempts(
    history,
    now,
):
    """
    Remove authentication failures outside
    the configured rolling window.
    """

    while (
        history
        and now - history[0]
        > AUTH_FAILURE_WINDOW_SECONDS
    ):

        history.popleft()


def detect_invalid_bearer_token(
    request_event,
):
    """
    Detect obviously invalid bearer-token usage
    against protected endpoints.

    This catches malformed/demo tokens before the
    request reaches the target API.

    Examples:

        Authorization: Bearer invalid-token
        Authorization: Bearer test-token
        Authorization: Bearer fake-token

    These are strong indicators of authentication
    abuse in a security gateway.

    Returns a finding only when:

    - the endpoint is protected
    - an Authorization header exists
    - the header uses Bearer authentication
    - the token is clearly invalid
    """

    findings = []

    path = request_event.get(
        "path"
    )

    if path not in PROTECTED_PATHS:
        return findings

    authorization = extract_authorization(
        request_event
    )

    if not authorization:
        return findings

    authorization_lower = (
        authorization.lower()
    )

    if not authorization_lower.startswith(
        "bearer "
    ):
        return findings

    token = authorization[
        len("Bearer "):
    ].strip()

    if not token:
        findings.append(
            make_finding(
                detection="AUTH_ABUSE",
                confidence=0.95,
                risk_score=80,
                reason=(
                    "Protected endpoint accessed with "
                    "an empty bearer token."
                ),
                metadata={
                    "auth_scheme": "Bearer",
                    "token_state": "empty",
                    "path": path,
                },
            )
        )

        return findings

    # Explicitly recognize obviously fake/demo tokens.
    invalid_token_markers = {
        "invalid-token",
        "invalid",
        "fake-token",
        "fake",
        "test-token",
        "test",
        "null",
        "undefined",
    }

    if token.lower() in invalid_token_markers:

        findings.append(
            make_finding(
                detection="AUTH_ABUSE",
                confidence=0.98,
                risk_score=85,
                reason=(
                    "Protected endpoint accessed with "
                    "an obviously invalid bearer token."
                ),
                metadata={
                    "auth_scheme": "Bearer",
                    "token_state": "invalid",
                    "path": path,
                },
            )
        )

    return findings


def detect_auth_abuse(
    request_event,
    response_status_code=None,
):
    """
    Detect authentication abuse.

    Detection mechanisms:

    1. Repeated failed authentication attempts.

       POST /login
       POST /auth/login

       Multiple HTTP 401 responses from the same
       IP + username within a rolling window trigger
       AUTH_ABUSE.

    2. Obviously invalid bearer tokens.

       Protected endpoints such as /admin are inspected
       for obviously invalid bearer credentials.

    The bearer-token detector is request-based because
    an obviously fake credential is itself a useful
    security signal.

    Login brute-force detection remains response-aware.
    """

    findings = []

    path = request_event.get(
        "path"
    )

    method = request_event.get(
        "method"
    )

    # -----------------------------------------------------------------------
    # Invalid bearer-token detection
    # -----------------------------------------------------------------------

    findings.extend(
        detect_invalid_bearer_token(
            request_event
        )
    )

    # -----------------------------------------------------------------------
    # Login brute-force detection
    # -----------------------------------------------------------------------

    # Only inspect login endpoints.
    if method != "POST":
        return findings

    if path not in {
        "/login",
        "/auth/login",
    }:
        return findings

    # We cannot determine whether authentication failed
    # until we know the upstream response.
    if response_status_code is None:
        return findings

    client_ip = (
        request_event.get(
            "client_ip"
        )
        or "unknown"
    )

    username = extract_username(
        request_event
    )

    # If the username is unavailable, fall back to
    # IP-based tracking.
    username_key = (
        username
        if username
        else "unknown"
    )

    history = _get_failure_history(
        client_ip,
        username_key,
    )

    now = time.time()

    _remove_expired_attempts(
        history,
        now,
    )

    # -----------------------------------------------------------------------
    # Failed authentication
    # -----------------------------------------------------------------------

    if response_status_code == 401:

        history.append(
            now
        )

        attempts = len(
            history
        )

        if attempts >= MAX_FAILED_ATTEMPTS:

            findings.append(
                make_finding(
                    detection="AUTH_ABUSE",
                    confidence=0.95,
                    risk_score=80,
                    reason=(
                        f"Repeated failed authentication "
                        f"attempts detected from "
                        f"{client_ip}"
                        f" for username "
                        f"'{username_key}': "
                        f"{attempts} failures within "
                        f"{AUTH_FAILURE_WINDOW_SECONDS} "
                        f"seconds."
                    ),
                    metadata={
                        "client_ip": client_ip,
                        "username": username_key,
                        "attempts": attempts,
                        "window_seconds": (
                            AUTH_FAILURE_WINDOW_SECONDS
                        ),
                        "status_code": (
                            response_status_code
                        ),
                    },
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Successful authentication
    # -----------------------------------------------------------------------

    if (
        200
        <= response_status_code
        < 300
    ):

        history.clear()

    return findings