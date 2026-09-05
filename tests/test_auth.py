from wyvrn.detectors.auth import (
    FAILED_ATTEMPTS,
    detect_auth_abuse,
)


def setup_function():
    FAILED_ATTEMPTS.clear()


def make_login_request(
    username="alice",
    client_ip="127.0.0.1",
):
    return {
        "request_id": "test-request",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "method": "POST",
        "path": "/login",
        "client_ip": client_ip,
        "headers": {},
        "query_params": {
            "username": username,
        },
        "body": None,
    }


def test_single_failed_login_is_not_abuse():
    request = make_login_request()

    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=401,
    )

    assert findings == []


def test_four_failed_logins_are_not_abuse():
    request = make_login_request()

    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_fifth_failed_login_detects_auth_abuse():
    request = make_login_request()

    for _ in range(5):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "AUTH_ABUSE"
    assert finding["confidence"] == 0.95
    assert finding["risk_score"] == 80

    assert (
        finding["metadata"]["attempts"]
        == 5
    )

    assert (
        finding["metadata"]["username"]
        == "alice"
    )

    assert (
        finding["metadata"]["status_code"]
        == 401
    )


def test_successful_login_does_not_count_as_failure():
    request = make_login_request()

    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []

    # Successful authentication clears the history.
    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=200,
    )

    assert findings == []

    # Four more failures should still not trigger.
    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_successful_login_is_not_auth_abuse():
    request = make_login_request()

    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=200,
    )

    assert findings == []


def test_non_401_response_does_not_count_as_failure():
    request = make_login_request()

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=500,
        )

    assert findings == []


def test_get_request_is_ignored():
    request = make_login_request()

    request["method"] = "GET"

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_non_login_endpoint_is_ignored():
    request = make_login_request()

    request["path"] = "/users/1"

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_failures_are_tracked_per_username():
    alice_request = make_login_request(
        username="alice",
    )

    bob_request = make_login_request(
        username="bob",
    )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                alice_request,
                401,
            )
            == []
        )

    # Bob has his own failure counter.
    for _ in range(4):
        assert (
            detect_auth_abuse(
                bob_request,
                401,
            )
            == []
        )

    # Fifth Alice attempt triggers.
    findings = detect_auth_abuse(
        alice_request,
        401,
    )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["username"]
        == "alice"
    )


def test_failures_are_tracked_per_ip():
    attacker_one = make_login_request(
        username="alice",
        client_ip="10.0.0.1",
    )

    attacker_two = make_login_request(
        username="alice",
        client_ip="10.0.0.2",
    )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                attacker_one,
                401,
            )
            == []
        )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                attacker_two,
                401,
            )
            == []
        )

    findings = detect_auth_abuse(
        attacker_one,
        401,
    )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["client_ip"]
        == "10.0.0.1"
    )


def test_json_body_username_is_detected():
    request = {
        "request_id": "test-request",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "method": "POST",
        "path": "/login",
        "client_ip": "127.0.0.1",
        "headers": {
            "content-type": "application/json",
        },
        "query_params": {},
        "body": (
            '{"username":"alice",'
            '"password":"wrong"}'
        ),
    }

    for _ in range(5):
        findings = detect_auth_abuse(
            request,
            401,
        )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["username"]
        == "alice"
    )from wyvrn.detectors.auth import (
    FAILED_ATTEMPTS,
    detect_auth_abuse,
)


def setup_function():
    FAILED_ATTEMPTS.clear()


def make_login_request(
    username="alice",
    client_ip="127.0.0.1",
):
    return {
        "request_id": "test-request",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "method": "POST",
        "path": "/login",
        "client_ip": client_ip,
        "headers": {},
        "query_params": {
            "username": username,
        },
        "body": None,
    }


def test_single_failed_login_is_not_abuse():
    request = make_login_request()

    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=401,
    )

    assert findings == []


def test_four_failed_logins_are_not_abuse():
    request = make_login_request()

    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_fifth_failed_login_detects_auth_abuse():
    request = make_login_request()

    for _ in range(5):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "AUTH_ABUSE"
    assert finding["confidence"] == 0.95
    assert finding["risk_score"] == 80

    assert (
        finding["metadata"]["attempts"]
        == 5
    )

    assert (
        finding["metadata"]["username"]
        == "alice"
    )

    assert (
        finding["metadata"]["status_code"]
        == 401
    )


def test_successful_login_does_not_count_as_failure():
    request = make_login_request()

    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []

    # Successful authentication clears the history.
    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=200,
    )

    assert findings == []

    # Four more failures should still not trigger.
    for _ in range(4):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_successful_login_is_not_auth_abuse():
    request = make_login_request()

    findings = detect_auth_abuse(
        request_event=request,
        response_status_code=200,
    )

    assert findings == []


def test_non_401_response_does_not_count_as_failure():
    request = make_login_request()

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=500,
        )

    assert findings == []


def test_get_request_is_ignored():
    request = make_login_request()

    request["method"] = "GET"

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_non_login_endpoint_is_ignored():
    request = make_login_request()

    request["path"] = "/users/1"

    for _ in range(10):
        findings = detect_auth_abuse(
            request_event=request,
            response_status_code=401,
        )

    assert findings == []


def test_failures_are_tracked_per_username():
    alice_request = make_login_request(
        username="alice",
    )

    bob_request = make_login_request(
        username="bob",
    )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                alice_request,
                401,
            )
            == []
        )

    # Bob has his own failure counter.
    for _ in range(4):
        assert (
            detect_auth_abuse(
                bob_request,
                401,
            )
            == []
        )

    # Fifth Alice attempt triggers.
    findings = detect_auth_abuse(
        alice_request,
        401,
    )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["username"]
        == "alice"
    )


def test_failures_are_tracked_per_ip():
    attacker_one = make_login_request(
        username="alice",
        client_ip="10.0.0.1",
    )

    attacker_two = make_login_request(
        username="alice",
        client_ip="10.0.0.2",
    )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                attacker_one,
                401,
            )
            == []
        )

    for _ in range(4):
        assert (
            detect_auth_abuse(
                attacker_two,
                401,
            )
            == []
        )

    findings = detect_auth_abuse(
        attacker_one,
        401,
    )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["client_ip"]
        == "10.0.0.1"
    )


def test_json_body_username_is_detected():
    request = {
        "request_id": "test-request",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "method": "POST",
        "path": "/login",
        "client_ip": "127.0.0.1",
        "headers": {
            "content-type": "application/json",
        },
        "query_params": {},
        "body": (
            '{"username":"alice",'
            '"password":"wrong"}'
        ),
    }

    for _ in range(5):
        findings = detect_auth_abuse(
            request,
            401,
        )

    assert len(findings) == 1

    assert (
        findings[0]["metadata"]["username"]
        == "alice"
    )