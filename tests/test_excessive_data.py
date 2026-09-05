from wyvrn.detectors.excessive_data import (
    detect_excessive_data,
)


def test_clean_user_response_is_not_flagged():

    response = {
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com",
    }

    findings = detect_excessive_data(
        "/users/1",
        response,
    )

    assert findings == []


def test_excessive_user_fields_are_detected():

    response = {
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
        "phone": "+91-9000000001",
        "password_hash": "fake_hash_alice",
    }

    findings = detect_excessive_data(
        "/users/1",
        response,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding["detection"]
        == "EXCESSIVE_DATA_EXPOSURE"
    )

    assert "role" in finding["metadata"]["unexpected_fields"]
    assert "phone" in finding["metadata"]["unexpected_fields"]
    assert (
        "password_hash"
        in finding["metadata"]["unexpected_fields"]
    )


def test_unknown_endpoint_is_ignored():

    response = {
        "id": 1,
        "name": "Alice",
    }

    findings = detect_excessive_data(
        "/products",
        response,
    )

    assert findings == []


def test_list_response_is_ignored_for_now():

    response = [
        {
            "id": 1,
            "name": "Alice",
        },
        {
            "id": 2,
            "name": "Bob",
        },
    ]

    findings = detect_excessive_data(
        "/users/1",
        response,
    )

    assert findings == []