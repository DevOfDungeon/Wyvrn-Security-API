from wyvrn.detectors.sensitive_data import (
    detect_sensitive_data,
)


# ============================================================
# PASSWORD HASH
# ============================================================

def test_detects_password_hash():

    response = {
        "id": 1,
        "name": "Alice",
        "password_hash": "fake_hash_alice",
    }

    findings = detect_sensitive_data(
        response
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SENSITIVE_DATA_EXPOSURE" in detections


# ============================================================
# API TOKEN
# ============================================================

def test_detects_access_token():

    response = {
        "id": 1,
        "access_token": "secret-token-123",
    }

    findings = detect_sensitive_data(
        response
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SENSITIVE_DATA_EXPOSURE" in detections


# ============================================================
# NESTED DATA
# ============================================================

def test_detects_nested_sensitive_field():

    response = {
        "user": {
            "profile": {
                "password": "secret"
            }
        }
    }

    findings = detect_sensitive_data(
        response
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SENSITIVE_DATA_EXPOSURE" in detections


# ============================================================
# LIST DATA
# ============================================================

def test_detects_sensitive_fields_in_list():

    response = {
        "users": [
            {
                "id": 1,
                "password_hash": "hash1",
            },
            {
                "id": 2,
                "password_hash": "hash2",
            },
        ]
    }

    findings = detect_sensitive_data(
        response
    )

    sensitive_findings = [
        finding
        for finding in findings
        if finding["detection"]
        == "SENSITIVE_DATA_EXPOSURE"
    ]

    assert len(sensitive_findings) == 2


# ============================================================
# CLEAN RESPONSE
# ============================================================

def test_clean_response_has_no_sensitive_data():

    response = {
        "id": 1,
        "name": "Alice",
        "role": "user",
    }

    findings = detect_sensitive_data(
        response
    )

    assert findings == []


# ============================================================
# EMAIL DETECTION
# ============================================================

def test_detects_email_pattern():

    response = {
        "message": "Contact alice@example.com"
    }

    findings = detect_sensitive_data(
        response
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SENSITIVE_DATA_PATTERN" in detections
