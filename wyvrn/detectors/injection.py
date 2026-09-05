import re

from wyvrn.detectors.engine import make_finding


# ============================================================
# SQL INJECTION PATTERNS
# ============================================================

SQL_PATTERNS = [
    re.compile(r"\bunion\b\s+\bselect\b", re.IGNORECASE),
    re.compile(r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
    re.compile(r"\bdrop\b\s+\btable\b", re.IGNORECASE),
    re.compile(r"\binsert\b\s+\binto\b", re.IGNORECASE),
    re.compile(r"\bdelete\b\s+\bfrom\b", re.IGNORECASE),
    re.compile(r"--", re.IGNORECASE),
]


# ============================================================
# COMMAND INJECTION PATTERNS
# ============================================================

COMMAND_PATTERNS = [
    re.compile(r";\s*(cat|ls|pwd|whoami|id|uname)\b", re.IGNORECASE),
    re.compile(r"\|\s*(cat|ls|pwd|whoami|id|uname)\b", re.IGNORECASE),
    re.compile(r"\$\(\s*(cat|ls|pwd|whoami|id|uname)\b", re.IGNORECASE),
    re.compile(r"`\s*(cat|ls|pwd|whoami|id|uname)\b", re.IGNORECASE),
]


# ============================================================
# XSS PATTERNS
# ============================================================

XSS_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
]


# ============================================================
# VALUE EXTRACTION
# ============================================================

def extract_values(request_event):
    values = []

    query_params = request_event.get(
        "query_params",
        {},
    )

    for key, value in query_params.items():
        values.append(
            (
                f"query:{key}",
                str(value),
            )
        )

    body = request_event.get("body")

    if body is not None:
        values.append(
            (
                "body",
                str(body),
            )
        )

    path = request_event.get("path")

    if path:
        values.append(
            (
                "path",
                str(path),
            )
        )

    return values


# ============================================================
# INJECTION DETECTOR
# ============================================================

def detect_injection(request_event):
    findings = []

    values = extract_values(
        request_event
    )

    for location, value in values:

        # ----------------------------------------------------
        # SQL INJECTION
        # ----------------------------------------------------

        for pattern in SQL_PATTERNS:

            if pattern.search(value):
                findings.append(
                    make_finding(
                        detection="SQL_INJECTION",
                        confidence=0.92,
                        risk_score=90,
                        reason=(
                            "Request contains a pattern commonly "
                            "associated with SQL injection."
                        ),
                        metadata={
                            "location": location,
                            "pattern": pattern.pattern,
                        },
                    )
                )

                break

        # ----------------------------------------------------
        # COMMAND INJECTION
        # ----------------------------------------------------

        for pattern in COMMAND_PATTERNS:

            if pattern.search(value):
                findings.append(
                    make_finding(
                        detection="COMMAND_INJECTION",
                        confidence=0.94,
                        risk_score=95,
                        reason=(
                            "Request contains a pattern commonly "
                            "associated with command injection."
                        ),
                        metadata={
                            "location": location,
                            "pattern": pattern.pattern,
                        },
                    )
                )

                break

        # ----------------------------------------------------
        # XSS
        # ----------------------------------------------------

        for pattern in XSS_PATTERNS:

            if pattern.search(value):
                findings.append(
                    make_finding(
                        detection="XSS_PAYLOAD",
                        confidence=0.90,
                        risk_score=80,
                        reason=(
                            "Request contains a pattern commonly "
                            "associated with cross-site scripting."
                        ),
                        metadata={
                            "location": location,
                            "pattern": pattern.pattern,
                        },
                    )
                )

                break

    return findings