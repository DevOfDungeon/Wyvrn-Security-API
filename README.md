# WYVRN Security API

> Runtime API Security, Threat Detection & Automated Threat Control

WYVRN is a runtime API security layer that sits between clients and an API to detect, assess, and respond to security threats in real time.

Instead of relying only on static vulnerability detection, WYVRN analyzes API requests and responses, calculates contextual risk, applies automated security policies, correlates related events, and streams security activity to a live dashboard.

---

## What WYVRN Detects

WYVRN currently detects:

- SQL Injection
- BOLA / IDOR
- Authentication Abuse
- Rate Abuse
- Sensitive Data Exposure
- Excessive Data Exposure
- Behavioral Anomalies

Security decisions are based on contextual risk and can result in:
ALLOW
MONITOR
RATE LIMIT
BLOCK

## Architecture

```text
                    CLIENT
                       │
                       ▼
              ┌─────────────────┐
              │ WYVRN MIDDLEWARE│
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │    DETECTORS    │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   RISK ENGINE   │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  POLICY ENGINE  │
              └────────┬────────┘
                       │
              ALLOW / MONITOR /
             RATE_LIMIT / BLOCK
                       │
                       ▼
                ┌─────────────┐
                │  TARGET API │
                └──────┬──────┘
                       │
                       ▼
                   RESPONSE
                       │
                       ▼
              RESPONSE DETECTORS
                       │
                       ▼
                RISK + CORRELATION
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
         EVENT STORE  CAMPAIGN  WEBSOCKET
                                  │
                                  ▼
                              DASHBOARD
```

## Project Structure

```text
Trojan-Horses/
│
├── target_api/
│   └── main.py
│
├── wyvrn/
│   ├── main.py
│   ├── middleware.py
│   ├── risk.py
│   ├── policy.py
│   ├── events.py
│   ├── store.py
│   ├── ws.py
│   ├── correlation.py
│   │
│   └── detectors/
│       ├── auth.py
│       ├── bola.py
│       ├── injection.py
│       ├── rate_limit.py
│       ├── sensitive_data.py
│       ├── excessive_data.py
│       └── anomaly.py
│
├── dashboard/
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── tests/
├── requirements.txt
├── pytest.ini
├── README.md
└── LICENSE
```
