from pydantic import BaseModel
from typing import Any, Dict, Optional


class RequestEvent(BaseModel):
    request_id: str
    timestamp: str

    method: str
    path: str

    client_ip: Optional[str] = None

    headers: Dict[str, Any] = {}
    query_params: Dict[str, Any] = {}
    body: Any = None


class ResponseEvent(BaseModel):
    status_code: int
    response_size: int
    latency_ms: float


class SecurityEvent(BaseModel):
    request: RequestEvent
    response: Optional[ResponseEvent] = None

    risk_score: int = 0
    action: str = "ALLOW"
﻿
