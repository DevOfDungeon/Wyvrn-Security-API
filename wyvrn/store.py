from typing import Any, Dict, List
from collections import deque


MAX_EVENTS = 1000

EVENTS = deque(maxlen=MAX_EVENTS)


def store_event(event: Dict[str, Any]) -> None:
    """
    Store a security event in memory.
    """

    EVENTS.appendleft(event)


def get_events(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Return the newest security events.
    """

    limit = min(limit, MAX_EVENTS)

    return list(EVENTS)[:limit]


def get_event_count() -> int:
    """
    Return total events currently stored.
    """

    return len(EVENTS)


def clear_events() -> None:
    """
    Clear all stored events.
    """

    EVENTS.clear()
