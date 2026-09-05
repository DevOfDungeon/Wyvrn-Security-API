from typing import Any, Set


# ============================================================
# ACTIVE WEBSOCKET CONNECTIONS
# ============================================================

connections: Set[Any] = set()


# ============================================================
# CONNECTION MANAGEMENT
# ============================================================

def add_connection(
    websocket: Any,
):
    """
    Register a dashboard WebSocket connection.
    """

    connections.add(
        websocket
    )


def remove_connection(
    websocket: Any,
):
    """
    Remove a dashboard WebSocket connection.
    """

    connections.discard(
        websocket
    )


# ============================================================
# BROADCAST
# ============================================================

async def broadcast_event(
    event,
):
    """
    Broadcast a security event to all connected dashboards.

    Dead connections are automatically removed.
    """

    disconnected = []

    for websocket in list(connections):

        try:

            await websocket.send_json(
                event
            )

        except Exception:

            disconnected.append(
                websocket
            )

    for websocket in disconnected:

        connections.discard(
            websocket
        )
