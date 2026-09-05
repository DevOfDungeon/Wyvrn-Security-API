from typing import Any, Dict, Set

#============================================================
#ACTIVE WEBSOCKET CLIENTS
#============================================================
connections: Set[Any] = set()


#============================================================
#CONNECTION MANAGEMENT
#============================================================
def add_connection(
    websocket: Any,
):

    connections.add(
        websocket
    )


def remove_connection(
    websocket: Any,
):

    connections.discard(
        websocket
    )


#============================================================
#BROADCAST
#============================================================
async def broadcast_event(
    event: Dict[str, Any],
):

    disconnected = []

    for websocket in connections:

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
