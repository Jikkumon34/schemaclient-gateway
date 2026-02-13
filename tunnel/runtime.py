from __future__ import annotations

import threading


_LOCK = threading.Lock()
_RESPONSE_WAITERS: dict[str, threading.Event] = {}


def register_response_waiter(request_id: str) -> threading.Event:
    event = threading.Event()
    with _LOCK:
        _RESPONSE_WAITERS[request_id] = event
    return event


def notify_response_waiter(request_id: str) -> None:
    with _LOCK:
        event = _RESPONSE_WAITERS.get(request_id)
    if event is not None:
        event.set()


def unregister_response_waiter(request_id: str) -> None:
    with _LOCK:
        _RESPONSE_WAITERS.pop(request_id, None)
