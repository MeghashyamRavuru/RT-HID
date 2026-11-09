from __future__ import annotations

import hashlib
import math


def instance_id(host_id: str, pid: int | None, created: object) -> str | None:
    """No PID-only fallback: unknown creation times cannot prove process identity."""
    if isinstance(created,bool):
        return None
    try:
        value = float(created)
    except (TypeError, ValueError, OverflowError):
        return None
    if pid is None or isinstance(pid, bool) or not isinstance(pid, int) or pid < 0 or not math.isfinite(value) or value <= 0:
        return None
    return hashlib.sha256(f"{host_id}|{pid}|{value!r}".encode()).hexdigest()


def event_instance(event) -> str | None:
    return instance_id(event.host_id, event.process_id,
                       event.metadata.get("create_time", event.evidence.get("create_time")))


def normalized_path(value: str) -> str:
    value = value.replace("\\", "/")
    return value.casefold() if len(value) > 1 and value[1] == ":" else value


def process_name(value: str | None) -> str:
    return (value or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
