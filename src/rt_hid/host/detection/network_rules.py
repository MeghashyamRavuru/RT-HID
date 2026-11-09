from __future__ import annotations

import ipaddress
from collections import deque
from datetime import datetime, timedelta

from ..identity import event_instance, process_name
from ..models import Detection
from .behavior import INTERPRETERS
from .registry import RULES


def evaluate_connections(engine, event):
    try:
        ip = ipaddress.ip_address(event.destination_ip)
    except (ValueError, TypeError):
        return []
    if ip.is_loopback or any(ip in ipaddress.ip_network(item, strict=False) for item in engine.config.network_destination_allowlist):
        return []
    if event.destination_port not in engine.config.network_unusual_ports:
        return []
    keys = ["HIDS-NET-002"]
    if process_name(event.process_name) in INTERPRETERS:
        keys.append("HIDS-NET-004")
    identity = (event.host_id, str(ip), event.process_name or "unknown")
    history = engine._recent_connections.setdefault(identity, deque(maxlen=100))
    if len(engine._recent_connections) > 2048:
        engine._recent_connections.pop(next(iter(engine._recent_connections)))
    now = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    cutoff = now - timedelta(seconds=engine.config.correlation_window_seconds)
    while history and datetime.fromisoformat(history[0].timestamp.replace("Z", "+00:00")) < cutoff:
        history.popleft()
    history.append(event)
    threshold = engine.registry.settings.get("HIDS-NET-003", {}).get("threshold", engine.config.network_repeat_threshold)
    if len(history) >= threshold:
        keys.append("HIDS-NET-003")
    results = []
    for key in keys:
        spec = RULES[key]
        results.append(Detection.create(rule_id=key, rule_name=spec.name, category="network_behavior", tactic=spec.tactic,
            technique_id=spec.technique_id, severity=spec.severity, confidence=spec.confidence, timestamp=event.timestamp,
            event_ids=tuple(item.event_id for item in history) if key == "HIDS-NET-003" else (event.event_id,),
            reason=f"{spec.name}: observed remote port {event.destination_port}; direction {event.metadata.get('direction', 'unknown')}",
            evidence={"destination_ip": str(ip), "port": event.destination_port, "process_name": event.process_name,
                      "process_identity": event_instance(event), "direction": event.metadata.get('direction'), "observations": len(history)},
            investigation="Check process ancestry and whether this destination is approved. A port number alone does not identify malicious traffic.", host_id=event.host_id))
    return results
