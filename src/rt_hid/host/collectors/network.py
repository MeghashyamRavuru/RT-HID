"""Portable socket snapshots. Direction on established sockets is inferred, not proven."""
from __future__ import annotations

from dataclasses import replace

from ..identity import instance_id
from ..models import CollectorStatus, HostEvent
from .base import Collector


class PortableNetworkCollector(Collector):
    def __init__(self, host_id, sink, config=None):
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True, capabilities={
            'mechanism':'psutil polling','outbound_direction':'inferred except SYN_SENT','short_lived_connections':'may be missed'})
        self._known = set()
        self._initialized = False
        self._listener_ports = set()

    def collect_once(self):
        import psutil
        current, events, errors = set(), [], 0
        sockets = psutil.net_connections(kind="inet")
        limited = sockets[:20000]
        listeners = {(item.pid, item.laddr.port) for item in limited if item.laddr and item.status == "LISTEN"}
        self._listener_ports.update(listeners)
        if len(self._listener_ports) > 10000:
            self._listener_ports = listeners
        owners = {}
        inaccessible = 0
        for item in limited:
            try:
                if not item.laddr:
                    continue
                protocol = "TCP" if int(item.type) == 1 else "UDP"
                remote = (item.raddr.ip, int(item.raddr.port)) if item.raddr else (None, None)
                identity = (item.pid, protocol, item.laddr.ip, item.laddr.port, *remote)
                # A snapshot can contain both inbound accepted sockets and outbound sockets.
                listener = item.status == "LISTEN"
                outbound = bool(item.raddr) and item.status in {"ESTABLISHED", "SYN_SENT", "NONE"} and (item.pid, item.laddr.port) not in self._listener_ports
                if not listener and not outbound:
                    continue
                if item.pid not in owners:
                    name, username, created = None, None, None
                    if item.pid:
                        try:
                            process = psutil.Process(item.pid)
                            created = process.create_time()
                            name, username = process.name(), process.username()
                        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
                            inaccessible += 1
                        except (OSError, ValueError):
                            errors += 1
                    owners[item.pid] = (name, username, created)
                name, username, created = owners[item.pid]
                key = (*identity, instance_id(self.host_id, item.pid, created))
                current.add(key)
                if self._initialized and key not in self._known:
                    metadata = {"create_time": created, "source_port": int(item.laddr.port),
                        "process_instance_id": instance_id(self.host_id, item.pid, created), "connection_state": item.status,
                        "direction": "listener" if listener else "outbound" if item.status == "SYN_SENT" else "inferred_outbound",
                        "direction_basis": "socket state and absence of an observed local listener; polling cannot establish every socket's initiator"}
                    events.append(HostEvent.create(self.host_id, "network_listen" if listener else "network_connection", "psutil",
                        process_id=item.pid, process_name=name, username=username, source_ip=item.laddr.ip,
                        destination_ip=item.laddr.ip if listener else remote[0],
                        destination_port=int(item.laddr.port) if listener else remote[1], protocol=protocol,
                        action="listen" if listener else "connect", outcome="observed", metadata=metadata,
                        evidence={"status": item.status}))
            except (AttributeError, TypeError, ValueError, OSError):
                errors += 1
        if len(sockets) > 20000:
            errors += 1
        self._known, self._initialized = current, True
        self.status = replace(self.status, available=True, inaccessible_processes=inaccessible,
            collection_errors=errors, last_error="socket_snapshot: CollectionLimit" if len(sockets) > 20000 else "socket_inspection: ValueError" if errors else None,
            detail="portable polling; outbound direction inferred; short-lived sockets may be missed")
        return events
