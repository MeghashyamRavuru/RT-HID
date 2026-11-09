from __future__ import annotations

import platform
import xml.etree.ElementTree as ET
from typing import Any

from ..config import HostConfig
from ..models import CollectorStatus, HostEvent
from ..storage import HostDatabase
from .base import Collector, EventSink
from .linux import LinuxFileIntegrityCollector, LinuxNetworkCollector, LinuxProcessCollector


_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_IDS = (4624, 4625, 1102, 4697, 4720)
_QUERY_IDS = " or ".join(f"EventID={value}" for value in _IDS)


def parse_security_event(xml: str, host_id: str) -> tuple[int, HostEvent] | None:
    """Normalize selected local Security records without storing raw XML."""
    root = ET.fromstring(xml)
    record_id = int(root.findtext("e:System/e:EventRecordID", namespaces=_NS) or "0")
    event_id = int(root.findtext("e:System/e:EventID", namespaces=_NS) or "0")
    created = root.find("e:System/e:TimeCreated", _NS)
    timestamp = created.get("SystemTime") if created is not None else None
    fields = {item.get("Name"): item.text or "" for item in root.findall("e:EventData/e:Data", _NS) if item.get("Name")}
    common = {"timestamp": timestamp} if timestamp else {}
    stable_id = f"windows-security-{record_id}-{timestamp or 'unknown'}"
    evidence: dict[str, Any] = {"windows_event_id": event_id, "record_id": record_id}
    if event_id in (4624, 4625):
        logon_type = fields.get("LogonType", "")
        source_ip = fields.get("IpAddress")
        if source_ip in {"", "-", "::1", "127.0.0.1"}:
            source_ip = None
        event = HostEvent.create(
            host_id, "auth", "windows_security_log", event_id=stable_id,
            action="remote_login" if logon_type in {"3", "10"} else "local_login",
            outcome="failure" if event_id == 4625 else "success",
            username=fields.get("TargetUserName") or None, source_ip=source_ip,
            evidence={**evidence, "logon_type": logon_type, "workstation": fields.get("WorkstationName", "")},
            **common,
        )
    elif event_id in (1102, 4697, 4720):
        action = {1102: "audit_log_cleared", 4697: "service_installed", 4720: "account_created"}[event_id]
        event = HostEvent.create(
            host_id, "security_change", "windows_security_log", event_id=stable_id, action=action,
            outcome="observed", username=fields.get("SubjectUserName") or None,
            evidence={**evidence, "target_account": fields.get("TargetUserName", ""),
                      "service_name": fields.get("ServiceName", ""),
                      "service_file": fields.get("ServiceFileName", "")},
            **common,
        )
    else:
        return None
    return record_id, event


class WindowsEventLogCollector(Collector):
    collector_id = "windows_event_log"

    def __init__(self, host_id: str, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.database = database
        self.status = CollectorStatus(self.collector_id, "windows", False, True)
        try:
            import win32evtlog  # type: ignore
        except ImportError:
            win32evtlog = None
        self._win32evtlog = win32evtlog
        self._pending_cursor: str | None = None

    def run_once(self) -> list[HostEvent]:
        events = super().run_once()
        if self.status.available and self._pending_cursor is not None:
            self.database.set_checkpoint("windows:Security", self._pending_cursor)
            self._pending_cursor = None
        return events

    def collect_once(self) -> list[HostEvent]:
        if platform.system().lower() != "windows" or self._win32evtlog is None:
            raise RuntimeError("Windows Security log requires Windows and pywin32")
        api = self._win32evtlog
        checkpoint_id = "windows:Security"
        cursor = self.database.get_checkpoint(checkpoint_id)
        handle = api.EvtQuery("Security", api.EvtQueryChannelPath | api.EvtQueryReverseDirection, "*")
        try:
            latest = api.EvtNext(handle, 1, 0)
            if latest:
                try:
                    root = ET.fromstring(api.EvtRender(latest[0], api.EvtRenderEventXml))
                    latest_record_id = int(root.findtext("e:System/e:EventRecordID", namespaces=_NS) or "0")
                finally:
                    latest[0].close()
            else:
                latest_record_id = 0
        finally:
            handle.close()
        if cursor is None:
            self.database.set_checkpoint(checkpoint_id, str(latest_record_id))
            return []
        if latest_record_id < int(cursor):
            # Security log was cleared or replaced; resume from its new beginning.
            cursor = "0"

        query = f"*[System[(EventRecordID>{int(cursor)}) and ({_QUERY_IDS})]]"
        handle = api.EvtQuery("Security", api.EvtQueryChannelPath | api.EvtQueryForwardDirection, query)
        events: list[HostEvent] = []
        highest = int(cursor)
        try:
            for _ in range(16):  # bounded batch; remainder is read on the next poll
                batch = api.EvtNext(handle, 128, 0)
                if not batch:
                    break
                for item in batch:
                    try:
                        parsed = parse_security_event(api.EvtRender(item, api.EvtRenderEventXml), self.host_id)
                        if parsed:
                            record_id, event = parsed
                            highest = max(highest, record_id)
                            events.append(event)
                    finally:
                        item.close()
        finally:
            handle.close()
        self._pending_cursor = str(highest)
        return events


class WindowsProcessCollector(LinuxProcessCollector):
    collector_id = "windows_process"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "windows", False, True)


class WindowsNetworkCollector(LinuxNetworkCollector):
    collector_id = "windows_network"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "windows", False, True)


class WindowsFileIntegrityCollector(LinuxFileIntegrityCollector):
    collector_id = "windows_file_integrity"

    def __init__(self, host_id: str, config: HostConfig, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, config, database, sink)
        self.status = CollectorStatus(self.collector_id, "windows", False, True)


class WindowsSystemCollector(Collector):
    collector_id = "windows_system"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "windows", False, True)

    def collect_once(self) -> list[HostEvent]:
        import psutil

        return [HostEvent.create(
            self.host_id, "system_snapshot", "psutil", action="snapshot", outcome="observed",
            evidence={"platform": platform.platform(), "boot_time": psutil.boot_time(),
                      "cpu_percent": psutil.cpu_percent(interval=None),
                      "memory_percent": psutil.virtual_memory().percent},
        )]
