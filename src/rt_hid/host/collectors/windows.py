from __future__ import annotations

import platform
from datetime import datetime, timezone
import ipaddress
import xml.etree.ElementTree as ET
from typing import Any

from ..config import HostConfig
from ..models import CollectorStatus, HostEvent
from ..storage import HostDatabase
from .base import Collector, EventSink
from .linux import LinuxFileIntegrityCollector, LinuxNetworkCollector, LinuxProcessCollector
from .persistence import executable_from_command


_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_IDS = (4624, 4625, 1102, 4697, 4720, 4698, 4699, 4702, 4728, 4732, 4756)
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
    elif event_id in (4698,4699,4702):
        target = None
        task_xml = fields.get('TaskContentNew') or fields.get('TaskContent') or ''
        if task_xml and len(task_xml) <= 262144:
            try:
                task = ET.fromstring(task_xml)
                target = next((item.text for item in task.iter() if item.tag.rsplit('}',1)[-1] == 'Command'), None)
            except ET.ParseError:
                pass
        event = HostEvent.create(host_id,'persistence_change','windows_security_log',event_id=stable_id,
            action={4698:'create',4699:'delete',4702:'modify'}[event_id],outcome='observed',username=fields.get('SubjectUserName') or None,
            metadata={'kind':'scheduled_task','target_path':target},
            evidence={**evidence,'task_name':fields.get('TaskName','')},**common)
    elif event_id in (4728,4732,4756):
        event = HostEvent.create(host_id,'security_change','windows_security_log',event_id=stable_id,
            action='group_member_added',outcome='observed',username=fields.get('SubjectUserName') or None,
            evidence={**evidence,'target_account':fields.get('MemberName',''), 'target_sid':fields.get('MemberSid',''),
                      'group_name':fields.get('TargetUserName',''), 'group_sid':fields.get('TargetSid','')},**common)
    elif event_id in (1102, 4697, 4720):
        action = {1102: "audit_log_cleared", 4697: "service_installed", 4720: "account_created"}[event_id]
        event = HostEvent.create(
            host_id, "security_change", "windows_security_log", event_id=stable_id, action=action,
            outcome="observed", username=fields.get("SubjectUserName") or None,
            evidence={**evidence, "target_account": fields.get("TargetUserName", ""),
                      "service_name": fields.get("ServiceName", ""),
                      "target_sid": fields.get("TargetSid", ""),
                      "service_file": executable_from_command(fields.get("ServiceFileName", ""))},
            **common,
        )
    else:
        return None
    return record_id, event


class WindowsEventLogCollector(Collector):
    collector_id = "windows_event_log"
    channel = "Security"
    query_ids = _QUERY_IDS
    parser = staticmethod(parse_security_event)

    def __init__(self, host_id: str, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.database = database
        self.status = CollectorStatus(self.collector_id, "windows", False, True,
            capabilities={'channel':self.channel,'mechanism':'Windows Event Log'})
        try:
            import win32evtlog  # type: ignore
        except ImportError:
            win32evtlog = None
        self._win32evtlog = win32evtlog
        self._pending_cursor: str | None = None

    def run_once(self) -> list[HostEvent]:
        events = super().run_once()
        if self.status.available and self._pending_cursor is not None:
            self.database.set_checkpoint("windows:" + self.channel, self._pending_cursor)
            self._pending_cursor = None
        return events

    def collect_once(self) -> list[HostEvent]:
        if platform.system().lower() != "windows" or self._win32evtlog is None:
            raise RuntimeError("Windows Security log requires Windows and pywin32")
        api = self._win32evtlog
        checkpoint_id = "windows:" + self.channel
        cursor = self.database.get_checkpoint(checkpoint_id)
        def next_events(handle, count):
            try:
                return api.EvtNext(handle, count, 0)
            except Exception as error:
                if getattr(error, 'winerror', None) == 259:
                    return []
                raise
        handle = api.EvtQuery(self.channel, api.EvtQueryChannelPath | api.EvtQueryReverseDirection, "*")
        try:
            latest = next_events(handle, 1)
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

        query = f"*[System[(EventRecordID>{int(cursor)}) and ({self.query_ids})]]"
        handle = api.EvtQuery(self.channel, api.EvtQueryChannelPath | api.EvtQueryForwardDirection, query)
        events: list[HostEvent] = []
        highest = int(cursor)
        try:
            for _ in range(16):  # bounded batch; remainder is read on the next poll
                batch = next_events(handle, 128)
                if not batch:
                    break
                for item in batch:
                    try:
                        rendered = api.EvtRender(item, api.EvtRenderEventXml)
                        parsed = self.parser(rendered, self.host_id)
                        if parsed:
                            record_id, event = parsed
                            highest = max(highest, record_id)
                            events.append(event)
                        else:
                            skipped = ET.fromstring(rendered)
                            highest = max(highest,int(skipped.findtext('e:System/e:EventRecordID',namespaces=_NS) or 0))
                    finally:
                        item.close()
        finally:
            handle.close()
        self._pending_cursor = str(highest)
        return events


def parse_system_event(xml, host_id):
    root = ET.fromstring(xml)
    record = int(root.findtext('e:System/e:EventRecordID', namespaces=_NS) or 0)
    code = int(root.findtext('e:System/e:EventID', namespaces=_NS) or 0)
    if code not in (7040,7045):
        return None
    fields = {item.get('Name'):item.text or '' for item in root.findall('e:EventData/e:Data', _NS)}
    time_node = root.find('e:System/e:TimeCreated',_NS)
    timestamp = time_node.get('SystemTime') if time_node is not None else None
    return record,HostEvent.create(host_id,'persistence_change','windows_system_log',
        event_id=f'windows-system-{record}-{timestamp}',**({'timestamp':timestamp} if timestamp else {}),
        action='create' if code == 7045 else 'modify',outcome='observed',
        metadata={'kind':'service','target_path':executable_from_command(fields.get('ImagePath',''))},
        evidence={'windows_event_id':code,'service_name':fields.get('ServiceName') or fields.get('param1',''),
                  'previous_start_type':fields.get('param2'), 'current_start_type':fields.get('param3')})


class WindowsSystemLogCollector(WindowsEventLogCollector):
    collector_id = 'windows_system_log'
    channel = 'System'
    query_ids = 'EventID=7040 or EventID=7045'
    parser = staticmethod(parse_system_event)


def parse_sysmon_network_event(xml,host_id):
    root = ET.fromstring(xml)
    if root.findtext('e:System/e:EventID',namespaces=_NS) != '3':
        return None
    fields = {item.get('Name'):item.text or '' for item in root.findall('e:EventData/e:Data',_NS)}
    record = int(root.findtext('e:System/e:EventRecordID',namespaces=_NS) or 0)
    if fields.get('Initiated','').lower() != 'true':
        return None
    timestamp_node = root.find('e:System/e:TimeCreated',_NS)
    timestamp = timestamp_node.get('SystemTime') if timestamp_node is not None else None
    pid = int(fields['ProcessId'])
    created = None
    # Never assign a late log record to a replacement process with the same PID.
    try:
        import psutil
        process = psutil.Process(pid)
        candidate = process.create_time()
        observed = datetime.fromisoformat(timestamp.replace('Z','+00:00')) if timestamp else datetime.now(timezone.utc)
        if candidate <= observed.timestamp() and process.exe().casefold() == fields.get('Image','').casefold():
            created = candidate
    except (psutil.Error, OSError, ValueError):
        pass
    return record,HostEvent.create(host_id,'network_connection','windows_sysmon',
        event_id=f'windows-sysmon-{record}-{timestamp}',**({'timestamp':timestamp} if timestamp else {}),
        process_id=pid,process_name=fields.get('Image','').replace('\\','/').rsplit('/',1)[-1],
        executable_path=fields.get('Image') or None,username=fields.get('User') or None,
        source_ip=str(ipaddress.ip_address(fields['SourceIp'])),destination_ip=str(ipaddress.ip_address(fields['DestinationIp'])),
        destination_port=int(fields['DestinationPort']),protocol=fields.get('Protocol','').upper(),action='connect',outcome='observed',
        metadata={'create_time':created,'source_port':int(fields['SourcePort']),'direction':'outbound',
            'direction_basis':'Sysmon Event ID 3 Initiated=true','process_guid':fields.get('ProcessGuid'),
            'destination_domain':fields.get('DestinationHostname') or None},evidence={'windows_event_id':3,'record_id':record})


class WindowsSysmonCollector(WindowsEventLogCollector):
    collector_id = 'windows_sysmon'
    channel = 'Microsoft-Windows-Sysmon/Operational'
    query_ids = 'EventID=3'
    parser = staticmethod(parse_sysmon_network_event)


class WindowsProcessCollector(LinuxProcessCollector):
    collector_id = "windows_process"

    def __init__(self, host_id: str, sink: EventSink, config: HostConfig | None = None) -> None:
        super().__init__(host_id, sink, config)
        self.status = CollectorStatus(self.collector_id, "windows", False, True)


class WindowsNetworkCollector(LinuxNetworkCollector):
    collector_id = "windows_network"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        from dataclasses import replace
        self.status = replace(self.status,platform='windows')


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
