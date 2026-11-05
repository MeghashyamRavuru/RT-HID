from __future__ import annotations

import hashlib
import platform
import re
import stat
from pathlib import Path
from typing import Any

from ..config import HostConfig
from ..models import CollectorStatus, HostEvent
from ..storage import HostDatabase
from .base import Collector, EventSink


class LinuxAuthCollector(Collector):
    collector_id = "linux_auth"

    def __init__(self, host_id: str, config: HostConfig, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)
        self.paths = config.auth_log_paths
        self.database = database
        self._active_path: Path | None = None

    def collect_once(self) -> list[HostEvent]:
        path = next((candidate for candidate in self.paths if candidate.is_file()), None)
        if path is None:
            raise RuntimeError("auth log unavailable; check path and read permissions")
        self._active_path = path
        checkpoint_id = f"auth:{path}"
        offset_value = self.database.get_checkpoint(checkpoint_id)
        offset = int(offset_value) if offset_value and offset_value.isdigit() else path.stat().st_size
        size = path.stat().st_size
        if offset > size:
            offset = 0
        events: list[HostEvent] = []
        with path.open("r", encoding="utf-8", errors="replace") as file:
            file.seek(offset)
            for line in file:
                event = self._parse_line(line)
                if event:
                    events.append(event)
            self.database.set_checkpoint(checkpoint_id, str(file.tell()))
        return events

    def _parse_line(self, line: str) -> HostEvent | None:
        lower = line.lower()
        failed = "failed password" in lower or "authentication failure" in lower or "invalid user" in lower
        success = "accepted password" in lower or "accepted publickey" in lower
        sudo_failure = "sudo" in lower and "incorrect password" in lower
        if not (failed or success or sudo_failure):
            return None
        action = "sudo" if sudo_failure else "ssh_login"
        outcome = "failure" if failed or sudo_failure else "success"
        source_ip = None
        match = re.search(r"from\s+(\S+)", line, re.IGNORECASE)
        if match:
            source_ip = match.group(1).rstrip(".")
        user_match = re.search(r"(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9._-]+)", line, re.IGNORECASE)
        return HostEvent.create(
            self.host_id,
            "auth",
            "linux_auth_log",
            severity="informational",
            username=user_match.group(1) if user_match else None,
            source_ip=source_ip,
            action=action,
            outcome=outcome,
            evidence={"line": _redact_log_line(line)},
        )


class LinuxProcessCollector(Collector):
    collector_id = "linux_process"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)
        self._known: dict[int, float] = {}
        self._initialized = False

    def collect_once(self) -> list[HostEvent]:
        import psutil

        current: dict[int, float] = {}
        events: list[HostEvent] = []
        for process in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "create_time"]):
            try:
                info = process.info
                pid = int(info["pid"])
                created = float(info.get("create_time") or 0.0)
                current[pid] = created
                if self._initialized and self._known.get(pid) != created:
                    events.append(HostEvent.create(
                        self.host_id,
                        "process_start",
                        "psutil",
                        process_id=pid,
                        parent_process_id=info.get("ppid"),
                        process_name=info.get("name"),
                        executable_path=info.get("exe"),
                        username=info.get("username"),
                        action="start",
                        outcome="observed",
                        evidence={"create_time": created},
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        if self._initialized:
            for pid in set(self._known) - set(current):
                events.append(HostEvent.create(self.host_id, "process_stop", "psutil", process_id=pid, action="stop", outcome="observed"))
        self._known = current
        self._initialized = True
        return events


class LinuxNetworkCollector(Collector):
    collector_id = "linux_network"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)
        self._known: set[tuple[Any, ...]] = set()
        self._initialized = False

    def collect_once(self) -> list[HostEvent]:
        import psutil

        current: set[tuple[Any, ...]] = set()
        events: list[HostEvent] = []
        for connection in psutil.net_connections(kind="inet"):
            try:
                if not connection.laddr:
                    continue
                address = connection.laddr
                ip = address.ip
                port = int(address.port)
                protocol = "TCP" if connection.type == 1 else "UDP"
                identity = (protocol, ip, port, connection.pid or 0, connection.status)
                current.add(identity)
                if self._initialized and connection.status == "LISTEN" and identity not in self._known:
                    events.append(HostEvent.create(
                        self.host_id,
                        "network_listen",
                        "psutil",
                        process_id=connection.pid,
                        destination_ip=ip,
                        destination_port=port,
                        protocol=protocol,
                        process_name=_process_name(connection.pid),
                        action="listen",
                        outcome="observed",
                        evidence={"status": connection.status},
                    ))
            except (AttributeError, OSError, ValueError):
                continue
        self._known = current
        self._initialized = True
        return events


class LinuxFileIntegrityCollector(Collector):
    collector_id = "linux_file_integrity"

    def __init__(self, host_id: str, config: HostConfig, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)
        self.paths = config.monitored_paths
        self.database = database

    def collect_once(self) -> list[HostEvent]:
        events: list[HostEvent] = []
        self.status = CollectorStatus(self.collector_id, self.status.platform, True, True)
        for path in self.paths:
            try:
                if not path.exists():
                    if self.database.get_baseline(str(path)) is not None:
                        events.append(HostEvent.create(
                            self.host_id, "file_change", self.collector_id,
                            file_path=str(path), action="delete", outcome="observed",
                        ))
                        self.database.delete_baseline(str(path))
                    continue
                if path.is_dir():
                    continue
                digest = _sha256(path)
                metadata = path.stat()
                previous = self.database.get_baseline(str(path))
                mode = stat.filemode(metadata.st_mode)
                if previous is None:
                    self.database.save_baseline(str(path), digest, mode, metadata.st_size)
                    continue
                actions: list[str] = []
                if previous["sha256"] != digest:
                    actions.append("modify")
                if previous["mode"] != mode:
                    actions.append("permission_change")
                if actions:
                    events.append(HostEvent.create(
                        self.host_id,
                        "file_change",
                        "linux_file_integrity",
                        file_path=str(path),
                        action=actions[0],
                        outcome="observed",
                        evidence={"sha256": digest, "previous_sha256": previous["sha256"], "actions": actions},
                    ))
                self.database.save_baseline(str(path), digest, mode, metadata.st_size)
            except (OSError, PermissionError) as error:
                self.status = CollectorStatus(self.collector_id, "linux", False, True, last_error=str(error), detail="path unavailable")
        return events


class LinuxSystemCollector(Collector):
    collector_id = "linux_system"

    def __init__(self, host_id: str, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)

    def collect_once(self) -> list[HostEvent]:
        import psutil

        return [HostEvent.create(
            self.host_id,
            "system_snapshot",
            "psutil",
            action="snapshot",
            outcome="observed",
            evidence={
                "platform": platform.platform(),
                "boot_time": psutil.boot_time(),
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "hostname": platform.node(),
            },
        )]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _process_name(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        import psutil
    except ImportError:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.Error, OSError):
        return None


def _redact_log_line(line: str) -> str:
    return re.sub(r"(password|passwd|token|secret)=?\S*", r"\1=<redacted>", line, flags=re.IGNORECASE).strip()
