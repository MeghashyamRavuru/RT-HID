from __future__ import annotations

import hashlib
import math
import platform
import re
import stat
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import HostConfig
from ..models import CollectorStatus, HostEvent
from ..storage import HostDatabase
from .base import Collector, EventSink
from .network import PortableNetworkCollector
from ..auth_telemetry import parse_linux_auth_line, redact_auth_line as _redact_log_line


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
        return parse_linux_auth_line(line, self.host_id)


class LinuxProcessCollector(Collector):
    collector_id = "linux_process"

    def __init__(self, host_id: str, sink: EventSink, config: HostConfig | None = None) -> None:
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, "linux", False, True)
        self.config = config or HostConfig(host_id=host_id)
        self._known: dict[tuple[int, float], dict[str, Any]] = {}
        self._hash_cache: OrderedDict[tuple[str, int, int], str] = OrderedDict()
        self._initialized = False

    def collect_once(self) -> list[HostEvent]:
        import psutil

        current: dict[tuple[int, float], dict[str, Any]] = {}
        events: list[HostEvent] = []
        inspected = identified = inaccessible = errors = 0
        error_summary: str | None = None
        unexpected_error = False
        hashes_remaining = self.config.process_hashes_per_scan

        def report(stage: str, exc: Exception) -> None:
            nonlocal errors, error_summary, unexpected_error
            errors += 1
            error_summary = f"{stage}: {_safe_process_error_type(exc)}"
            if not isinstance(exc, (psutil.AccessDenied, psutil.NoSuchProcess,
                                    psutil.ZombieProcess, OSError, ValueError,
                                    TypeError, OverflowError, KeyError)):
                unexpected_error = True

        try:
            clear_cache = getattr(psutil.process_iter,'cache_clear',None)
            if clear_cache is not None:
                clear_cache()
            process_iterator = iter(psutil.process_iter(
                ["pid", "create_time"]
            ))
        except Exception as exc:
            report("process_enumeration", exc)
            self.status = replace(self.status, available=False, processes_inspected=0,
                                  inaccessible_processes=0, collection_errors=errors,
                                  last_error=error_summary, detail="process enumeration failed")
            return []
        while True:
            try:
                process = next(process_iterator)
            except StopIteration:
                break
            except Exception as exc:
                report("process_enumeration", exc)
                self.status = replace(self.status, available=False, processes_inspected=inspected,
                                      inaccessible_processes=inaccessible, collection_errors=errors,
                                      last_error=error_summary, detail="process enumeration failed")
                return []
            inspected += 1
            identity: tuple[int, float] | None = None
            stage = "process_info"
            try:
                inaccessible_process = False
                info = process.info
                stage = "pid"
                pid = int(info["pid"])
                if pid < 0:
                    raise ValueError("invalid PID")
                stage = "creation_time"
                created_value = info.get("create_time")
                if created_value is None:
                    created_value = process.create_time()
                if created_value is None:
                    raise ValueError("missing process creation time")
                created = float(created_value)
                if self.status.platform == "windows" and pid in (0, 4) and created == 0.0:
                    # Windows Idle/System can report a sentinel zero creation time.
                    # They have no reliable (PID, creation time) identity to track.
                    continue
                if not math.isfinite(created) or created <= 0:
                    raise ValueError("invalid process creation time")
                created_at = datetime.fromtimestamp(created, timezone.utc).isoformat()
                identified += 1
                identity = (pid, created)
                if identity in current:
                    continue
                current[identity] = {"created_at": None}
                if not self._initialized or identity in self._known:
                    if identity in self._known:
                        current[identity] = self._known[identity]
                    continue

                # Expensive optional fields are needed only for a newly observed instance.
                # Fresh iteration objects above keep creation times reliable across PID reuse.
                stage = 'process_metadata'
                if hasattr(process,'as_dict'):
                    info = {**info,**process.as_dict(attrs=['ppid','name','exe','username'],ad_value=None)}
                ppid = None
                parent_name = None
                parent_created = None
                stage = "parent_pid"
                if info.get("ppid") is not None:
                    try:
                        ppid = int(info["ppid"])
                        if ppid < 0:
                            raise ValueError("invalid parent PID")
                    except (TypeError, ValueError, OverflowError) as exc:
                        report("parent_pid", exc)
                        ppid = None
                if ppid is not None:
                    stage = "parent_name"
                    try:
                        parent_process = psutil.Process(ppid)
                        parent_name = parent_process.name()
                        if hasattr(parent_process, "create_time"):
                            parent_created = float(parent_process.create_time())
                            if not math.isfinite(parent_created) or not 0 < parent_created <= created:
                                parent_created = None
                    except (psutil.AccessDenied, psutil.NoSuchProcess,
                            psutil.ZombieProcess, OSError, ValueError) as exc:
                        report("parent_name", exc)
                command_line = None
                cwd = None
                stage = "command_line"
                try:
                    command_line = _redact_command_line(process.cmdline(), self.config.process_command_line_max_length)
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    raise
                except (psutil.AccessDenied, OSError, ValueError) as exc:
                    inaccessible_process = True
                    report(stage, exc)
                stage = "working_directory"
                try:
                    cwd = process.cwd()
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    raise
                except (psutil.AccessDenied, OSError, ValueError) as exc:
                    inaccessible_process = True
                    report(stage, exc)
                if inaccessible_process:
                    inaccessible += 1

                stage = "process_metadata"
                executable = info.get("exe")
                digest = None
                hash_error = None
                stage = "executable_hash"
                if executable and self.config.executable_hashing_enabled:
                    digest, hash_error, used_budget = self._hash_executable(str(executable), hashes_remaining)
                    hashes_remaining -= used_budget
                    if hash_error and hash_error != "scan budget reached":
                        errors += 1
                        error_summary = f"executable_hash: {hash_error}"
                metadata = {"create_time": created,
                            "created_at": created_at,
                            "parent_name": parent_name, "command_line": command_line,
                            "parent_create_time": parent_created,
                            "working_directory": cwd, "executable_sha256": digest,
                            "executable_hash_error": hash_error}
                current[identity] = {"created_at": created_at}
                stage = "event_build"
                events.append(HostEvent.create(
                    self.host_id, "process_start", "psutil", process_id=pid,
                    parent_process_id=ppid, process_name=info.get("name"),
                    executable_path=executable, username=info.get("username"),
                    action="start", outcome="observed", metadata=metadata,
                    evidence={"create_time": created},
                ))
            except Exception as exc:  # isolate unexpected per-process failures as well
                inaccessible += 1
                report(stage, exc)
                if identity is not None and identity not in self._known:
                    current.pop(identity, None)
                # Preserve known instances if this PID cannot be inspected this scan.
                pid = getattr(process, "pid", None)
                for identity, metadata in self._known.items():
                    if identity[0] == pid:
                        current[identity] = metadata
                continue
        if self._initialized:
            current_pids = {pid for pid, _created in current}
            for (pid, created), metadata in self._known.items():
                if (pid, created) not in current:
                    if pid not in current_pids:
                        try:
                            if psutil.pid_exists(pid):
                                current[(pid, created)] = metadata
                                continue
                        except Exception as exc:
                            report("process_liveness", exc)
                            current[(pid, created)] = metadata
                            continue
                    try:
                        events.append(HostEvent.create(self.host_id, "process_stop", "psutil",
                                                       process_id=pid, action="stop", outcome="observed",
                                                       metadata={"create_time": created,
                                                                 "created_at": metadata.get("created_at")}))
                    except Exception as exc:
                        report("stop_event", exc)
                        current[(pid, created)] = metadata
        self._known = current
        self._initialized = True
        functional = (not inspected or identified > 0) and not unexpected_error
        self.status = replace(self.status, available=functional, processes_inspected=inspected,
                              inaccessible_processes=inaccessible, collection_errors=errors,
                              last_error=error_summary,
                              detail=f"{inspected} inspected, {inaccessible} inaccessible, {len(events)} events")
        return events

    def _hash_executable(self, executable: str, remaining: int) -> tuple[str | None, str | None, int]:
        try:
            path = Path(executable)
            before = path.stat()
            if not path.is_file():
                return None, "not a regular file", 0
            if before.st_size > self.config.executable_hash_max_bytes:
                return None, "file exceeds size limit", 0
            key = (str(path), before.st_size, before.st_mtime_ns)
            if key in self._hash_cache:
                self._hash_cache.move_to_end(key)
                return self._hash_cache[key], None, 0
            if remaining <= 0:
                return None, "scan budget reached", 0
            digest = hashlib.sha256()
            bytes_read = 0
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    bytes_read += len(chunk)
                    if bytes_read > self.config.executable_hash_max_bytes:
                        return None, "file exceeds size limit", 1
                    digest.update(chunk)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                return None, "file changed during hashing", 1
            result = digest.hexdigest()
            self._hash_cache[key] = result
            if len(self._hash_cache) > 256:
                self._hash_cache.popitem(last=False)
            return result, None, 1
        except (OSError, ValueError) as exc:
            return None, _safe_process_error_type(exc), 1


_SAFE_PROCESS_ERROR_TYPES = {
    "AccessDenied", "NoSuchProcess", "ZombieProcess", "ValueError", "TypeError",
    "OverflowError", "KeyError", "OSError", "FileNotFoundError", "PermissionError",
    "RuntimeError", "AttributeError",
}


def _safe_process_error_type(exc: Exception) -> str:
    name = type(exc).__name__
    return name if name in _SAFE_PROCESS_ERROR_TYPES else "UnexpectedError"


_SECRET_ARGUMENT = re.compile(r"(?i)(?<![\w])(password|passwd|token|api[_-]?key|secret|client[_-]?secret|access[_-]?key)([=:])[^\s]+")
_SECRET_FLAG = re.compile(r"(?i)^-{1,2}(password|passwd|token|api[_-]?key|secret|client[_-]?secret|access[_-]?key)$")


def _redact_command_line(arguments: list[str] | None, max_length: int) -> list[str] | None:
    if arguments is None:
        return None
    result: list[str] = []
    length = 0
    hide_next = False
    for argument in arguments:
        raw = str(argument)
        raw_truncated = len(raw) > max_length
        limited = raw[:max_length]
        value = "<redacted>" if hide_next else _SECRET_ARGUMENT.sub(r"\1\2<redacted>", limited)
        hide_next = bool(_SECRET_FLAG.match(limited))
        if raw_truncated or length + len(value) > max_length:
            if length + len("<truncated>") <= max_length:
                result.append("<truncated>")
            break
        result.append(value)
        length += len(value)
    return result


class LinuxNetworkCollector(PortableNetworkCollector):
    collector_id = "linux_network"

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
                self.status = CollectorStatus(self.collector_id, self.status.platform, False, True,
                    last_error='file_snapshot: '+type(error).__name__, detail="path unavailable")
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
