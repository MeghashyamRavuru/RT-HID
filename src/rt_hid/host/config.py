from __future__ import annotations

import json
import os
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def default_monitored_paths() -> list[Path]:
    if os.name == "nt":
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        return [root / "System32" / "drivers" / "etc" / "hosts"]
    return [Path("/etc/passwd"), Path("/etc/shadow"), Path("/etc/sudoers"), Path("/etc/ssh/sshd_config")]


@dataclass
class HostConfig:
    host_id: str
    database_path: Path = Path("data/host_ids.sqlite3")
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000
    auth_log_paths: list[Path] = field(default_factory=lambda: [Path("/var/log/auth.log"), Path("/var/log/secure"),
                                                               Path("/var/log/vsftpd.log"),
                                                               Path("/var/log/proftpd/proftpd.log")])
    windows_ftp_log_paths: list[Path] = field(default_factory=lambda: [
        Path(os.environ.get("SystemDrive", "C:") + r"\inetpub\logs\LogFiles")])
    monitored_paths: list[Path] = field(default_factory=default_monitored_paths)
    process_interval_seconds: float = 10.0
    executable_hashing_enabled: bool = True
    process_command_line_max_length: int = 2048
    executable_hash_max_bytes: int = 16 * 1024 * 1024
    process_hashes_per_scan: int = 2
    network_interval_seconds: float = 15.0
    system_interval_seconds: float = 30.0
    auth_interval_seconds: float = 2.0
    file_integrity_interval_seconds: float = 30.0
    auth_failure_threshold: int = 5
    auth_failure_window_seconds: float = 300.0
    alert_cooldown_seconds: float = 300.0
    retention_days: int = 30
    rule_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    correlation_window_seconds: float = 300.0
    network_unusual_ports: list[int] = field(default_factory=lambda: [4444, 5555, 6667, 9001])
    network_destination_allowlist: list[str] = field(default_factory=list)
    network_repeat_threshold: int = 5
    threat_intelligence_enabled: bool = False
    sysmon_enabled: bool = False
    persistence_enabled: bool = False
    persistence_paths: list[Path] = field(default_factory=list)
    persistence_registry_enabled: bool = False
    persistence_services_enabled: bool = False
    persistence_interval_seconds: float = 60.0
    persistence_max_files: int = 500
    persistence_max_bytes: int = 1024 * 1024
    persistence_verify_every_scans: int = 10
    yara_enabled: bool = False
    yara_rule_paths: list[Path] = field(default_factory=list)
    yara_scan_paths: list[Path] = field(default_factory=list)
    yara_max_bytes: int = 16 * 1024 * 1024
    yara_timeout_seconds: int = 10
    response_enabled: bool = False
    retention_enabled: bool = False
    maintenance_interval_seconds: float = 86400.0
    enabled_collectors: set[str] = field(default_factory=lambda: {"auth", "ftp", "process", "network", "file_integrity", "system", "event_log"})

    @classmethod
    def from_json(cls, path: Path) -> "HostConfig":
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        paths = {"database_path", "auth_log_paths", "windows_ftp_log_paths", "monitored_paths", "persistence_paths", "yara_rule_paths", "yara_scan_paths"}
        for key in paths:
            if key in payload and key != "database_path":
                payload[key] = [Path(value) for value in payload[key]]
        if "database_path" in payload:
            payload["database_path"] = Path(payload["database_path"])
        if "enabled_collectors" in payload:
            payload["enabled_collectors"] = set(payload["enabled_collectors"])
        return cls(**payload)

    def validate(self) -> None:
        if not self.host_id:
            raise ValueError("host_id is required")
        if not self.dashboard_host:
            raise ValueError("dashboard_host is required")
        if not 1 <= self.dashboard_port <= 65535:
            raise ValueError("dashboard_port is invalid")
        for value in (
            self.process_interval_seconds,
            self.network_interval_seconds,
            self.system_interval_seconds,
            self.auth_interval_seconds,
            self.file_integrity_interval_seconds,
            self.alert_cooldown_seconds,
            self.persistence_interval_seconds,
            self.correlation_window_seconds,
            self.maintenance_interval_seconds,
        ):
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("collection intervals and cooldown must be positive")
        if type(self.auth_failure_threshold) is not int or not 2 <= self.auth_failure_threshold <= 100 or not math.isfinite(self.auth_failure_window_seconds) or not 0 < self.auth_failure_window_seconds <= 86400:
            raise ValueError("invalid authentication failure rule configuration")
        if type(self.retention_days) is not int or not 1 <= self.retention_days <= 36500:
            raise ValueError("retention_days must be positive")
        if not isinstance(self.executable_hashing_enabled, bool):
            raise ValueError("executable_hashing_enabled must be a boolean")
        if not 128 <= self.process_command_line_max_length <= 16384:
            raise ValueError("process_command_line_max_length must be between 128 and 16384")
        if not 0 <= self.executable_hash_max_bytes <= 64 * 1024 * 1024:
            raise ValueError("executable_hash_max_bytes must be between 0 and 64 MiB")
        if not 0 <= self.process_hashes_per_scan <= 8:
            raise ValueError("process_hashes_per_scan must be between 0 and 8")
        for key in ("threat_intelligence_enabled", "sysmon_enabled", "persistence_enabled", "persistence_registry_enabled",
                    "persistence_services_enabled", "yara_enabled", "response_enabled", "retention_enabled"):
            if not isinstance(getattr(self, key), bool):
                raise ValueError(f"{key} must be a boolean")
        if not 1 <= self.persistence_max_files <= 5000 or not 1 <= self.persistence_max_bytes <= 16 * 1024 * 1024:
            raise ValueError("invalid persistence scan limits")
        if type(self.persistence_verify_every_scans) is not int or not 1 <= self.persistence_verify_every_scans <= 1000:
            raise ValueError('invalid persistence verification interval')
        if not 1 <= self.yara_max_bytes <= 64 * 1024 * 1024 or not 1 <= self.yara_timeout_seconds <= 60:
            raise ValueError("invalid YARA scan limits")
        if not 2 <= self.network_repeat_threshold <= 100 or any(type(port) is not int or not 1 <= port <= 65535 for port in self.network_unusual_ports):
            raise ValueError("invalid network rule settings")
        import ipaddress
        for network in self.network_destination_allowlist:
            ipaddress.ip_network(network, strict=False)
        if not isinstance(self.rule_settings, dict):
            raise ValueError("rule_settings must be an object")
        if not 1 <= self.correlation_window_seconds <= 86400:
            raise ValueError('correlation window must be between 1 second and 1 day')
        for key in ('persistence_paths','yara_scan_paths','yara_rule_paths'):
            values = getattr(self,key)
            if not isinstance(values,list) or len(values)>64 or any(not isinstance(path,Path) for path in values):
                raise ValueError('invalid configured path list')
