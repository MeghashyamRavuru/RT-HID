from __future__ import annotations

import json
import os
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
    auth_log_paths: list[Path] = field(default_factory=lambda: [Path("/var/log/auth.log"), Path("/var/log/secure")])
    monitored_paths: list[Path] = field(default_factory=default_monitored_paths)
    process_interval_seconds: float = 10.0
    network_interval_seconds: float = 15.0
    system_interval_seconds: float = 30.0
    auth_interval_seconds: float = 2.0
    file_integrity_interval_seconds: float = 30.0
    auth_failure_threshold: int = 5
    auth_failure_window_seconds: float = 300.0
    alert_cooldown_seconds: float = 300.0
    retention_days: int = 30
    enabled_collectors: set[str] = field(default_factory=lambda: {"auth", "process", "network", "file_integrity", "system", "event_log"})

    @classmethod
    def from_json(cls, path: Path) -> "HostConfig":
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        paths = {"database_path", "auth_log_paths", "monitored_paths"}
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
        ):
            if value <= 0:
                raise ValueError("collection intervals and cooldown must be positive")
        if self.auth_failure_threshold < 2 or self.auth_failure_window_seconds <= 0:
            raise ValueError("invalid authentication failure rule configuration")
        if self.retention_days < 1:
            raise ValueError("retention_days must be positive")
