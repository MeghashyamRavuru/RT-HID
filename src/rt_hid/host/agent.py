from __future__ import annotations

import logging
import platform
import signal
import threading
import time
from dataclasses import replace
from typing import Any

from .alerts.manager import HostAlertManager
from .collectors.base import Collector
from .collectors.linux import LinuxAuthCollector, LinuxFileIntegrityCollector, LinuxNetworkCollector, LinuxProcessCollector, LinuxSystemCollector
from .collectors.windows import WindowsEventLogCollector, WindowsFileIntegrityCollector, WindowsNetworkCollector, WindowsProcessCollector, WindowsSystemCollector
from .config import HostConfig
from .detection.engine import HostDetectionEngine
from .models import HostEvent
from .platform import detect_capabilities
from .storage import HostDatabase


class HostAgent:
    def __init__(self, config: HostConfig, logger: logging.Logger | None = None) -> None:
        config.validate()
        self.config = config
        self.logger = logger or logging.getLogger("rt_hid.host")
        self.database = HostDatabase(config.database_path)
        self.detector = HostDetectionEngine(config)
        self.alerts = HostAlertManager(self.database, config)
        self.stop_event = threading.Event()
        self.capabilities = detect_capabilities()
        self.collectors = self._build_collectors()
        self._next_run: dict[str, float] = {}

    def _build_collectors(self) -> list[Collector]:
        sink = self.ingest_event
        if self.capabilities.system == "linux":
            candidates: list[Collector] = [
                LinuxAuthCollector(self.config.host_id, self.config, self.database, sink),
                LinuxProcessCollector(self.config.host_id, sink, self.config),
                LinuxNetworkCollector(self.config.host_id, sink),
                LinuxFileIntegrityCollector(self.config.host_id, self.config, self.database, sink),
                LinuxSystemCollector(self.config.host_id, sink),
            ]
        elif self.capabilities.system == "windows":
            candidates = [
                WindowsEventLogCollector(self.config.host_id, self.database, sink),
                WindowsProcessCollector(self.config.host_id, sink, self.config),
                WindowsNetworkCollector(self.config.host_id, sink),
                WindowsFileIntegrityCollector(self.config.host_id, self.config, self.database, sink),
                WindowsSystemCollector(self.config.host_id, sink),
            ]
        else:
            candidates = []
        return [collector for collector in candidates if collector.collector_id in self.config.enabled_collectors or collector.collector_id.split("_", 1)[-1] in self.config.enabled_collectors]

    def ingest_event(self, event: HostEvent) -> None:
        if not self.database.save_event(event):
            return
        for detection in self.detector.evaluate(event):
            self.database.save_detection(detection)
            self.alerts.consume(detection)

    def collect_once(self) -> None:
        for collector in self.collectors:
            collector.run_once()
            self.database.save_collector_status(collector.status)

    def run_forever(self, install_signals: bool = True) -> None:
        if install_signals:
            self._install_signal_handlers()
        while not self.stop_event.is_set():
            now = time.monotonic()
            for collector in self.collectors:
                if now < self._next_run.get(collector.collector_id, 0):
                    continue
                collector.run_once()
                self.database.save_collector_status(collector.status)
                name = collector.collector_id.split("_", 1)[-1]
                interval = {
                    "auth": self.config.auth_interval_seconds,
                    "event_log": self.config.auth_interval_seconds,
                    "process": self.config.process_interval_seconds,
                    "network": self.config.network_interval_seconds,
                    "file_integrity": self.config.file_integrity_interval_seconds,
                    "system": self.config.system_interval_seconds,
                }[name]
                self._next_run[collector.collector_id] = now + interval
            self.stop_event.wait(1.0)

    def stop(self) -> None:
        self.stop_event.set()
        self.alerts.shutdown()
        for collector in self.collectors:
            collector.status = replace(collector.status, state="stopped", detail="stopped")
            self.database.save_collector_status(collector.status)
        self.database.close()

    def status(self) -> dict[str, Any]:
        return {
            "host_id": self.config.host_id,
            "hostname": platform.node(),
            "platform": self.capabilities.__dict__,
            "collectors": [collector.status.to_dict() for collector in self.collectors],
        }

    def _install_signal_handlers(self) -> None:
        def handle(_signum: int, _frame: Any) -> None:
            self.stop_event.set()

        for signal_name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signal_name):
                signal.signal(getattr(signal, signal_name), handle)
