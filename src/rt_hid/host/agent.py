from __future__ import annotations

import logging
import platform
import signal
import threading
import time
from datetime import datetime, timezone
from dataclasses import replace
from typing import Any

from .alerts.manager import HostAlertManager
from .collectors.base import Collector
from .collectors.linux import LinuxAuthCollector, LinuxFileIntegrityCollector, LinuxNetworkCollector, LinuxProcessCollector, LinuxSystemCollector
from .collectors.ftp import WindowsFtpCollector
from .collectors.windows import WindowsEventLogCollector, WindowsFileIntegrityCollector, WindowsNetworkCollector, WindowsProcessCollector, WindowsSystemCollector
from .config import HostConfig
from .detection.engine import HostDetectionEngine
from .models import HostEvent
from .platform import detect_capabilities
from .storage import HostDatabase
from .processes import ProcessGraph
from .intelligence import Intelligence
from .collectors.persistence import PersistenceCollector
from .collectors.windows import WindowsSystemLogCollector,WindowsSysmonCollector
from .correlation import Correlator
from .jobs import JobRunner
from .scanning import YaraScanner
from .audit import AuditLog
from .maintenance import Maintenance
from .response import ResponseService
from .notifications import DesktopNotifier


class HostAgent:
    def __init__(self, config: HostConfig, logger: logging.Logger | None = None) -> None:
        config.validate()
        self.config = config
        self.logger = logger or logging.getLogger("rt_hid.host")
        self.database = HostDatabase(config.database_path)
        self.processes = ProcessGraph(self.database)
        self.detector = HostDetectionEngine(config, self.database, self.processes)
        self._ingest_lock = threading.RLock()
        self.notifications = DesktopNotifier(config.desktop_notifications_enabled, self.logger, config.dashboard_port)
        self.alerts = HostAlertManager(self.database, config, self.notifications)
        self.intelligence = Intelligence(self.database, config)
        self.correlator = Correlator(self.database, config)
        self.jobs = JobRunner(self.database)
        self.scanner = YaraScanner(config,self.jobs,self.ingest_event)
        self.audit = AuditLog(self.database)
        self.jobs.audit = self.audit
        self.maintenance = Maintenance(self.database,config,self.audit,self._ingest_lock)
        self.response = ResponseService(config,self.database,self.processes,self.audit)
        self.stop_event = threading.Event()
        self.capabilities = detect_capabilities()
        self.collectors = self._build_collectors()
        self._next_run: dict[str, float] = {}
        self._persistence_thread = None
        self._next_maintenance = 0.0

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
                WindowsFtpCollector(self.config.host_id, self.config, self.database, sink),
                WindowsProcessCollector(self.config.host_id, sink, self.config),
                WindowsNetworkCollector(self.config.host_id, sink),
                WindowsFileIntegrityCollector(self.config.host_id, self.config, self.database, sink),
                WindowsSystemCollector(self.config.host_id, sink),
            ]
        else:
            candidates = []
        result = [collector for collector in candidates if collector.collector_id in self.config.enabled_collectors or collector.collector_id.split("_", 1)[-1] in self.config.enabled_collectors]
        if self.config.persistence_enabled and self.capabilities.system in {'windows','linux'}:
            result.append(PersistenceCollector(self.config.host_id,self.config,self.database,sink,self.capabilities.system))
            if self.capabilities.system == 'windows':
                result.append(WindowsSystemLogCollector(self.config.host_id,self.database,sink))
        if self.config.sysmon_enabled and self.capabilities.system == 'windows':
            result.append(WindowsSysmonCollector(self.config.host_id,self.database,sink))
        return result

    def ingest_event(self, event: HostEvent) -> None:
        with self._ingest_lock:
            if not self.database.save_event(event):
                return
            self.processes.observe(event)
            detections = self.detector.evaluate(event)
            detections += self.detector.finalize(self.intelligence.match(event), event)
            detections += self.detector.finalize(self.correlator.evaluate(event, detections), event)
            for detection in detections:
                if self.alerts.consume(detection) is None:
                    self.database.save_detection(detection)

    def collect_once(self) -> None:
        for collector in self.collectors:
            collector.run_once()
            self.database.save_collector_status(collector.status)

    def run_forever(self, install_signals: bool = True) -> None:
        self.jobs.recover()
        if install_signals:
            self._install_signal_handlers()
        while not self.stop_event.is_set():
            now = time.monotonic()
            if self.config.retention_enabled and now >= self._next_maintenance:
                try:
                    self.jobs.submit('retention','resolved evidence policy',self.maintenance.retention,actor='system')
                except ValueError:
                    pass  # Bounded queue: retry on the next scheduler cycle.
                else:
                    self._next_maintenance = now + self.config.maintenance_interval_seconds
            for collector in self.collectors:
                if now < self._next_run.get(collector.collector_id, 0):
                    continue
                if collector.collector_id.endswith('_persistence'):
                    if self._persistence_thread is not None and self._persistence_thread.is_alive():
                        continue
                    def scan(target=collector):
                        target.run_once()
                        self.database.save_collector_status(target.status)
                    self._persistence_thread = threading.Thread(target=scan,daemon=True)
                    self._persistence_thread.start()
                else:
                    collector.run_once()
                    self.database.save_collector_status(collector.status)
                name = collector.collector_id.split("_", 1)[-1]
                interval = {
                    "auth": self.config.auth_interval_seconds,
                    "ftp": self.config.auth_interval_seconds,
                    "event_log": self.config.auth_interval_seconds,
                    "system_log": self.config.auth_interval_seconds,
                    "sysmon": self.config.auth_interval_seconds,
                    "persistence": self.config.persistence_interval_seconds,
                    "process": self.config.process_interval_seconds,
                    "network": self.config.network_interval_seconds,
                    "file_integrity": self.config.file_integrity_interval_seconds,
                    "system": self.config.system_interval_seconds,
                }[name]
                self._next_run[collector.collector_id] = now + interval
            self.stop_event.wait(1.0)

    def stop(self) -> None:
        self.stop_event.set()
        if self._persistence_thread is not None:
            self._persistence_thread.join(timeout=10)
        self.jobs.close()
        self.alerts.shutdown()
        self.notifications.close()
        for collector in self.collectors:
            collector.status = replace(collector.status, state="stopped", detail="stopped")
            self.database.save_collector_status(collector.status)
        self.database.close()

    def status(self) -> dict[str, Any]:
        collectors = []
        for collector in self.collectors:
            item = collector.status.to_dict()
            last = item.get('last_success')
            item['seconds_since_success'] = max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(last.replace('Z','+00:00'))).total_seconds()) if last else None
            collectors.append(item)
        return {
            "host_id": self.config.host_id,
            "hostname": platform.node(),
            "platform": self.capabilities.__dict__,
            "collectors": collectors,
            "desktop_notifications": self.notifications.status(),
            "background_queue":{'depth':self.jobs.queue.qsize(),'capacity':4,'worker_running':bool(self.jobs.thread and self.jobs.thread.is_alive())},
            "capabilities": {"network":"psutil polling with inferred outbound direction", "persistence":self.config.persistence_enabled,
                "sysmon":"configured; see collector health" if self.config.sysmon_enabled and self.capabilities.system=='windows' else 'not configured or unsupported', "auditd":"not configured", "journald":"not configured", "ebpf":"not installed",
                "response":self.config.response_enabled,"yara":self.scanner.status()},
        }

    def _install_signal_handlers(self) -> None:
        def handle(_signum: int, _frame: Any) -> None:
            self.stop_event.set()

        for signal_name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signal_name):
                signal.signal(getattr(signal, signal_name), handle)
