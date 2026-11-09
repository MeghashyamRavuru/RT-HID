import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rt_hid.host.agent import HostAgent
from rt_hid.host.collectors.linux import LinuxProcessCollector, _redact_command_line
from rt_hid.host.collectors.windows import WindowsProcessCollector
from rt_hid.host.config import HostConfig
from rt_hid.host.models import HostEvent
from rt_hid.host.storage import HostDatabase


class AccessDenied(Exception):
    pass


class NoSuchProcess(Exception):
    pass


class ZombieProcess(Exception):
    pass


class FakeProcess:
    def __init__(self, pid, created, *, exe=None, name="worker", ppid=10,
                 command=None, cwd=None, failure=None):
        self.pid = pid
        self._info = {"pid": pid, "create_time": created, "exe": exe, "name": name,
                      "ppid": ppid, "username": "alice"}
        self.command = command
        self.directory = cwd
        self.failure = failure

    @property
    def info(self):
        if self.failure == "info":
            raise AccessDenied()
        if self.failure == "gone_info":
            raise NoSuchProcess()
        if self.failure == "zombie_info":
            raise ZombieProcess()
        return self._info

    def create_time(self):
        if self.failure == "gone_time":
            raise NoSuchProcess()
        return self._info["create_time"]

    def cmdline(self):
        if self.failure == "cmdline":
            raise AccessDenied()
        if self.failure == "gone":
            raise NoSuchProcess()
        if self.failure == "zombie":
            raise ZombieProcess()
        if self.failure == "value_error_cmdline":
            raise ValueError("--password=private-token")
        if self.failure == "unexpected_cmdline":
            raise RuntimeError("--password=private-token")
        return self.command

    def cwd(self):
        if self.failure in {"cwd", "gone", "zombie"}:
            raise AccessDenied()
        return self.directory


class ProcessTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.processes = []
        self.emitted = []
        self.parents = {10: "shell"}
        self.alive_pids = set()
        self.fake_psutil = SimpleNamespace(
            AccessDenied=AccessDenied, NoSuchProcess=NoSuchProcess,
            ZombieProcess=ZombieProcess, process_iter=lambda _attrs: list(self.processes),
            Process=lambda pid: SimpleNamespace(name=lambda: self.parents[pid]),
            pid_exists=lambda pid: pid in self.alive_pids,
        )
        self.module_patch = patch.dict(sys.modules, {"psutil": self.fake_psutil})
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)

    def collector(self, cls=LinuxProcessCollector, **options):
        config = HostConfig(host_id="host-1", **options)
        return cls("host-1", self.emitted.append, config)

    def test_process_config_defaults_and_limits(self):
        config = HostConfig(host_id="host-1")
        config.validate()
        self.assertEqual(config.process_interval_seconds, 10.0)
        self.assertTrue(config.executable_hashing_enabled)
        with self.assertRaises(ValueError):
            HostConfig(host_id="host-1", process_hashes_per_scan=9).validate()

    def test_baseline_start_duplicate_stop_and_pid_reuse(self):
        collector = self.collector(executable_hashing_enabled=False)
        self.processes = [FakeProcess(42, 1000, command=["worker"], cwd="/tmp")]
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.run_once(), [])
        self.processes = [FakeProcess(42, 2000, command=["worker", "--token", "secret"], cwd="/tmp")]
        events = collector.run_once()
        self.assertEqual([event.event_type for event in events], ["process_start", "process_stop"])
        started = events[0]
        self.assertEqual(started.metadata["parent_name"], "shell")
        self.assertEqual(started.metadata["working_directory"], "/tmp")
        self.assertEqual(started.metadata["command_line"], ["worker", "--token", "<redacted>"])
        self.assertEqual(events[1].metadata["create_time"], 1000)
        self.assertEqual(collector.run_once(), [])
        self.processes = []
        stopped = collector.run_once()
        self.assertEqual(len(stopped), 1)
        self.assertEqual(stopped[0].event_type, "process_stop")
        self.assertEqual(stopped[0].metadata["create_time"], 2000)

    def test_missing_fields_and_process_inspection_failures_are_isolated(self):
        collector = self.collector(executable_hashing_enabled=False)
        collector.run_once()
        self.processes = [FakeProcess(1, 1000, exe=None, command=None),
                          FakeProcess(2, 1001, failure="info"),
                          FakeProcess(3, 1002, failure="gone"),
                          FakeProcess(4, 1003, failure="zombie"),
                          FakeProcess(5, 1004, failure="cwd")]
        events = collector.run_once()
        self.assertEqual(len(events), 2)
        self.assertIsNone(events[0].executable_path)
        self.assertIsNone(events[0].metadata["command_line"])
        self.assertIsNone(events[1].metadata["working_directory"])
        self.assertEqual(collector.status.processes_inspected, 5)
        self.assertGreaterEqual(collector.status.inaccessible_processes, 4)
        self.assertEqual(collector.status.events_generated, 2)
        self.assertEqual(collector.status.state, "running")
        self.assertIsNotNone(collector.status.last_duration_seconds)
        self.assertIsNotNone(collector.status.last_success)
        self.assertNotIn("secret", collector.status.last_error or "")

    def test_inaccessible_known_process_is_not_reported_stopped(self):
        collector = self.collector(executable_hashing_enabled=False)
        self.processes = [FakeProcess(7, 1000)]
        collector.run_once()
        self.processes = [FakeProcess(7, 1000, failure="info")]
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(len(collector._known), 1)

    def test_invalid_creation_times_preserve_known_process(self):
        for cls in (LinuxProcessCollector, WindowsProcessCollector):
            with self.subTest(collector=cls.__name__):
                collector = self.collector(cls, executable_hashing_enabled=False)
                self.processes = [FakeProcess(7, 1000)]
                collector.run_once()
                for invalid in ("not-a-time", "nan", "inf", -1, 1e30):
                    with self.subTest(value=invalid):
                        self.processes = [FakeProcess(7, invalid)]
                        self.assertEqual(collector.run_once(), [])
                        self.assertEqual(set(collector._known), {(7, 1000.0)})
                        self.assertTrue(collector.status.last_error.startswith("creation_time: "))
                        self.assertEqual(collector.status.collection_errors, 1)
                self.processes = [FakeProcess(7, 1000)]
                self.assertEqual(collector.run_once(), [])

    def test_windows_zero_time_system_processes_are_skipped(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(0, 0.0), FakeProcess(4, 0.0), FakeProcess(42, 1000)]
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.processes_inspected, 3)
        self.assertEqual(collector.status.inaccessible_processes, 0)
        self.assertEqual(collector.status.collection_errors, 0)
        self.assertIsNone(collector.status.last_error)
        self.assertEqual(set(collector._known), {(42, 1000.0)})
        self.processes.append(FakeProcess(43, 1001))
        self.assertEqual([event.process_id for event in collector.run_once()], [43])

        self.processes.append(FakeProcess(99, 0.0))
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.last_error, "creation_time: ValueError")

    def test_linux_zero_creation_time_remains_diagnostic(self):
        collector = self.collector(LinuxProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(0, 0.0)]
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.last_error, "creation_time: ValueError")

    def test_missing_creation_time_and_process_exit_during_lookup(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(8, 1000)]
        collector.run_once()
        for process, expected in (
            (FakeProcess(8, None), "creation_time: ValueError"),
            (FakeProcess(8, None, failure="gone_time"), "creation_time: NoSuchProcess"),
            (FakeProcess(8, 1000, failure="gone_info"), "process_info: NoSuchProcess"),
            (FakeProcess(8, 1000, failure="zombie_info"), "process_info: ZombieProcess"),
            (FakeProcess(8, 1000, failure="info"), "process_info: AccessDenied"),
        ):
            with self.subTest(error=expected):
                self.processes = [process]
                self.assertEqual(collector.run_once(), [])
                self.assertEqual(collector.status.last_error, expected)
                self.assertEqual(set(collector._known), {(8, 1000.0)})
                self.assertEqual(collector.status.inaccessible_processes, 1)
                self.assertEqual(collector.status.collection_errors, 1)

    def test_disappearing_new_process_does_not_leave_seen_identity(self):
        collector = self.collector(executable_hashing_enabled=False)
        collector.run_once()
        self.processes = [FakeProcess(9, 1000, failure="gone")]
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.last_error, "command_line: NoSuchProcess")
        self.assertNotIn((9, 1000.0), collector._known)
        self.processes = [FakeProcess(9, 1000, command=["worker"])]
        self.assertEqual([event.event_type for event in collector.run_once()], ["process_start"])

    def test_temporarily_omitted_live_pid_does_not_emit_stop(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(12, 1000)]
        collector.run_once()
        self.processes = []
        self.alive_pids.add(12)
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(set(collector._known), {(12, 1000.0)})
        self.alive_pids.clear()
        self.assertEqual([event.event_type for event in collector.run_once()], ["process_stop"])

    def test_enumeration_value_error_is_sanitized_and_keeps_baseline(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(12, 1000)]
        collector.run_once()
        previous_success = collector.status.last_success

        def broken_iterator(_attrs):
            yield FakeProcess(13, 1001)
            raise ValueError("--token=private-token")

        self.fake_psutil.process_iter = broken_iterator
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.last_error, "process_enumeration: ValueError")
        self.assertEqual(collector.status.state, "degraded")
        self.assertEqual(collector.status.last_success, previous_success)
        self.assertEqual(set(collector._known), {(12, 1000.0)})
        self.assertNotIn("private-token", str(collector.status.to_dict()))

    def test_optional_value_error_is_sanitized_and_unexpected_error_degrades(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        collector.run_once()
        self.processes = [FakeProcess(10, 1000, failure="value_error_cmdline")]
        self.assertEqual(len(collector.run_once()), 1)
        self.assertEqual(collector.status.last_error, "command_line: ValueError")
        self.assertNotIn("private-token", str(collector.status.to_dict()))
        self.assertEqual(collector.status.state, "running")
        self.processes.append(FakeProcess(11, 1001, failure="unexpected_cmdline"))
        self.assertEqual(collector.run_once(), [])
        self.assertEqual(collector.status.last_error, "command_line: RuntimeError")
        self.assertEqual(collector.status.state, "degraded")
        self.assertNotIn("private-token", str(collector.status.to_dict()))

    def test_hash_generation_cache_size_limit_and_disabled_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "program.bin"
            executable.write_bytes(b"example executable")
            collector = self.collector(executable_hash_max_bytes=1024)
            collector.run_once()
            self.processes = [FakeProcess(1, 1000, exe=str(executable))]
            first = collector.run_once()[0]
            self.assertEqual(first.metadata["executable_sha256"],
                             hashlib.sha256(b"example executable").hexdigest())
            self.assertEqual(collector.run_once(), [])
            self.processes.append(FakeProcess(2, 1001, exe=str(executable)))
            with patch.object(Path, "open", side_effect=AssertionError("cached file was opened")):
                second = collector.run_once()[0]
            self.assertEqual(second.metadata["executable_sha256"], first.metadata["executable_sha256"])

            limited = self.collector(executable_hash_max_bytes=2)
            limited.run_once()
            self.processes = [FakeProcess(3, 1002, exe=str(executable))]
            self.assertEqual(limited.run_once()[0].metadata["executable_hash_error"], "file exceeds size limit")
            disabled = self.collector(executable_hashing_enabled=False)
            disabled.run_once()
            self.processes = [FakeProcess(4, 1003, exe=str(executable))]
            self.assertIsNone(disabled.run_once()[0].metadata["executable_sha256"])

    def test_hash_failure_budget_and_redaction(self):
        collector = self.collector(process_hashes_per_scan=0)
        collector.run_once()
        self.processes = [FakeProcess(1, 1000, exe="missing.exe",
                                      command=["tool", "--password=secret", "--api-key", "value"])]
        event = collector.run_once()[0]
        self.assertIsNone(event.metadata["executable_sha256"])
        self.assertEqual(event.metadata["command_line"],
                         ["tool", "--password=<redacted>", "--api-key", "<redacted>"])
        self.assertNotIn("secret", json.dumps(event.to_dict()))
        self.assertEqual(_redact_command_line(["tool", "A" * 200], 128), ["tool", "<truncated>"])

    def test_hash_budget_and_changed_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.bin"
            second_path = Path(directory) / "second.bin"
            first_path.write_bytes(b"first")
            second_path.write_bytes(b"second")
            collector = self.collector(process_hashes_per_scan=1)
            collector.run_once()
            self.processes = [FakeProcess(1, 1000, exe=str(first_path)),
                              FakeProcess(2, 1001, exe=str(second_path))]
            events = collector.run_once()
            self.assertIsNotNone(events[0].metadata["executable_sha256"])
            self.assertEqual(events[1].metadata["executable_hash_error"], "scan budget reached")
            first_path.write_bytes(b"changed content")
            self.processes.append(FakeProcess(3, 1002, exe=str(first_path)))
            new_hash = collector.run_once()[0].metadata["executable_sha256"]
            self.assertEqual(new_hash, hashlib.sha256(b"changed content").hexdigest())

    def test_windows_collector_uses_same_process_identity_logic(self):
        collector = self.collector(WindowsProcessCollector, executable_hashing_enabled=False)
        self.processes = [FakeProcess(9, 1000)]
        self.assertEqual(collector.run_once(), [])
        self.processes = [FakeProcess(9, 2000)]
        self.assertEqual([event.event_type for event in collector.run_once()],
                         ["process_start", "process_stop"])
        self.assertEqual(collector.status.platform, "windows")

    def test_metadata_persists_and_old_records_remain_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            database = HostDatabase(Path(directory) / "events.sqlite3")
            try:
                event = HostEvent.create("host-1", "process_start", "fixture", process_id=7,
                                         metadata={"parent_name": "shell", "executable_sha256": "abc"})
                self.assertTrue(database.save_event(event))
                old = {"event_id": "old", "event_type": "process_start", "process_id": 1}
                with database.connection:
                    database.connection.execute(
                        "INSERT INTO host_events(event_id, timestamp, host_id, event_type, source, payload) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        ("old", event.timestamp, "host-1", "process_start", "fixture", json.dumps(old)))
                rows = database._records_by_ids("host_events", "event_id", [event.event_id, "old"])
                self.assertEqual(rows[0]["metadata"]["parent_name"], "shell")
                self.assertEqual(rows[1], old)
            finally:
                database.close()

    def test_collector_health_uses_existing_status_store(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = self.collector(executable_hashing_enabled=False)
            self.processes = [FakeProcess(1, 1000)]
            collector.run_once()
            self.processes.append(FakeProcess(2, 1001))
            collector.run_once()
            status = collector.status.to_dict()
            self.assertEqual(status["state"], "running")
            self.assertEqual(status["processes_inspected"], 2)
            self.assertEqual(status["events_generated"], 1)
            database = HostDatabase(Path(directory) / "events.sqlite3")
            try:
                database.save_collector_status(collector.status)
                row = database.connection.execute(
                    "SELECT payload FROM collector_status WHERE collector_id = ?", (collector.collector_id,)
                ).fetchone()
                self.assertEqual(json.loads(row["payload"])["last_success"], status["last_success"])
            finally:
                database.close()

    def test_process_metadata_reaches_incident_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "events.sqlite3",
                                enabled_collectors=set())
            agent = HostAgent(config)
            try:
                agent.ingest_event(HostEvent.create(
                    "host-1", "process_start", "fixture", process_id=7,
                    executable_path="/tmp/sample", metadata={"parent_name": "shell",
                                                              "command_line": ["sample"],
                                                              "executable_sha256": "abc"},
                ))
                incidents = agent.database.list_incidents()
                self.assertEqual(len(incidents), 1)
                detail = agent.database.get_incident_detail(incidents[0]["incident_id"])
                self.assertEqual(detail["events"][0]["metadata"]["executable_sha256"], "abc")
            finally:
                agent.stop()
