import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rt_hid.host.agent import HostAgent
from rt_hid.host.api import create_app
from rt_hid.host.config import HostConfig
from rt_hid.host.models import CollectorStatus, HostEvent


class ConsoleApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        config = HostConfig(host_id="console-host", database_path=Path(self.directory.name) / "host.sqlite3",
                            enabled_collectors=set(), monitored_paths=[Path("/etc/checked.conf")])
        self.agent = HostAgent(config)
        self.addCleanup(self.agent.stop)
        self.agent.database.set_admin_password("example-local-admin-password")
        self.client = create_app(self.agent).test_client()

    def login(self):
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            token = browser_session["csrf_token"]
        response = self.client.post("/login", data={"username": "admin", "password": "example-local-admin-password",
                                                     "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        return {"X-CSRF-Token": self.client.get("/api/session").get_json()["csrf_token"]}

    def test_new_pages_require_login_and_old_api_remains_a_list(self):
        for path in ("/api/alert-page", "/api/event-page?kind=process", "/api/settings"):
            self.assertEqual(self.client.get(path).status_code, 401)
        self.login()
        self.assertIsInstance(self.client.get("/api/alerts").get_json(), list)
        for path in ("/api/alert-page", "/api/event-page?kind=process", "/api/settings"):
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertEqual(self.client.get("/api/alert-page").get_json()["total"], 0)
        self.assertEqual(self.client.get("/api/event-page?kind=file").get_json()["items"], [])

    def test_alert_and_event_filtering_pagination_and_links(self):
        self.agent.ingest_event(HostEvent.create("console-host", "file_change", "fixture",
                                                 file_path="/etc/checked.conf", action="modify",
                                                 outcome="observed"))
        self.agent.ingest_event(HostEvent.create("console-host", "file_change", "fixture",
                                                 file_path="/etc/other.conf", action="delete",
                                                 outcome="observed"))
        self.agent.ingest_event(HostEvent.create("console-host", "process_start", "fixture",
                                                 process_id=123, process_name="sample",
                                                 executable_path="/tmp/sample", action="start",
                                                 outcome="observed", metadata={"parent_name": "shell"}))
        self.login()
        page = self.client.get("/api/alert-page?limit=1&offset=0&severity=medium").get_json()
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["items"]), 1)
        self.assertEqual(self.client.get("/api/alert-page?status=false_positive").get_json()["total"], 0)
        rule = self.client.get("/api/alert-page?rule=HIDS-FIM-001").get_json()
        self.assertEqual(rule["total"], 2)
        files = self.client.get("/api/event-page?kind=file&action=modify&q=checked.conf").get_json()
        self.assertEqual(files["total"], 1)
        self.assertEqual(len(files["items"][0]["related_incident_ids"]), 1)
        self.assertEqual(self.client.get("/api/event-page?kind=process&action=stop").get_json()["total"], 0)
        process = self.client.get("/api/event-page?kind=process&action=start").get_json()["items"][0]
        self.assertEqual(process["metadata"]["parent_name"], "shell")
        incident_page = self.client.get("/api/incident-page?severity=medium&limit=1").get_json()
        self.assertEqual(incident_page["total"], 3)
        self.assertEqual(len(incident_page["items"]), 1)

    def test_invalid_queries_are_json_errors(self):
        self.login()
        for path in (
            "/api/alert-page?limit=0", "/api/alert-page?offset=-1",
            "/api/alert-page?order=random", "/api/alert-page?severity=urgent",
            "/api/alert-page?status=unknown", "/api/event-page?kind=unknown",
            "/api/event-page?kind=file&action=start", "/api/incident-page?state=invalid",
            "/api/incident-page?severity=urgent", "/api/alert-page?q=" + "a" * 101,
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())

    def test_settings_and_health_expose_no_auth_secrets(self):
        self.agent.collectors = []
        self.login()
        settings = self.client.get("/api/settings").get_json()
        self.assertEqual(settings["monitored_paths"], [str(Path("/etc/checked.conf"))])
        self.assertNotIn("password", settings)
        self.assertNotIn("session_secret", settings)
        self.assertEqual(self.client.get("/api/status").get_json()["collectors"], [])
        status = CollectorStatus("windows_process", "windows", True, True,
                                 state="running", collection_errors=1, inaccessible_processes=2)
        self.agent.collectors = [type("FakeCollector", (), {"status": status})()]
        self.assertEqual(self.client.get("/api/status").get_json()["collectors"][0]["collection_errors"], 1)
        self.agent.collectors = []

    def test_templates_keep_nonce_and_csrf(self):
        login_page = self.client.get("/login")
        self.assertIn(b'name="csrf_token"', login_page.data)
        self.assertIn(b'<script nonce=', login_page.data)
        self.assertIn("script-src 'nonce-", login_page.headers["Content-Security-Policy"])
        self.login()
        dashboard = self.client.get("/")
        self.assertIn(b'id="view-processes"', dashboard.data)
        self.assertIn(b'id="view-collectors"', dashboard.data)
        self.assertIn(b'<script nonce=', dashboard.data)

    def test_utc_activity_window_and_alert_scope(self):
        for path in ("/etc/recent.conf", "/etc/old.conf"):
            self.agent.ingest_event(HostEvent.create("console-host", "file_change", "fixture",
                                                     file_path=path, action="modify", outcome="observed"))
        alerts = self.agent.database.list_alerts()
        old_incident = next(item["incident_id"] for item in alerts if item["file_path"] == "/etc/old.conf")
        old_day = (datetime.now(timezone.utc).date() - timedelta(days=7)).isoformat()
        self.agent.database.connection.execute(
            "UPDATE incidents SET first_seen = ? WHERE incident_id = ?",
            (old_day + "T23:59:59+00:00", old_incident),
        )
        self.agent.database.connection.commit()
        csrf = self.login()
        counts = self.client.get("/api/overview").get_json()
        self.assertEqual(counts["activity_timezone"], "UTC")
        self.assertEqual(sum(item["count"] for item in counts["activity"]), 1)
        self.assertEqual(counts["severity_counts"]["medium"], 2)
        alert = alerts[0]
        self.assertEqual(self.client.post(
            f"/api/alerts/{alert['alert_id']}/false-positive").status_code, 403)
        self.assertEqual(self.client.post(
            f"/api/alerts/{alert['alert_id']}/false-positive", headers=csrf).status_code, 200)
        counts = self.client.get("/api/overview").get_json()
        self.assertEqual(counts["severity_counts"]["medium"], 1)
        self.assertEqual(self.client.get("/api/alert-page?status=false_positive").get_json()["total"], 1)
        self.assertEqual(self.client.post(
            f"/api/alerts/{alert['alert_id']}/undo-false-positive", headers=csrf).status_code, 200)

    def test_incident_actions_remain_available(self):
        self.agent.ingest_event(HostEvent.create("console-host", "file_change", "fixture",
                                                 file_path="/etc/checked.conf", action="modify",
                                                 outcome="observed"))
        csrf = self.login()
        incident_id = self.client.get("/api/incident-page").get_json()["items"][0]["incident_id"]
        self.assertEqual(self.client.post(
            f"/api/incidents/{incident_id}/acknowledge", headers=csrf).status_code, 200)
        self.assertEqual(self.client.get("/api/incident-page?state=acknowledged").get_json()["total"], 1)
        self.assertEqual(self.client.post(
            f"/api/incidents/{incident_id}/resolve", headers=csrf).status_code, 200)
        self.assertEqual(self.client.get("/api/incident-page?state=resolved").get_json()["total"], 1)
        self.assertEqual(self.client.post(
            f"/api/incidents/{incident_id}/undo-state", headers=csrf).status_code, 200)
        self.assertEqual(self.client.get("/api/incident-page?state=acknowledged").get_json()["total"], 1)
