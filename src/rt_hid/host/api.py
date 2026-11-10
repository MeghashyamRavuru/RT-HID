from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException

from .agent import HostAgent
from .advanced_api import register_advanced_routes
from . import AGENT_VERSION


PAGE = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
LOGIN_PAGE = Path(__file__).with_name("login.html").read_text(encoding="utf-8")
CHANGE_PASSWORD_PAGE = Path(__file__).with_name("change_password.html").read_text(encoding="utf-8")
VALID_STATES = {"all", "open", "new", "updated", "acknowledged", "resolved"}
VALID_SEVERITIES = {"all", "priority", "informational", "low", "medium", "high", "critical"}
VALID_ALERT_STATUSES = {"all", "active", "new", "acknowledged", "resolved", "false_positive"}
EVENT_KINDS = {
    "process": ("process_start", "process_stop"),
    "network": ("network_listen", "network_connection"),
    "file": ("file_change",),
    "persistence": ("persistence_change",),
}
EVENT_ACTIONS = {
    "process": {"all", "start", "stop"},
    "network": {"all", "listen", "connect"},
    "file": {"all", "modify", "delete", "create", "permission_change"},
    "persistence": {"all", "modify", "delete", "create"},
}


def create_app(agent: HostAgent) -> Flask:
    app = Flask(__name__)
    app.secret_key = agent.database.session_secret()
    app.config.update(
        SESSION_COOKIE_NAME="rt_hid_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # dashboard is restricted to local HTTP loopback
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    failed_logins: dict[str, deque[float]] = defaultdict(deque)
    login_lock = threading.Lock()

    def logged_in() -> bool:
        version = agent.database.auth_version()
        return bool(version and session.get("admin_version") == version)

    def valid_csrf(token: str) -> bool:
        expected = session.get("csrf_token")
        return bool(expected and token and hmac.compare_digest(expected, token))

    def page_parameters() -> tuple[int, int, str, str]:
        try:
            limit = int(request.args.get("limit", "25"))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            abort(400, "invalid pagination")
        if not 1 <= limit <= 100 or not 0 <= offset <= 1_000_000:
            abort(400, "invalid pagination")
        order = request.args.get("order", "newest")
        if order not in {"newest", "oldest"}:
            abort(400, "invalid sort order")
        query = request.args.get("q", "").strip()
        if len(query) > 100:
            abort(400, "search query is too long")
        return limit, offset, order, query

    def page_since() -> str | None:
        window = request.args.get("since", "all")
        if window == "all":
            return None
        hours = {"24h": 24, "7d": 168, "30d": 720}.get(window)
        if hours is None:
            abort(400, "invalid time window")
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    @app.errorhandler(HTTPException)
    def api_errors(error: HTTPException):
        if request.path.startswith("/api/"):
            return jsonify({"error": error.description}), error.code
        return error

    @app.before_request
    def protect_resources():
        g.audit_actor = 'admin' if logged_in() else 'anonymous'
        if request.endpoint == "login":
            return None
        if request.endpoint == "change_password":
            if session.get("pending_password_change") and not agent.database.has_admin_password():
                return None
            session.clear()
            return redirect(url_for("login"))
        if session.get("pending_password_change") and not agent.database.has_admin_password():
            if request.path.startswith("/api/") or request.method != "GET":
                return jsonify({"error": "password change required"}), 403
            return redirect(url_for("change_password"))
        if not logged_in():
            session.clear()
            if request.path.startswith("/api/") or request.method != "GET":
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login"))
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not valid_csrf(request.headers.get("X-CSRF-Token", "")):
                return jsonify({"error": "invalid CSRF token"}), 403
        return None

    @app.after_request
    def security_headers(response):
        if request.method in {'POST','PUT','PATCH','DELETE'} and request.path.startswith('/api/'):
            agent.audit.append('http_write',request.path,str(response.status_code),actor=getattr(g,'audit_actor','anonymous'))
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        nonce = getattr(g, "script_nonce", None)
        policy = (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
            "connect-src 'self'; style-src 'self' 'unsafe-inline'; "
        )
        response.headers["Content-Security-Policy"] = policy + (
            f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
        )
        return response

    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error':'internal server error; check local application logs'}),500
        return error

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET" and logged_in():
            return redirect(url_for("index"))
        if request.method == "GET" and session.get("pending_password_change") and not agent.database.has_admin_password():
            return redirect(url_for("change_password"))
        first_login = not agent.database.has_admin_password()
        csrf_token = session.get("csrf_token") or secrets.token_urlsafe(32)
        session["csrf_token"] = csrf_token
        error = None
        if request.method == "POST":
            if not valid_csrf(request.form.get("csrf_token", "")):
                abort(403)
            address = request.remote_addr or "local"
            now = time.monotonic()
            with login_lock:
                attempts = failed_logins[address]
                while attempts and attempts[0] < now - 300:
                    attempts.popleft()
                blocked = len(attempts) >= 5
            if blocked:
                error = "Too many attempts. Try again in a few minutes."
            elif (request.form.get("username") == "admin" and
                  ((first_login and hmac.compare_digest(request.form.get("password", ""), "admin")) or
                   (not first_login and agent.database.verify_admin_password(request.form.get("password", ""))))):
                with login_lock:
                    failed_logins.pop(address, None)
                session.clear()
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                if first_login:
                    session["pending_password_change"] = True
                    return redirect(url_for("change_password"))
                session["admin_version"] = agent.database.auth_version()
                return redirect(url_for("index"))
            else:
                with login_lock:
                    failed_logins[address].append(now)
                error = "Incorrect password."
        g.script_nonce = secrets.token_urlsafe(24)
        login_html = LOGIN_PAGE.replace("<script>", f'<script nonce="{g.script_nonce}">')
        return render_template_string(login_html, csrf_token=csrf_token, error=error,
                                      first_login=first_login), (401 if error else 200)

    @app.route("/change-password", methods=["GET", "POST"])
    def change_password():
        error = None
        if request.method == "POST":
            if not valid_csrf(request.form.get("csrf_token", "")):
                abort(403)
            password = request.form.get("password", "")
            if password != request.form.get("confirmation", ""):
                error = "Passwords do not match."
            elif password == "admin":
                error = "Choose a password different from the default."
            else:
                try:
                    if not agent.database.initialize_admin_password(password):
                        session.clear()
                        return redirect(url_for("login"))
                except ValueError as exc:
                    error = str(exc)
                else:
                    session.clear()
                    session["admin_version"] = agent.database.auth_version()
                    session["csrf_token"] = secrets.token_urlsafe(32)
                    session.permanent = True
                    return redirect(url_for("index"))
        g.script_nonce = secrets.token_urlsafe(24)
        password_html = CHANGE_PASSWORD_PAGE.replace("<script>", f'<script nonce="{g.script_nonce}">')
        return render_template_string(password_html, csrf_token=session["csrf_token"],
                                      error=error), (400 if error else 200)

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify({"status": "signed_out"})

    @app.get("/api/session")
    def session_info():
        return jsonify({"username": "admin", "csrf_token": session["csrf_token"]})

    @app.get("/")
    def index() -> Response:
        g.script_nonce = secrets.token_urlsafe(24)
        return Response(PAGE.replace("<script>", f'<script nonce="{g.script_nonce}">'), mimetype="text/html")

    @app.get("/api/status")
    def status():
        return jsonify(agent.status())

    @app.get("/api/overview")
    def overview():
        return jsonify(agent.database.incident_counts())

    @app.get("/api/alerts")
    def alerts():
        return jsonify(agent.database.list_alerts(request.args.get("limit", 100, type=int)))

    @app.get("/api/incidents")
    def incidents():
        return jsonify(agent.database.list_incidents(request.args.get("limit", 100, type=int)))

    @app.get("/api/incident-page")
    def incident_page():
        limit, offset, order, query = page_parameters()
        state = request.args.get("state", "all")
        if state not in VALID_STATES:
            abort(400, "invalid incident state")
        severity = request.args.get("severity", "all")
        if severity not in VALID_SEVERITIES:
            abort(400, "invalid severity")
        return jsonify(agent.database.page_incidents(
            limit=limit, offset=offset,
            state=state,
            severity=severity, order=order, query=query, since=page_since(),
        ))

    @app.get("/api/alert-page")
    def alert_page():
        limit, offset, order, query = page_parameters()
        severity = request.args.get("severity", "all")
        alert_status = request.args.get("status", "all")
        rule = request.args.get("rule", "").strip()
        if severity not in VALID_SEVERITIES or alert_status not in VALID_ALERT_STATUSES or len(rule) > 100:
            abort(400, "invalid alert filter")
        return jsonify(agent.database.page_alerts(
            limit=limit, offset=offset, order=order, query=query,
            severity=severity, status=alert_status, rule=rule, since=page_since(),
        ))

    @app.get("/api/event-page")
    def event_page():
        limit, offset, order, query = page_parameters()
        kind = request.args.get("kind", "")
        action = request.args.get("action", "all")
        if kind not in EVENT_KINDS or action not in EVENT_ACTIONS[kind]:
            abort(400, "invalid event filter")
        return jsonify(agent.database.page_events(
            event_types=EVENT_KINDS[kind], limit=limit, offset=offset,
            query=query, action=action, order=order, since=page_since(),
        ))

    @app.get("/api/settings")
    def settings():
        return jsonify({
            "version": AGENT_VERSION,
            "host_id": agent.config.host_id,
            "platform": agent.capabilities.__dict__,
            "database_path": str(agent.config.database_path),
            "enabled_collectors": sorted(agent.config.enabled_collectors),
            "process_interval_seconds": agent.config.process_interval_seconds,
            "executable_hashing_enabled": agent.config.executable_hashing_enabled,
            "monitored_paths": [str(path) for path in agent.config.monitored_paths],
            "dashboard_host": agent.config.dashboard_host,
            "persistence_enabled":agent.config.persistence_enabled,
            "persistence_paths":[str(path) for path in agent.config.persistence_paths],
            "threat_intelligence_enabled":agent.config.threat_intelligence_enabled,
            "response_enabled":agent.config.response_enabled,
            "retention_enabled":agent.config.retention_enabled,
            "retention_days":agent.config.retention_days,
            "network_destination_allowlist":agent.config.network_destination_allowlist,
        })

    @app.get("/api/incidents/<incident_id>")
    def incident_detail(incident_id: str):
        detail = agent.database.get_incident_detail(incident_id)
        if detail is None:
            abort(404, "incident not found")
        return jsonify(detail)

    @app.post("/api/incidents/<incident_id>/notes")
    def add_note(incident_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("body"), str):
            abort(400, "note body is required")
        try:
            note = agent.database.add_incident_note(incident_id, payload["body"])
        except ValueError as error:
            abort(400, str(error))
        except KeyError:
            abort(404, "incident not found")
        return jsonify(note), 201

    @app.post("/api/incidents/<incident_id>/acknowledge")
    def acknowledge(incident_id: str):
        try:
            agent.alerts.acknowledge(incident_id)
        except KeyError:
            abort(404, "incident not found")
        return jsonify({"status": "acknowledged", "incident_id": incident_id})

    @app.post("/api/incidents/<incident_id>/resolve")
    def resolve(incident_id: str):
        try:
            agent.alerts.resolve(incident_id)
        except KeyError:
            abort(404, "incident not found")
        return jsonify({"status": "resolved", "incident_id": incident_id})

    @app.post("/api/incidents/<incident_id>/undo-state")
    def undo_incident_state(incident_id: str):
        try:
            restored = agent.database.undo_incident_state(incident_id)
        except KeyError:
            abort(404, "incident not found")
        except ValueError as error:
            abort(409, str(error))
        return jsonify({"status": restored, "incident_id": incident_id})

    @app.post("/api/alerts/<alert_id>/false-positive")
    def false_positive(alert_id: str):
        try:
            agent.alerts.false_positive(alert_id)
        except KeyError:
            abort(404, "alert not found")
        return jsonify({"status": "false_positive", "alert_id": alert_id})

    @app.post("/api/alerts/<alert_id>/undo-false-positive")
    def undo_false_positive(alert_id: str):
        try:
            restored = agent.database.undo_alert_status(alert_id)
        except KeyError:
            abort(404, "alert not found")
        except ValueError as error:
            abort(409, str(error))
        return jsonify({"status": restored, "alert_id": alert_id})

    register_advanced_routes(app, agent)
    return app
