from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, redirect, render_template_string, request, session, url_for

from .agent import HostAgent


PAGE = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
LOGIN_PAGE = Path(__file__).with_name("login.html").read_text(encoding="utf-8")
CHANGE_PASSWORD_PAGE = Path(__file__).with_name("change_password.html").read_text(encoding="utf-8")
VALID_STATES = {"all", "new", "updated", "acknowledged", "resolved"}


def create_app(agent: HostAgent) -> Flask:
    app = Flask(__name__)
    app.secret_key = agent.database.session_secret()
    app.config.update(
        SESSION_COOKIE_NAME="rt_hid_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # dashboard is restricted to local HTTP loopback
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    failed_logins: dict[str, deque[float]] = defaultdict(deque)
    login_lock = threading.Lock()

    def logged_in() -> bool:
        version = agent.database.auth_version()
        return bool(version and session.get("admin_version") == version)

    def valid_csrf(token: str) -> bool:
        expected = session.get("csrf_token")
        return bool(expected and token and hmac.compare_digest(expected, token))

    @app.before_request
    def protect_resources():
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
        return render_template_string(LOGIN_PAGE, csrf_token=csrf_token, error=error,
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
        return render_template_string(CHANGE_PASSWORD_PAGE, csrf_token=session["csrf_token"],
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
        state = request.args.get("state", "all")
        if state not in VALID_STATES:
            abort(400, "invalid incident state")
        return jsonify(agent.database.page_incidents(
            limit=request.args.get("limit", 25, type=int),
            offset=request.args.get("offset", 0, type=int),
            state=state,
            query=request.args.get("q", ""),
        ))

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

    return app
