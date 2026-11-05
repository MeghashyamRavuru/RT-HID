from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, abort, jsonify, request

from .agent import HostAgent


PAGE = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
VALID_STATES = {"all", "new", "updated", "acknowledged", "resolved"}


def create_app(agent: HostAgent) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return Response(PAGE, mimetype="text/html")

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

    @app.post("/api/alerts/<alert_id>/false-positive")
    def false_positive(alert_id: str):
        try:
            agent.alerts.false_positive(alert_id)
        except KeyError:
            abort(404, "alert not found")
        return jsonify({"status": "false_positive", "alert_id": alert_id})

    return app
