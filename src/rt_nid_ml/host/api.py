from __future__ import annotations

from flask import Flask, jsonify, render_template_string, request

from .agent import HostAgent

PAGE = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RT-NID-ML Host Security</title><style>body{font-family:system-ui;background:#10161d;color:#e8edf2;max-width:1100px;margin:auto;padding:28px}h1{margin-bottom:4px}.muted{color:#93a1ad}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.card{background:#17212b;border:1px solid #33414d;border-radius:6px;padding:18px}.value{display:block;font-size:28px;font-weight:700;margin-top:8px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:11px 8px;border-bottom:1px solid #33414d}.high,.critical{color:#ff9e91}.medium{color:#ffd27d}.low{color:#8ed6ff}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}} </style></head><body><h1>Host Security</h1><div class='muted' id='host'>Loading host status...</div><div class='grid'><div class='card'>Alerts<span class='value' id='count'>0</span></div><div class='card'>Critical<span class='value' id='critical'>0</span></div><div class='card'>Incidents<span class='value' id='incidents'>0</span></div><div class='card'>Collectors<span class='value' id='collectors'>0</span></div></div><div class='card'><table><thead><tr><th>Time</th><th>Severity</th><th>Title</th><th>Category</th><th>State</th></tr></thead><tbody id='rows'></tbody></table></div><script>async function refresh(){const [s,a,i]=await Promise.all([fetch('/api/status').then(r=>r.json()),fetch('/api/alerts').then(r=>r.json()),fetch('/api/incidents').then(r=>r.json())]);document.querySelector('#host').textContent=(s.platform.system||'unknown')+' '+(s.platform.release||'')+' | '+s.host_id;document.querySelector('#count').textContent=a.length;document.querySelector('#critical').textContent=a.filter(x=>['critical','high'].includes(x.severity)).length;document.querySelector('#incidents').textContent=i.length;document.querySelector('#collectors').textContent=s.collectors.length;document.querySelector('#rows').innerHTML=a.map(x=>`<tr><td>${x.last_seen}</td><td class='${x.severity}'>${x.severity}</td><td>${x.title}</td><td>${x.category}</td><td>${x.status}</td></tr>`).join('')}refresh();setInterval(refresh,3000)</script></body></html>"""


def create_app(agent: HostAgent) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template_string(PAGE)

    @app.get("/api/status")
    def status():
        return jsonify(agent.status())

    @app.get("/api/alerts")
    def alerts():
        return jsonify(agent.database.list_alerts(int(request.args.get("limit", 100))))

    @app.get("/api/incidents")
    def incidents():
        return jsonify(agent.database.list_incidents(int(request.args.get("limit", 100))))

    @app.post("/api/incidents/<incident_id>/acknowledge")
    def acknowledge(incident_id: str):
        agent.alerts.acknowledge(incident_id)
        return jsonify({"status": "acknowledged", "incident_id": incident_id})

    @app.post("/api/incidents/<incident_id>/resolve")
    def resolve(incident_id: str):
        agent.alerts.resolve(incident_id)
        return jsonify({"status": "resolved", "incident_id": incident_id})

    @app.post("/api/alerts/<alert_id>/false-positive")
    def false_positive(alert_id: str):
        agent.alerts.false_positive(alert_id)
        return jsonify({"status": "false_positive", "alert_id": alert_id})

    return app
