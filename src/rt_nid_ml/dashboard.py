from __future__ import annotations

import argparse
import threading
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, render_template_string


class AlertStore:
    def __init__(self, max_alerts: int = 500) -> None:
        self._alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self._lock = threading.Lock()
        self._started_at = datetime.now(timezone.utc)
        self._packet_count = 0

    def record_alert(self, alert: dict[str, Any]) -> None:
        with self._lock:
            self._alerts.append(dict(alert))

    def record_packet(self) -> None:
        with self._lock:
            self._packet_count += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            alerts = list(reversed(self._alerts))
            counts = Counter(alert["alert_type"] for alert in alerts)
            return {
                "alerts": alerts,
                "alert_count": len(alerts),
                "packet_count": self._packet_count,
                "attack_counts": dict(counts),
                "started_at": self._started_at.isoformat(),
            }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RT-NID-ML Dashboard</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #10161d; color: #e8edf2; }
body { max-width: 1100px; margin: 0 auto; padding: 32px 20px; }
h1 { margin-bottom: 6px; } .muted { color: #8e9ba8; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 24px 0; }
.card { border: 1px solid #2c3945; background: #17212b; padding: 18px; border-radius: 6px; }
.value { display:block; font-size: 30px; font-weight: 700; margin-top: 6px; }
table { width: 100%; border-collapse: collapse; } th, td { text-align:left; padding: 12px 8px; border-bottom: 1px solid #2c3945; }
.badge { color: #ffb4a2; font-weight: 700; } @media (max-width: 650px) { .grid { grid-template-columns: 1fr; } }
</style></head><body>
<h1>Network Detection</h1><div class="muted">Live flow alerts from the RT-NID-ML sensor</div>
<div class="grid"><div class="card">Packets<span class="value" id="packets">0</span></div>
<div class="card">Alerts<span class="value" id="alerts">0</span></div>
<div class="card">Top attack<span class="value" id="top">-</span></div></div>
<div class="card"><table><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Score</th></tr></thead><tbody id="rows"></tbody></table></div>
<script>
async function refresh() { const data = await fetch('/api/summary').then(r => r.json());
 document.querySelector('#packets').textContent = data.packet_count;
 document.querySelector('#alerts').textContent = data.alert_count;
 const top = Object.entries(data.attack_counts).sort((a,b) => b[1]-a[1])[0];
 document.querySelector('#top').textContent = top ? top[0] : '-';
 document.querySelector('#rows').innerHTML = data.alerts.map(a => `<tr><td>${new Date(a.timestamp * 1000).toLocaleTimeString()}</td><td>${a.source_ip}</td><td class="badge">${a.alert_type}</td><td>${a.score}</td></tr>`).join(''); }
refresh(); setInterval(refresh, 2000);
</script></body></html>"""


def create_app(store: AlertStore | None = None) -> Flask:
    store = store or AlertStore()
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return render_template_string(PAGE)

    @app.get("/api/summary")
    def summary() -> Any:
        return jsonify(store.snapshot())

    app.config["ALERT_STORE"] = store
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RT-NID-ML alert dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
