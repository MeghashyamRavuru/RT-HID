from __future__ import annotations

import json
import math
import re
from datetime import datetime
from dataclasses import fields
from functools import wraps

from flask import abort, jsonify, request, session

from .collectors.linux import _redact_command_line
from .identity import event_instance
from .models import HostEvent
from .detection.engine import HostDetectionEngine
from .maintenance import envelope


def validated(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        except KeyError:
            return jsonify({"error": "record not found"}), 404
    return call


def body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def pagination():
    try:
        limit, offset = int(request.args.get("limit", 25)), int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        raise ValueError("invalid pagination") from None
    if not 1 <= limit <= 100 or not 0 <= offset <= 1_000_000:
        raise ValueError("invalid pagination")
    return limit, offset


def sanitized_sample(value, depth=0):
    if depth > 4:
        return '<limited>'
    if isinstance(value,dict):
        return {str(key)[:128]: '<redacted>' if re.search(r'password|passwd|secret|token|credential|private.?key|environ',str(key),re.I)
                else sanitized_sample(item,depth+1) for key,item in list(value.items())[:50]}
    if isinstance(value,list):
        return [sanitized_sample(item,depth+1) for item in value[:100]]
    return value[:2048] if isinstance(value,str) else value


def register_advanced_routes(app, agent):
    @app.get("/api/processes/<event_id>/relationships")
    @validated
    def process_relationships(event_id):
        if len(event_id) > 128:
            raise ValueError("invalid event ID")
        with agent.database._lock:
            row = agent.database.connection.execute("SELECT payload FROM host_events WHERE event_id=?", (event_id,)).fetchone()
        if not row:
            abort(404, "event not found")
        event = HostEvent(**json.loads(row[0]))
        key = event_instance(event)
        if not key:
            return jsonify({"nodes": [], "children": [], "complete": False, "reason": "Creation time unavailable; identity cannot be verified."})
        return jsonify({**agent.processes.ancestry(key), "children": agent.processes.children(key)})

    @app.get("/api/rules")
    def rules():
        return jsonify({"items": agent.detector.registry.list()})

    @app.patch("/api/rules/<rule_id>")
    @validated
    def tune_rule(rule_id):
        with agent._ingest_lock:
            agent.detector.registry.update(rule_id, body())
        return jsonify({"status": "updated", "rule_id": rule_id})

    @app.post("/api/rules/test")
    @validated
    def test_rule():
        data = body()
        if set(data) - {item.name for item in fields(HostEvent)}:
            raise ValueError("unsupported event fields")
        for key,value in data.items():
            if key not in {'metadata','evidence','process_id','parent_process_id','destination_port'} and value is not None:
                if not isinstance(value,str) or len(value)>4096:
                    raise ValueError('invalid sample field type or length')
        for key in ('process_id','parent_process_id','destination_port'):
            if data.get(key) is not None and (type(data[key]) is not int or not 0 <= data[key] <= (65535 if key=='destination_port' else 2**31-1)):
                raise ValueError('invalid sample process ID or port')
        if 'timestamp' in data:
            try:
                datetime.fromisoformat(data['timestamp'].replace('Z','+00:00'))
            except (ValueError,AttributeError):
                raise ValueError('invalid sample timestamp') from None
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("invalid metadata")
        metadata = {key: value for key, value in metadata.items() if key in {
            "parent_name", "create_time", "parent_create_time", "executable_sha256", "destination_domain", "command_line"}}
        for key in ('parent_name','executable_sha256','destination_domain'):
            if metadata.get(key) is not None and (not isinstance(metadata[key],str) or len(metadata[key])>2048):
                raise ValueError('invalid sample metadata')
        for key in ('create_time','parent_create_time'):
            if metadata.get(key) is not None:
                try:
                    if isinstance(metadata[key],bool) or not math.isfinite(float(metadata[key])) or float(metadata[key])<=0:
                        raise ValueError()
                except (TypeError,ValueError,OverflowError):
                    raise ValueError('invalid sample creation time') from None
        arguments = metadata.get("command_line")
        if arguments is not None:
            if not isinstance(arguments, list) or len(arguments) > 64 or any(not isinstance(arg, str) for arg in arguments):
                raise ValueError("invalid command line")
            metadata["command_line"] = _redact_command_line(arguments, 2048)
        data["metadata"] = metadata
        if not isinstance(data.get('evidence',{}),dict):
            raise ValueError('invalid sample evidence')
        data['evidence'] = sanitized_sample(data.get('evidence',{}))
        data.pop("event_id", None)
        data.pop("host_id", None)
        data.pop("source", None)
        kind = data.pop("event_type", None)
        if not isinstance(kind, str):
            raise ValueError("event_type required")
        event = HostEvent.create(agent.config.host_id, kind, "rule_test", **data)
        engine = HostDetectionEngine(agent.config)
        engine.registry.settings = dict(agent.detector.registry.settings)
        return jsonify({"detections": [item.to_dict() for item in engine.evaluate(event)], "persisted": False})

    @app.get("/api/mitre/coverage")
    def coverage():
        return jsonify(agent.detector.registry.coverage())

    @app.get("/api/intelligence")
    @validated
    def intelligence_page():
        return jsonify(agent.intelligence.page(*pagination()))

    @app.post("/api/intelligence/import")
    @validated
    def import_intelligence():
        data = body()
        if set(data) - {"format", "content"}:
            raise ValueError("unsupported import fields")
        return jsonify(agent.intelligence.import_data(data.get("content"), data.get("format", "json")))

    @app.patch("/api/intelligence/<indicator_id>")
    @validated
    def change_indicator(indicator_id):
        data = body()
        if set(data) != {"enabled"}:
            raise ValueError("only enabled can be changed")
        agent.intelligence.set_enabled(indicator_id, data["enabled"])
        return jsonify({"status": "updated"})

    @app.delete("/api/intelligence/<indicator_id>")
    @validated
    def remove_indicator(indicator_id):
        agent.intelligence.remove(indicator_id)
        return jsonify({"status": "removed"})

    @app.get('/api/scans/status')
    def scans_status():
        return jsonify(agent.scanner.status())

    @app.post('/api/scans')
    @validated
    def start_scan():
        data = body()
        if set(data) != {'path'}:
            raise ValueError('path required')
        return jsonify({'job_id':agent.scanner.submit(data['path'])}),202

    @app.get('/api/jobs')
    @validated
    def jobs():
        return jsonify(agent.jobs.page(*pagination()))

    @app.post('/api/jobs/<job_id>/cancel')
    @validated
    def cancel_job(job_id):
        agent.jobs.cancel(job_id)
        return jsonify({'status':'cancellation requested'})

    @app.get('/api/response/status')
    def response_status():
        return jsonify(agent.response.status())

    @app.get('/api/response/history')
    @validated
    def response_history():
        return jsonify(agent.audit.page(*pagination()))

    @app.post('/api/response/prepare')
    @validated
    def prepare_response():
        try:
            return jsonify(agent.response.prepare(body(),session['admin_version']))
        except PermissionError as error:
            return jsonify({'error':str(error)}),403

    @app.post('/api/response/execute')
    @validated
    def execute_response():
        try:
            return jsonify(agent.response.execute(body(),session['admin_version']))
        except PermissionError as error:
            return jsonify({'error':str(error)}),403

    @app.get('/api/maintenance/status')
    def maintenance_status():
        return jsonify(agent.maintenance.status())

    @app.post('/api/maintenance/<action>')
    @validated
    def maintenance_action(action):
        handlers = {'backup':agent.maintenance.backup,'integrity':agent.maintenance.integrity,'retention':agent.maintenance.retention}
        if action not in handlers:
            raise ValueError('unsupported maintenance action')
        if action == 'retention':
            data = body()
            if data.get('confirm') is not True or not agent.database.verify_admin_password(data.get('password','')):
                agent.audit.append('retention','policy','denied','confirmation or administrator verification failed')
                return jsonify({'error':'confirmation and administrator password required'}),403
            if not agent.config.retention_enabled:
                raise ValueError('retention disabled in host configuration')
        return jsonify({'job_id':agent.jobs.submit(action,action,handlers[action])}),202

    @app.get('/api/incidents/<incident_id>/integrity-export')
    def integrity_export(incident_id):
        bundle = agent.database.get_incident_detail(incident_id)
        if bundle is None:
            abort(404,'incident not found')
        agent.audit.append('evidence_export',incident_id,'completed')
        return jsonify(envelope(bundle))
