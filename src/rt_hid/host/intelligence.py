from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone

from .models import Detection, SEVERITIES, utc_now


def normalize(kind, value):
    if not isinstance(kind,str) or not isinstance(value, str) or len(value) > 512:
        raise ValueError("invalid indicator value")
    value = value.strip()
    if kind == "sha256" and re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return kind, value.lower()
    if kind in {"ip", "ipv4", "ipv6"}:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("invalid IP indicator") from None
        if (kind == "ipv4" and ip.version != 4) or (kind == "ipv6" and ip.version != 6):
            raise ValueError("IP version mismatch")
        return "ip", ip.compressed
    if kind == "domain":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError('domain indicator must not be an IP address')
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("invalid domain") from None
        if len(value) <= 253 and "." in value and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
            return kind, value
    raise ValueError("invalid IOC type or value")


class Intelligence:
    def __init__(self, database, config):
        self.database, self.config = database, config

    def import_data(self, text, format="json"):
        if not isinstance(text, str) or len(text.encode("utf-8")) > 1024 * 1024:
            raise ValueError("IOC import exceeds 1 MiB")
        if not isinstance(format,str) or format not in {"json", "csv"}:
            raise ValueError("format must be json or csv")
        try:
            records = json.loads(text) if format == "json" else list(csv.DictReader(io.StringIO(text)))
        except (ValueError, csv.Error):
            raise ValueError("invalid IOC import") from None
        if not isinstance(records, list) or not 1 <= len(records) <= 5000:
            raise ValueError("expected 1 to 5000 IOC records")
        normalized = [self.validate(record) for record in records]
        with self.database._lock, self.database.connection:
            for record in normalized:
                existing = self.database.connection.execute("SELECT payload FROM indicators WHERE type=? AND value=?", (record['type'], record['value'])).fetchone()
                if existing:
                    previous = json.loads(existing[0])
                    record.update(indicator_id=previous['indicator_id'], first_seen=previous['first_seen'])
                self.database.connection.execute("INSERT INTO indicators VALUES (?,?,?,?,?,?) ON CONFLICT(type,value) DO UPDATE SET enabled=excluded.enabled,expires_at=excluded.expires_at,payload=excluded.payload",
                    (record['indicator_id'], record['type'], record['value'], int(record['enabled']), record['expires_at'], json.dumps(record)))
        return {"imported": len(normalized), "unique": len({(r['type'], r['value']) for r in normalized})}

    def validate(self, record):
        if not isinstance(record, dict) or set(record) - {"type", "value", "source", "description", "confidence", "severity", "first_seen", "last_seen", "expires_at", "tags", "enabled"}:
            raise ValueError("unsupported indicator fields")
        kind, value = normalize(record.get('type'), record.get('value'))
        source = record.get('source', 'local')
        description = record.get('description', '')
        if not isinstance(source, str) or not 1 <= len(source) <= 128 or not isinstance(description, str) or len(description) > 512:
            raise ValueError("invalid indicator source or description")
        confidence = record.get('confidence', .5)
        if isinstance(confidence, bool):
            raise ValueError("invalid IOC confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            raise ValueError("invalid IOC confidence") from None
        if not 0 <= confidence <= 1:
            raise ValueError("invalid IOC confidence")
        severity = record.get('severity', 'medium')
        if not isinstance(severity,str) or severity not in SEVERITIES:
            raise ValueError("invalid IOC severity")
        enabled = record.get('enabled', True)
        if enabled in ('true', 'false'):
            enabled = enabled == 'true'
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        tags = record.get('tags', [])
        if isinstance(tags, str):
            tags = tags.split(';') if tags else []
        if not isinstance(tags, list) or len(tags) > 16 or any(not isinstance(tag, str) or len(tag) > 64 for tag in tags):
            raise ValueError("invalid IOC tags")
        dates = {}
        for key in ('first_seen', 'last_seen', 'expires_at'):
            value_date = record.get(key)
            try:
                parsed = datetime.fromisoformat(value_date.replace('Z', '+00:00')) if value_date else None
                if parsed and parsed.tzinfo is None:
                    raise ValueError()
                dates[key] = parsed.astimezone(timezone.utc).isoformat() if parsed else None
            except (ValueError, AttributeError, TypeError):
                raise ValueError("IOC dates must include a timezone") from None
        return {'indicator_id': uuid.uuid4().hex, 'type': kind, 'value': value, 'source': source, 'description': description,
            'confidence': confidence, 'severity': severity, 'enabled': enabled, 'tags': tags,
            'first_seen': dates['first_seen'] or utc_now(), 'last_seen': dates['last_seen'] or utc_now(), 'expires_at': dates['expires_at']}

    def page(self, limit, offset):
        with self.database._lock:
            total = self.database.connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            rows = self.database.connection.execute("SELECT payload FROM indicators ORDER BY type,value LIMIT ? OFFSET ?", (limit,offset)).fetchall()
        now = utc_now()
        return {"items": [{**json.loads(row[0]), "expired": bool(json.loads(row[0]).get('expires_at') and json.loads(row[0])['expires_at'] <= now)} for row in rows], "total": total, "limit": limit, "offset": offset, "matching_enabled": self.config.threat_intelligence_enabled}

    def set_enabled(self, key, enabled):
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        with self.database._lock, self.database.connection:
            row = self.database.connection.execute("SELECT payload FROM indicators WHERE indicator_id=?", (key,)).fetchone()
            if not row:
                raise KeyError(key)
            record = json.loads(row[0]); record['enabled'] = enabled
            self.database.connection.execute("UPDATE indicators SET enabled=?,payload=? WHERE indicator_id=?", (int(enabled), json.dumps(record), key))

    def remove(self, key):
        with self.database._lock, self.database.connection:
            if not self.database.connection.execute("DELETE FROM indicators WHERE indicator_id=?", (key,)).rowcount:
                raise KeyError(key)

    def match(self, event):
        if not self.config.threat_intelligence_enabled:
            return []
        candidates = [('sha256', event.metadata.get('executable_sha256'))] if event.event_type == 'process_start' else []
        if event.event_type == 'network_connection':
            candidates += [('ip', event.destination_ip), ('domain', event.metadata.get('destination_domain'))]
        matches = []
        with self.database._lock:
            for kind, value in candidates:
                if not value:
                    continue
                try:
                    kind, value = normalize(kind, value)
                except ValueError:
                    continue
                row = self.database.connection.execute("SELECT payload FROM indicators WHERE type=? AND value=? AND enabled=1 AND (expires_at IS NULL OR expires_at>?)", (kind, value, utc_now())).fetchone()
                if row:
                    matches.append(json.loads(row[0]))
        if not matches:
            return []
        ranking = {key: index for index, key in enumerate(("informational", "low", "medium", "high", "critical"))}
        return [Detection.create(rule_id="HIDS-IOC-001", rule_name="Local threat indicator match", category="threat_intelligence",
            tactic="Command and Control", technique_id=None, severity=max(matches, key=lambda item: ranking[item['severity']])['severity'],
            confidence=max(item['confidence'] for item in matches), timestamp=event.timestamp,
            event_ids=(event.event_id,), reason="Observed telemetry matches enabled local indicators; assess source reliability",
            evidence={"indicators": matches, "process_name": event.process_name},
            investigation="Assess indicator source reliability, age, confidence and observed behavior. A match alone does not confirm compromise.", host_id=event.host_id)]
