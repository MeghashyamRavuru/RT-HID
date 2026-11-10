from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone

from .models import Detection, SEVERITIES, utc_now


_STIX_PATTERN = re.compile(
    r"\[\s*(ipv4-addr:value|ipv6-addr:value|domain-name:value|file:hashes\.'SHA-256')\s*=\s*'([^'\\]{1,512})'\s*\]",
    re.IGNORECASE)


def _stix_records(bundle):
    if bundle.get('type') != 'bundle' or bundle.get('spec_version') != '2.1':
        raise ValueError('expected a STIX 2.1 bundle')
    objects = bundle.get('objects')
    if not isinstance(objects, list) or not 1 <= len(objects) <= 5000:
        raise ValueError('expected 1 to 5000 STIX objects')
    records = []
    kinds = {'ipv4-addr:value': 'ipv4', 'ipv6-addr:value': 'ipv6',
             'domain-name:value': 'domain', "file:hashes.'sha-256'": 'sha256'}
    for item in objects:
        if not isinstance(item, dict):
            raise ValueError('invalid STIX object')
        if item.get('type') != 'indicator':
            continue
        if item.get('spec_version') != '2.1' or item.get('pattern_type') != 'stix':
            raise ValueError('unsupported STIX indicator version or pattern type')
        stix_id = item.get('id')
        if not isinstance(stix_id, str) or not re.fullmatch(
            r'indicator--[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', stix_id):
            raise ValueError('invalid STIX indicator ID')
        if not item.get('valid_from'):
            raise ValueError('STIX indicator valid_from is required')
        pattern = item.get('pattern')
        match = _STIX_PATTERN.fullmatch(pattern) if isinstance(pattern, str) else None
        if match is None:
            raise ValueError('unsupported STIX pattern; use one exact IP, domain or SHA-256 comparison')
        confidence = item.get('confidence', 50)
        if type(confidence) is not int or not 0 <= confidence <= 100:
            raise ValueError('STIX confidence must be an integer from 0 to 100')
        name, description = item.get('name', ''), item.get('description', '')
        if not isinstance(name, str) or not isinstance(description, str):
            raise ValueError('invalid STIX indicator name or description')
        details = ': '.join(part for part in (name, description) if part)
        tags = item.get('indicator_types', [])
        if not isinstance(tags, list):
            raise ValueError('invalid STIX indicator types')
        enabled = item.get('revoked', False)
        if not isinstance(enabled, bool):
            raise ValueError('invalid STIX revoked flag')
        records.append({'type': kinds[match.group(1).lower()], 'value': match.group(2),
                        'source': 'STIX ' + stix_id, 'description': details,
                        'confidence': confidence / 100, 'tags': tags,
                        'first_seen': item.get('created'), 'last_seen': item.get('modified'),
                        'valid_from': item.get('valid_from'), 'expires_at': item.get('valid_until'),
                        'enabled': not enabled})
    if not records:
        raise ValueError('STIX bundle has no supported indicators')
    return records


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
        if format == 'json' and isinstance(records, dict):
            records = _stix_records(records)
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
        if not isinstance(record, dict) or set(record) - {"type", "value", "source", "description", "confidence", "severity", "first_seen", "last_seen", "valid_from", "expires_at", "tags", "enabled"}:
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
        for key in ('first_seen', 'last_seen', 'valid_from', 'expires_at'):
            value_date = record.get(key)
            try:
                parsed = datetime.fromisoformat(value_date.replace('Z', '+00:00')) if value_date else None
                if parsed and parsed.tzinfo is None:
                    raise ValueError()
                dates[key] = parsed.astimezone(timezone.utc).isoformat() if parsed else None
            except (ValueError, AttributeError, TypeError):
                raise ValueError("IOC dates must include a timezone") from None
        if dates['valid_from'] and dates['expires_at'] and dates['expires_at'] <= dates['valid_from']:
            raise ValueError('IOC expiry must follow valid_from')
        return {'indicator_id': uuid.uuid4().hex, 'type': kind, 'value': value, 'source': source, 'description': description,
            'confidence': confidence, 'severity': severity, 'enabled': enabled, 'tags': tags,
            'first_seen': dates['first_seen'] or utc_now(), 'last_seen': dates['last_seen'] or utc_now(),
            'valid_from': dates['valid_from'], 'expires_at': dates['expires_at']}

    def page(self, limit, offset):
        with self.database._lock:
            total = self.database.connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            rows = self.database.connection.execute("SELECT payload FROM indicators ORDER BY type,value LIMIT ? OFFSET ?", (limit,offset)).fetchall()
        now = utc_now()
        items = []
        for row in rows:
            item = json.loads(row[0])
            items.append({**item, 'expired': bool(item.get('expires_at') and item['expires_at'] <= now),
                          'not_yet_valid': bool(item.get('valid_from') and item['valid_from'] > now)})
        return {"items": items, "total": total, "limit": limit, "offset": offset, "matching_enabled": self.config.threat_intelligence_enabled}

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
                now = utc_now()
                row = self.database.connection.execute("SELECT payload FROM indicators WHERE type=? AND value=? AND enabled=1 AND (expires_at IS NULL OR expires_at>?)", (kind, value, now)).fetchone()
                if row:
                    indicator = json.loads(row[0])
                    if not indicator.get('valid_from') or indicator['valid_from'] <= now:
                        matches.append(indicator)
        if not matches:
            return []
        ranking = {key: index for index, key in enumerate(("informational", "low", "medium", "high", "critical"))}
        return [Detection.create(rule_id="HIDS-IOC-001", rule_name="Local threat indicator match", category="threat_intelligence",
            tactic="Command and Control", technique_id=None, severity=max(matches, key=lambda item: ranking[item['severity']])['severity'],
            confidence=max(item['confidence'] for item in matches), timestamp=event.timestamp,
            event_ids=(event.event_id,), reason="Observed telemetry matches enabled local indicators; assess source reliability",
            evidence={"indicators": matches, "process_name": event.process_name},
            investigation="Assess indicator source reliability, age, confidence and observed behavior. A match alone does not confirm compromise.", host_id=event.host_id)]
