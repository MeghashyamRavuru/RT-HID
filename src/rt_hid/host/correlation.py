from __future__ import annotations

import json
from datetime import datetime, timedelta

from .identity import event_instance, normalized_path
from .models import Detection
from .detection.registry import RULES
from .detection.persistence_rules import privileged_group


class Correlator:
    def __init__(self, database, config):
        self.database, self.config = database, config

    def evaluate(self, event, current):
        now = datetime.fromisoformat(event.timestamp.replace('Z','+00:00'))
        cutoff = (now - timedelta(seconds=self.config.correlation_window_seconds)).isoformat()
        with self.database._lock:
            rows = self.database.connection.execute(
                "SELECT detections.payload FROM detections WHERE host_id=? AND julianday(timestamp)>=julianday(?) "
                "AND julianday(timestamp)<=julianday(?) AND category!='correlation' "
                "AND NOT EXISTS(SELECT 1 FROM alerts WHERE json_extract(alerts.payload,'$.detection_id')=detections.detection_id AND status='false_positive') "
                "ORDER BY timestamp DESC LIMIT 256", (event.host_id,cutoff,event.timestamp)).fetchall()
        results = []
        identity = event_instance(event)
        for row in rows:
            previous = json.loads(row[0])
            if event.event_id in previous['event_ids']:
                continue
            key, grouping, explanation = None, None, None
            evidence = previous['evidence']
            suspicious = previous['rule_id'].startswith(('HIDS-EXEC-','HIDS-BEH-'))
            if event.event_type == 'network_connection' and identity and suspicious and evidence.get('process_identity') == identity:
                key, grouping = 'HIDS-CORR-001', identity
                explanation = 'Same verified process instance produced suspicious execution and a subsequent remote socket observation within the configured window.'
            elif event.event_type == 'process_start' and event.executable_path:
                target = evidence.get('target_path') or evidence.get('service_file')
                if previous['rule_id'].startswith('HIDS-PER-') or previous['rule_id'] == 'HIDS-SEC-003':
                    if target and normalized_path(target) == normalized_path(event.executable_path):
                        key, grouping = 'HIDS-CORR-002', identity or event.event_id
                        explanation = 'Persistence executable path exactly matches a subsequent process executable on the same host.'
                if previous['rule_id'] == 'HIDS-FIM-001' and any(item.rule_id.startswith(('HIDS-EXEC-','HIDS-BEH-')) for item in current):
                    target = evidence.get('file_path')
                    if target and normalized_path(target) == normalized_path(event.executable_path):
                        key, grouping = 'HIDS-CORR-003', identity or event.event_id
                        explanation = 'A changed monitored file exactly matches the executable in a subsequent suspicious process event.'
            elif event.action == 'group_member_added' and privileged_group(event.evidence) and previous['rule_id'] == 'HIDS-SEC-002':
                sid = event.evidence.get('target_sid')
                if sid and sid == evidence.get('target_sid'):
                    key, grouping = 'HIDS-CORR-004', sid + ':' + previous['event_ids'][0]
                    explanation = 'Account creation and group membership addition refer to the same account SID on the same host.'
            if key:
                spec = RULES[key]
                results.append(Detection.create(rule_id=key,rule_name=spec.name,category='correlation',tactic=spec.tactic,
                    technique_id=spec.technique_id,severity=spec.severity,confidence=spec.confidence,timestamp=event.timestamp,
                    event_ids=tuple(dict.fromkeys([*previous['event_ids'],event.event_id])),
                    related_detection_ids=tuple(dict.fromkeys([previous['detection_id'], *[item.detection_id for item in current]])),
                    reason=explanation,evidence={'correlation_key':grouping, 'process_identity':identity,
                        'process_name':event.process_name,'window_seconds':self.config.correlation_window_seconds},
                    investigation=spec.investigation,host_id=event.host_id))
        # One correlation result per rule/group; combine all matching evidence.
        grouped = {}
        from dataclasses import replace
        for item in results:
            key = (item.rule_id,item.evidence['correlation_key'])
            if key in grouped:
                old = grouped[key]
                item = replace(item,event_ids=tuple(dict.fromkeys([*old.event_ids,*item.event_ids])),
                               related_detection_ids=tuple(dict.fromkeys([*old.related_detection_ids,*item.related_detection_ids])))
            grouped[key] = item
        return list(grouped.values())
