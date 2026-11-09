from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, replace

from ..identity import normalized_path
from ..models import SEVERITIES, utc_now


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str
    confidence: float
    tactic: str
    technique_id: str | None
    event_types: tuple[str, ...]
    investigation: str = "Verify authorization, process ancestry and related evidence before taking action."
    version: str = "2.0.0"
    mapping_version: str = "RT-HID-2026-11"


def rule(key, name, severity, confidence, tactic, technique, *types):
    return Rule(key, name, name + "; an indicator for investigation.", severity, confidence, tactic, technique, types)


RULES = {item.rule_id: item for item in [
    rule("HIDS-AUTH-001", "Repeated SSH authentication failures", "high", .8, "Credential Access", "T1110", "auth"),
    rule("HIDS-AUTH-002", "Repeated authentication failures", "high", .8, "Credential Access", "T1110", "auth"),
    rule("HIDS-AUTH-003", "Login succeeded after failures", "high", .7, "Credential Access", "T1110", "auth"),
    rule("HIDS-NET-001", "New listening service", "low", .65, "Discovery", None, "network_listen"),
    rule("HIDS-EXEC-001", "Executable launched from temporary directory", "medium", .6, "Execution", None, "process_start"),
    rule("HIDS-EXEC-002", "Encoded PowerShell command", "medium", .6, "Execution", "T1059.001", "process_start"),
    rule("HIDS-FIM-001", "Security-sensitive file changed", "medium", .9, "Defense Evasion", "T1562", "file_change"),
    rule("HIDS-SEC-001", "Security audit log cleared", "high", .85, "Defense Evasion", "T1070.001", "security_change"),
    rule("HIDS-SEC-002", "Local account created", "medium", .85, "Persistence", "T1136", "security_change"),
    rule("HIDS-SEC-003", "Service installed", "medium", .85, "Persistence", "T1543.003", "security_change"),
    rule("HIDS-BEH-001", "Office application launched an interpreter", "high", .85, "Execution", "T1059", "process_start"),
    rule("HIDS-BEH-002", "Web server launched a shell", "high", .85, "Execution", "T1059", "process_start"),
    rule("HIDS-BEH-003", "Browser launched a script interpreter", "medium", .65, "Execution", "T1059", "process_start"),
    rule("HIDS-BEH-004", "Service launched an unusual child", "high", .8, "Execution", None, "process_start"),
    rule("HIDS-BEH-005", "Interpreter to downloader to temporary executable", "high", .85, "Command and Control", "T1105", "process_start"),
    rule("HIDS-BEH-006", "System executable name in an unusual location", "medium", .7, "Defense Evasion", "T1036.005", "process_start"),
    rule("HIDS-BEH-007", "Interpreter running a script from a temporary location", "medium", .8, "Execution", "T1059", "process_start"),
    rule("HIDS-NET-002", "Connection to a configured unusual port", "medium", .55, "Command and Control", None, "network_connection"),
    rule("HIDS-NET-003", "Repeated connections to an unusual destination", "medium", .7, "Command and Control", None, "network_connection"),
    rule("HIDS-NET-004", "Interpreter connected to an unusual port", "high", .8, "Execution", "T1059", "network_connection"),
    rule("HIDS-IOC-001", "Local threat indicator match", "high", .7, "Command and Control", None, "process_start", "network_connection"),
    rule("HIDS-PER-001", "Persistence location changed", "medium", .8, "Persistence", None, "persistence_change"),
    rule("HIDS-PER-002", "Persistence entry launches from a temporary location", "high", .85, "Persistence", None, "persistence_change"),
    rule("HIDS-PER-003", "Scheduled task created or changed", "medium", .85, "Persistence", "T1053.005", "persistence_change"),
    rule("HIDS-PER-004", "Privileged group membership changed", "high", .85, "Persistence", "T1098.007", "security_change"),
    rule("HIDS-PER-005", "Run key or startup folder changed", "medium", .8, "Persistence", "T1547.001", "persistence_change"),
    rule("HIDS-PER-006", "Cron persistence location changed", "medium", .8, "Persistence", "T1053.003", "persistence_change"),
    rule("HIDS-PER-007", "Systemd service unit changed", "medium", .8, "Persistence", "T1543.002", "persistence_change"),
    rule("HIDS-PER-008", "SSH authorized keys changed", "high", .85, "Persistence", "T1098.004", "persistence_change"),
    rule("HIDS-PER-009", "Shell startup file changed", "medium", .8, "Persistence", "T1546.004", "persistence_change"),
    rule("HIDS-PER-010", "Windows service configuration changed", "medium", .8, "Persistence", "T1543.003", "persistence_change"),
    rule("HIDS-PER-011", "Systemd timer changed", "medium", .8, "Persistence", "T1053.006", "persistence_change"),
    rule("HIDS-CORR-001", "Suspicious process followed by network activity", "high", .9, "Command and Control", None, "network_connection"),
    rule("HIDS-CORR-002", "Persistence entry followed by matching execution", "high", .85, "Persistence", None, "process_start"),
    rule("HIDS-CORR-003", "Modified file followed by suspicious execution", "high", .85, "Execution", None, "process_start"),
    rule("HIDS-CORR-004", "New account added to a privileged group", "high", .85, "Persistence", "T1098.007", "security_change"),
    rule("HIDS-YARA-001", "User-provided YARA rule matched", "medium", .6, "Execution", None, "file_scan"),
]}


class RuleRegistry:
    def __init__(self, config, database=None):
        self.config, self.database = config, database
        self.settings = dict(config.rule_settings)
        if database is not None:
            with database._lock:
                for row in database.connection.execute("SELECT rule_id,payload FROM rule_settings"):
                    self.settings[row[0]] = json.loads(row[1])
        for key, setting in self.settings.items():
            self.validate(key, setting)

    @staticmethod
    def validate(key: str, settings: dict) -> dict:
        if key not in RULES:
            raise ValueError("unknown rule")
        if not isinstance(settings, dict) or set(settings) - {"enabled", "severity", "confidence", "allowlist", "threshold"}:
            raise ValueError("unsupported rule settings")
        if "enabled" in settings and not isinstance(settings["enabled"], bool):
            raise ValueError("enabled must be a boolean")
        if "severity" in settings and (not isinstance(settings['severity'],str) or settings["severity"] not in SEVERITIES):
            raise ValueError("invalid severity")
        confidence = settings.get("confidence", .5)
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid confidence")
        threshold = settings.get("threshold", 5)
        if "threshold" in settings and key not in {"HIDS-AUTH-001", "HIDS-AUTH-002", "HIDS-NET-003"}:
            raise ValueError("this rule does not have a threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 2 <= threshold <= 100:
            raise ValueError("threshold must be between 2 and 100")
        allowlist = settings.get("allowlist", [])
        if not isinstance(allowlist, list) or len(allowlist) > 100:
            raise ValueError("invalid allowlist")
        for condition in allowlist:
            if not isinstance(condition, dict) or not condition or set(condition) - {"executable_path", "file_path", "username", "parent_name", "destination_ip"}:
                raise ValueError("unsupported allowlist condition")
            if any(not isinstance(value, str) or not 1 <= len(value) <= 512 for value in condition.values()):
                raise ValueError("invalid allowlist value")
        return settings

    def update(self, key: str, settings: dict):
        self.validate(key, settings)
        settings = json.loads(json.dumps(settings))
        if self.database is not None:
            with self.database._lock, self.database.connection:
                self.database.connection.execute("INSERT OR REPLACE INTO rule_settings VALUES (?,?,?)",
                                                 (key, utc_now(), json.dumps(settings)))
        self.settings[key] = settings

    def apply(self, detection, event):
        spec = RULES[detection.rule_id]
        settings = self.settings.get(spec.rule_id, {})
        if not settings.get("enabled", True):
            return None
        values = {"executable_path": event.executable_path or detection.evidence.get('target_path'), "file_path":event.file_path or detection.evidence.get('file_path'), "username": event.username,
                  "parent_name": event.metadata.get("parent_name"), "destination_ip": event.destination_ip}
        for condition in settings.get("allowlist", []):
            if all(normalized_path(str(values.get(key) or "")) == normalized_path(value) for key, value in condition.items()):
                return None
        return replace(detection, severity=settings.get("severity", detection.severity),
                       confidence=settings.get("confidence", detection.confidence), rule_version=spec.version,
                       tactic=spec.tactic, technique_id=spec.technique_id)

    def list(self):
        return [{**asdict(item), "settings": self.settings.get(item.rule_id, {}),
                 "enabled": self.settings.get(item.rule_id, {}).get("enabled", True)} for item in RULES.values()]

    def coverage(self):
        rules = self.list()
        return {"mapping_version": "RT-HID-2026-11", "rules": [item for item in rules if item['enabled'] and item['technique_id']],
                "gaps": ["kernel activity", "memory injection", "credential access in memory", "DNS without domain telemetry", "encrypted application traffic"],
                "scope": "Implemented active rules; mappings are not a claim of complete technique coverage."}
