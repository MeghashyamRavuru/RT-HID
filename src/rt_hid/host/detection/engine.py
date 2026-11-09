from __future__ import annotations

import base64
import binascii
import re
import uuid
from dataclasses import replace
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from ..config import HostConfig
from ..models import Detection, HostEvent
from .registry import RuleRegistry
from .behavior import evaluate_behavior, is_temporary
from .network_rules import evaluate_connections
from .persistence_rules import evaluate_persistence
from ..identity import event_instance


class HostDetectionEngine:
    """Explainable, platform-neutral rules over normalized host events."""

    def __init__(self, config: HostConfig, database=None, graph=None) -> None:
        self.config = config
        self.registry = RuleRegistry(config, database)
        self.graph = graph
        self._recent_auth_failures: dict[tuple[str, str], deque[HostEvent]] = defaultdict(deque)
        self._known_listeners: set[tuple[str, int, str]] = set()
        self._recent_event_ids: set[str] = set()
        self._recent_event_order: deque[str] = deque()
        self._recent_connections = {}

    def evaluate(self, event: HostEvent) -> list[Detection]:
        if event.event_id in self._recent_event_ids:
            return []
        if len(self._recent_event_order) >= 10_000:
            self._recent_event_ids.discard(self._recent_event_order.popleft())
        self._recent_event_ids.add(event.event_id)
        self._recent_event_order.append(event.event_id)
        handlers = {"auth": self._auth_rules, "network_listen": self._network_rules,
                    "process_start": self._process_rules, "file_change": self._file_rules,
                    "security_change": self._security_rules}
        candidates = handlers[event.event_type](event) if event.event_type in handlers else []
        if event.event_type == "network_connection":
            candidates.extend(evaluate_connections(self, event))
        if event.event_type == "persistence_change" or (event.event_type == "security_change" and event.action == "group_member_added"):
            candidates.extend(evaluate_persistence(event))
        if event.event_type == 'file_scan' and event.evidence.get('matched_rules'):
            candidates.append(Detection.create(rule_id='HIDS-YARA-001',rule_name='User-provided YARA rule matched',category='file_scan',
                tactic='Execution',technique_id=None,severity='medium',confidence=.6,timestamp=event.timestamp,event_ids=(event.event_id,),
                reason='Configured YARA rules matched a file snapshot; a match is not confirmation of malware',
                evidence={**event.evidence,'file_path':event.file_path},investigation='Review rule provenance, file hash and host behavior before responding.',host_id=event.host_id))
        return self.finalize(candidates, event)

    def finalize(self, candidates, event):
        results = []
        for candidate in candidates:
            item = self.registry.apply(candidate, event)
            if item:
                if event_instance(event):
                    item = replace(item, evidence={**item.evidence, "process_identity": event_instance(event)})
                key = f"{item.host_id}|{item.rule_id}|{item.rule_version}|{'|'.join(sorted(item.event_ids))}"
                results.append(replace(item, detection_id=uuid.uuid5(uuid.NAMESPACE_URL, key).hex))
        return results

    def _auth_rules(self, event: HostEvent) -> list[Detection]:
        if event.action not in {"ssh_login", "ftp_login", "sudo", "remote_login", "local_login"}:
            return []
        source = event.source_ip or f"local:{event.username or 'unknown'}"
        rule_key = "HIDS-AUTH-001" if event.action == "ssh_login" else "HIDS-AUTH-002"
        threshold = self.registry.settings.get(rule_key, {}).get("threshold", self.config.auth_failure_threshold)
        key = (event.host_id, source, event.action)
        failures = self._recent_auth_failures[key]
        cutoff = _parse_timestamp(event.timestamp) - timedelta(seconds=self.config.auth_failure_window_seconds)
        while failures and _parse_timestamp(failures[0].timestamp) < cutoff:
            failures.popleft()
        if event.outcome == "success":
            if len(failures) < threshold:
                failures.clear()
                return []
            related = tuple(item.event_id for item in failures) + (event.event_id,)
            failures.clear()
            return [Detection.create(
                rule_id="HIDS-AUTH-003", rule_name="Login succeeded after failures",
                category="suspicious_login", tactic="Credential Access", technique_id="T1110",
                severity="high", confidence=0.7, timestamp=event.timestamp,
                event_ids=related, reason=f"Successful {event.action} from {source} followed recent failures",
                evidence={"source_ip": event.source_ip, "username": event.username, "action": event.action,
                          "previous_failures": len(related) - 1},
                investigation="Verify this login and review the preceding failed attempts.", host_id=event.host_id,
            )]
        if event.outcome != "failure":
            return []
        if len(self._recent_auth_failures) > 2048:
            self._recent_auth_failures.pop(next(iter(self._recent_auth_failures)))
        failures.append(event)
        while len(failures) > 100:
            failures.popleft()
        if len(failures) < threshold:
            return []
        rule_id = "HIDS-AUTH-001" if event.action == "ssh_login" else "HIDS-AUTH-002"
        return [Detection.create(
            rule_id=rule_id,
            rule_name="Repeated authentication failures",
            category="brute_force",
            tactic="Credential Access",
            technique_id="T1110",
            severity="high",
            confidence=min(0.99, 0.6 + len(failures) / (threshold * 10)),
            timestamp=event.timestamp,
            event_ids=tuple(item.event_id for item in failures),
            reason=f"{len(failures)} failed {event.action} attempts from {source} within the configured window",
            evidence={"source_ip": event.source_ip, "username": event.username, "attempts": len(failures), "action": event.action},
            investigation="Review the source, target account, and any subsequent successful login.",
            host_id=event.host_id,
        )]

    def _network_rules(self, event: HostEvent) -> list[Detection]:
        if event.action != "listen" or event.destination_port is None:
            return []
        identity = (event.host_id, event.protocol or "unknown", event.destination_port, event.process_name or "")
        if identity in self._known_listeners:
            return []
        self._known_listeners.add(identity)
        if len(self._known_listeners) > 10000:
            self._known_listeners.clear()
            self._known_listeners.add(identity)
        severity = "medium" if event.destination_port in {21, 22, 23, 445, 3389} else "low"
        return [Detection.create(
            rule_id="HIDS-NET-001",
            rule_name="New listening service",
            category="suspicious_listening_port",
            tactic="Persistence",
            technique_id="T1608",
            severity=severity,
            confidence=0.65,
            timestamp=event.timestamp,
            event_ids=(event.event_id,),
            reason=f"New {event.protocol or 'unknown'} listener on port {event.destination_port}",
            evidence={"port": event.destination_port, "process": event.process_name},
            investigation="Confirm that the listening service is approved and expected on this host.",
            host_id=event.host_id,
        )]

    def _process_rules(self, event: HostEvent) -> list[Detection]:
        path = (event.executable_path or "").lower().replace("\\", "/")
        parent = (event.metadata.get("parent_name") or "").lower()
        temporary = is_temporary(path)
        detections: list[Detection] = []
        if temporary:
            detections.append(Detection.create(
                rule_id="HIDS-EXEC-001",
                rule_name="Executable launched from temporary directory",
                category="suspicious_execution",
                tactic="Execution",
                technique_id="T1204",
                severity="medium",
                confidence=0.6,
                timestamp=event.timestamp,
                event_ids=(event.event_id,),
                reason="A process started from a temporary executable path",
                evidence={"executable_path": event.executable_path, "parent": parent, "pid": event.process_id},
                investigation="Verify the executable origin, package ownership, and parent process chain.",
                host_id=event.host_id,
            ))
        encoded = _encoded_powershell_command(event)
        if encoded is not None:
            network_execution = _network_command_execution(encoded)
            detections.append(Detection.create(
                rule_id="HIDS-EXEC-002",
                rule_name="Encoded PowerShell command with network execution" if network_execution
                          else "Encoded PowerShell command",
                category="suspicious_execution",
                tactic="Execution",
                technique_id="T1059.001",
                severity="high" if network_execution else "medium",
                confidence=0.9 if network_execution else 0.6,
                timestamp=event.timestamp,
                event_ids=(event.event_id,),
                reason="Encoded PowerShell command contains network and command execution patterns" if network_execution
                       else "PowerShell started with an encoded command argument",
                evidence={"process_name": event.process_name, "pid": event.process_id,
                          "process_identity": f"{event.process_id}:{event.metadata.get('create_time') or event.event_id}",
                          "executable_path": event.executable_path, "network_execution_pattern": network_execution},
                investigation="Confirm who launched PowerShell, inspect the parent process and command, "
                              "and verify any network destination. Encoded commands can also be used for administration.",
                host_id=event.host_id,
            ))
        detections.extend(evaluate_behavior(event, self.graph, self.config.correlation_window_seconds))
        return detections

    def _file_rules(self, event: HostEvent) -> list[Detection]:
        if event.action not in {"modify", "delete", "create", "permission_change"}:
            return []
        return [Detection.create(
            rule_id="HIDS-FIM-001",
            rule_name="Security-sensitive file changed",
            category="file_integrity",
            tactic="Defense Evasion",
            technique_id="T1562",
            severity="high" if event.file_path in {"/etc/shadow", "/etc/sudoers"} else "medium",
            confidence=0.9,
            timestamp=event.timestamp,
            event_ids=(event.event_id,),
            reason=f"Monitored security file {event.action}",
            evidence={"file_path": event.file_path, "action": event.action},
            investigation="Confirm whether the change was authorized and review the responsible process/user.",
            host_id=event.host_id,
        )]

    def _security_rules(self, event: HostEvent) -> list[Detection]:
        rules = {
            "audit_log_cleared": ("HIDS-SEC-001", "Security audit log cleared", "defense_evasion", "T1070.001", "high"),
            "account_created": ("HIDS-SEC-002", "Local account created", "persistence", "T1136", "medium"),
            "service_installed": ("HIDS-SEC-003", "Service installed", "persistence", "T1543.003", "medium"),
        }
        if event.action not in rules:
            return []
        rule_id, name, category, technique, severity = rules[event.action]
        return [Detection.create(
            rule_id=rule_id, rule_name=name, category=category,
            tactic="Defense Evasion" if event.action == "audit_log_cleared" else "Persistence",
            technique_id=technique, severity=severity, confidence=0.85,
            timestamp=event.timestamp, event_ids=(event.event_id,),
            reason=f"Windows Security event reports: {name.lower()}",
            evidence={**event.evidence, "username": event.username},
            investigation="Confirm whether this security change was authorized.", host_id=event.host_id,
        )]


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _encoded_powershell_command(event: HostEvent) -> str | None:
    name = (event.executable_path or event.process_name or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
    if name not in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
        return None
    arguments = event.metadata.get("command_line")
    if not isinstance(arguments, list):
        return None
    for index, argument in enumerate(arguments[:32]):
        if not isinstance(argument, str):
            continue
        option, separator, _ = argument.lower().partition(":")
        if option not in {"-encodedcommand", "-enc", "-ec", "-e"}:
            continue
        encoded = argument.split(":", 1)[1] if separator else arguments[index + 1] if index + 1 < len(arguments) else ""
        if not isinstance(encoded, str) or not 1 <= len(encoded) <= 8192:
            return ""
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-16-le")
        except (binascii.Error, UnicodeError, ValueError):
            return ""
    return None


def _network_command_execution(command: str) -> bool:
    normalized = re.sub(r"\s+", "", command).lower()
    network = "system.net.sockets.tcpclient" in normalized or "net.sockets.tcpclient" in normalized
    execution = bool(re.search(r"(?<![\w-])(?:iex|invoke-expression)(?![\w-])", command, re.IGNORECASE))
    return network and execution
