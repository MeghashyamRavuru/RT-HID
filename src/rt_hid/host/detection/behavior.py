from __future__ import annotations

from datetime import datetime
import re

from ..identity import event_instance, process_name
from ..models import Detection
from .registry import RULES

INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash", "sh", "dash", "zsh", "python", "python3", "python.exe", "pythonw.exe", "node", "node.exe", "perl", "ruby"}
PARENT_RULES = (
    ("HIDS-BEH-001", {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}, INTERPRETERS),
    ("HIDS-BEH-002", {"w3wp.exe", "httpd.exe", "httpd", "apache2", "nginx", "php-fpm"}, INTERPRETERS),
    ("HIDS-BEH-003", {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"}, INTERPRETERS - {"cmd.exe"}),
)


def is_temporary(path):
    path = (path or "").lower().replace("\\", "/")
    return path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) or bool(re.match(r'^[a-z]:/windows/temp/',path)) or "/appdata/local/temp/" in path


def evaluate_behavior(event, graph, window):
    parent, child = process_name(event.metadata.get("parent_name")), process_name(event.process_name or event.executable_path)
    keys = [key for key, parents, children in PARENT_RULES if parent in parents and child in children]
    if parent in {"services.exe", "svchost.exe", "systemd"} and is_temporary(event.executable_path):
        keys.append("HIDS-BEH-004")
    path = (event.executable_path or "").lower().replace("\\", "/")
    if child in {"lsass.exe", "svchost.exe", "services.exe", "csrss.exe"} and path and not re.match(r'^[a-z]:/(?:windows|winnt)/(?:system32|syswow64)/',path):
        keys.append("HIDS-BEH-006")
    temporary_script = None
    arguments = event.metadata.get('command_line')
    if child in INTERPRETERS and isinstance(arguments,list):
        for argument in arguments[:64]:
            if isinstance(argument,str) and argument.lower().rstrip('"\'').endswith(('.ps1','.vbs','.js','.hta','.py','.sh','.bat','.cmd')) and is_temporary(argument.strip('"\'')):
                temporary_script = argument.strip('"\'')
                keys.append('HIDS-BEH-007')
                break
    related = [event.event_id]
    if graph and event_instance(event):
        ancestry = graph.ancestry(event_instance(event))["nodes"]
        if len(ancestry) >= 3:
            names = [process_name(node["event"].get("process_name")) for node in ancestry[:3]]
            age = (datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")) - datetime.fromisoformat(ancestry[2]["first_seen"].replace("Z", "+00:00"))).total_seconds()
            if is_temporary(event.executable_path) and names[1] in {"curl", "wget", "curl.exe", "bitsadmin.exe", "certutil.exe"} and names[2] in INTERPRETERS and 0 <= age <= window:
                keys.append("HIDS-BEH-005")
                related = [node["event_id"] for node in reversed(ancestry[:3])]
    result = []
    for key in keys:
        spec = RULES[key]
        result.append(Detection.create(rule_id=key, rule_name=spec.name, category="behavioral_execution", tactic=spec.tactic,
            technique_id=spec.technique_id, severity=spec.severity, confidence=spec.confidence, timestamp=event.timestamp,
            event_ids=tuple(related), reason=f"{spec.name}: observed parent {parent or 'unknown'} and child {child or 'unknown'}",
            evidence={"process_name": event.process_name, "parent_name": parent, "pid": event.process_id,
                      **({'file_path':temporary_script} if key=='HIDS-BEH-007' else {}),
                      "process_identity": event_instance(event) or event.event_id, "parent_identity_verified": bool(event.metadata.get("parent_create_time"))},
            investigation=spec.investigation, host_id=event.host_id))
    return result
