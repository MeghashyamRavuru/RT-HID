from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

from .collectors.persistence import safe_content_path
from .models import HostEvent


class YaraScanner:
    def __init__(self, config, jobs, sink):
        self.config, self.jobs, self.sink = config,jobs,sink

    def status(self):
        try:
            importlib.import_module('yara')
            available = True
        except (ImportError,OSError):
            available = False
        return {'enabled':self.config.yara_enabled,'available':available,
                'rule_files':len(self.config.yara_rule_paths),'configured_paths':[str(path) for path in self.config.yara_scan_paths],
                'max_bytes':self.config.yara_max_bytes,'timeout_seconds':self.config.yara_timeout_seconds}

    def validate_path(self, value):
        if not isinstance(value,str) or not 1 <= len(value) <= 1024:
            raise ValueError('invalid scan path')
        path = Path(value)
        if path.is_symlink() or not safe_content_path(path):
            raise ValueError('linked or credential paths cannot be scanned')
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise ValueError('scan file unavailable') from None
        allowed = False
        for scope in self.config.yara_scan_paths:
            root = scope.resolve()
            if resolved == root or (root.is_dir() and root in resolved.parents):
                allowed = True
        if not allowed or not resolved.is_file():
            raise ValueError('file must be within configured YARA scope')
        if resolved.stat().st_size > self.config.yara_max_bytes:
            raise ValueError('file exceeds YARA size limit')
        return resolved

    def submit(self, path):
        if not self.config.yara_enabled:
            raise ValueError('YARA scanning is disabled in host configuration')
        if not self.status()['available'] or not self.config.yara_rule_paths:
            raise ValueError('YARA or configured rules unavailable')
        validated = self.validate_path(path)
        return self.jobs.submit('yara',str(validated),lambda cancelled:self.scan(str(validated),cancelled))

    def scan(self, path, cancelled):
        yara = importlib.import_module('yara')
        path = self.validate_path(path)
        rules, total = {}, 0
        if len(self.config.yara_rule_paths) > 16:
            raise ValueError('too many YARA rule files')
        for index,rule in enumerate(self.config.yara_rule_paths):
            if rule.is_symlink():
                raise ValueError('linked YARA rule file')
            size = rule.stat().st_size
            total += size
            if total > 1024 * 1024:
                raise ValueError('YARA rule files exceed 1 MiB')
            rules['local_' + str(index)] = str(rule.resolve())
        if cancelled():
            return {'cancelled':True}
        compiled = yara.compile(filepaths=rules,includes=False)
        with path.open('rb') as stream:
            content = stream.read(self.config.yara_max_bytes+1)
        if len(content) > self.config.yara_max_bytes:
            raise ValueError('file grew beyond size limit')
        digest = hashlib.sha256(content).hexdigest()
        matches = compiled.match(data=content,timeout=self.config.yara_timeout_seconds)
        names = [str(match.rule)[:128] for match in matches[:100]]
        if not cancelled():
            self.sink(HostEvent.create(self.config.host_id,'file_scan','yara',action='scan',outcome='observed',file_path=str(path),
                evidence={'matched_rules':names,'sha256':digest,'matches_truncated':len(matches)>100}))
        return {'path':str(path),'sha256':digest,'matched_rules':names,'bytes_scanned':len(content)}
