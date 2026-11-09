from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from dataclasses import replace
from pathlib import Path

from ..models import CollectorStatus, HostEvent
from .base import Collector

DENIED_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "shadow", "gshadow"}


def safe_content_path(path):
    return path.name.lower() not in DENIED_NAMES and path.suffix.lower() not in {".pem", ".key", ".pfx", ".p12"}


def executable_from_command(value):
    """Extract the executable only; never persist service/Run-key arguments."""
    if not isinstance(value, str):
        return None
    match = re.match(r'^\s*"([^"]+)"|^\s*(.+?\.(?:exe|com|bat|cmd|ps1))(?:\s|$)', value[:4096], re.IGNORECASE)
    return (match.group(1) or match.group(2)) if match else None


def default_persistence_paths(system):
    if system == "windows":
        return [Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Tasks',
                Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Microsoft/Windows/Start Menu/Programs/StartUp',
                Path(os.environ.get('APPDATA', str(Path.home()))) / 'Microsoft/Windows/Start Menu/Programs/Startup']
    return [Path(item) for item in ('/etc/crontab','/etc/cron.d','/etc/cron.daily','/etc/cron.hourly',
        '/var/spool/cron','/etc/systemd/system','/etc/profile','/etc/profile.d','/etc/sudoers','/etc/sudoers.d')] + [Path.home() / item for item in ('.ssh/authorized_keys','.bashrc','.bash_profile','.profile','.zshrc','.config/systemd/user')]


class PersistenceCollector(Collector):
    def __init__(self, host_id, config, database, sink, system):
        self.collector_id = system + '_persistence'
        super().__init__(host_id, sink)
        self.status = CollectorStatus(self.collector_id, system, False, True)
        self.config, self.database, self.system = config, database, system
        self.paths = config.persistence_paths or default_persistence_paths(system)
        self._pending = {}
        self._scan_count = config.persistence_verify_every_scans - 1

    def run_once(self):
        self._pending = {}
        self._scan_count += 1
        events = super().run_once()
        if self.status.state == 'running' and self.status.available:
            with self.database._lock, self.database.connection:
                for scope,current in self._pending.items():
                    previous = self.previous(scope)
                    for key in set(previous)-set(current)-{''}:
                        self.database.connection.execute('DELETE FROM persistence_baselines WHERE scope=? AND entry=?',(scope,key))
                    self.database.connection.executemany('INSERT INTO persistence_baselines VALUES (?,?,?) ON CONFLICT(scope,entry) DO UPDATE SET payload=excluded.payload',
                        [(scope,'',json.dumps({'generation':uuid.uuid4().hex}))] + [(scope,key,json.dumps(value)) for key,value in current.items() if previous.get(key)!=value])
        return events

    def previous(self, scope):
        with self.database._lock:
            rows = self.database.connection.execute('SELECT entry,payload FROM persistence_baselines WHERE scope=?', (scope,)).fetchall()
        return {row[0]: json.loads(row[1]) for row in rows}

    def changes(self, scope, current, kind):
        previous = self.previous(scope)
        initialized = '' in previous
        generation = previous.pop('', {}).get('generation','initial')
        events = []
        if initialized:
            for key in sorted(set(previous) | set(current)):
                before, after = previous.get(key), current.get(key)
                if before == after:
                    continue
                action = 'create' if before is None else 'delete' if after is None else 'modify'
                stable = uuid.uuid5(uuid.NAMESPACE_URL, scope + key + generation + json.dumps([before,after],sort_keys=True)).hex
                events.append(HostEvent.create(self.host_id, 'persistence_change', self.collector_id, action=action,
                    event_id=stable,
                    file_path=key if kind == 'file' else None, outcome='observed',
                    evidence={'scope':scope, 'entry':key, 'kind':kind, 'previous':before, 'current':after},
                    metadata={'target_path': (after or before or {}).get('executable_path') or (key if kind == 'file' else None)}))
        if not initialized or previous != current:
            self._pending[scope] = current
        return events

    def files_snapshot(self, root, deadline):
        if root.is_symlink() or str(root.absolute()) == root.anchor or root.absolute() == Path.home().absolute():
            raise ValueError('scope too broad or linked')
        previous = self.previous('file:' + str(root))
        try:
            root.stat()
        except FileNotFoundError:
            return {}
        entries = [root] if not root.is_dir() else []
        if root.is_dir():
            pending = [(root,0)]
            while pending:
                directory, depth = pending.pop()
                for item in directory.iterdir():
                    if time.monotonic() > deadline:
                        raise TimeoutError()
                    if item.is_symlink():
                        continue
                    if item.is_dir():
                        if depth < 2:
                            pending.append((item, depth+1))
                    elif safe_content_path(item):
                        entries.append(item)
                    if len(entries) + len(pending) > self.config.persistence_max_files:
                        raise OverflowError()
        if len(entries) > self.config.persistence_max_files:
            raise OverflowError()
        snapshot, remaining = {}, 16 * 1024 * 1024
        for path in entries:
            if time.monotonic() > deadline:
                raise TimeoutError()
            if not safe_content_path(path):
                continue
            try:
                metadata = path.stat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            key = str(path)
            state = {'size':metadata.st_size, 'mode':stat.S_IMODE(metadata.st_mode), 'mtime_ns':metadata.st_mtime_ns}
            cached = previous.get(key)
            if self._scan_count % self.config.persistence_verify_every_scans != 0 and cached and all(cached.get(name) == value for name,value in state.items()):
                snapshot[key] = cached
                continue
            if metadata.st_size > self.config.persistence_max_bytes:
                state['hash_unavailable'] = 'file size limit'
            else:
                remaining -= metadata.st_size
                if remaining < 0:
                    raise OverflowError()
                # Read only bounded bytes, and reject files changed while hashing.
                with path.open('rb') as stream:
                    content = stream.read(self.config.persistence_max_bytes + 1)
                if len(content) > self.config.persistence_max_bytes or path.stat().st_mtime_ns != metadata.st_mtime_ns:
                    raise OSError('changed during scan')
                state['sha256'] = hashlib.sha256(content).hexdigest()
            snapshot[key] = state
        return snapshot

    def registry_snapshots(self):
        import winreg
        targets = [('HKCU',winreg.HKEY_CURRENT_USER), ('HKLM',winreg.HKEY_LOCAL_MACHINE)]
        for label,hive in targets:
            for suffix in ('Run','RunOnce'):
                keypath = 'Software\\Microsoft\\Windows\\CurrentVersion\\' + suffix
                for view in (getattr(winreg,'KEY_WOW64_64KEY',0), getattr(winreg,'KEY_WOW64_32KEY',0)):
                    scope = f'registry:{label}:{suffix}:{view}'
                    values = {}
                    try:
                        with winreg.OpenKey(hive,keypath,0,winreg.KEY_READ | view) as key:
                            count = winreg.QueryInfoKey(key)[1]
                            if count > self.config.persistence_max_files:
                                raise OverflowError()
                            for index in range(count):
                                name,value,kind = winreg.EnumValue(key,index)
                                values[name] = {'sha256':hashlib.sha256(str(value).encode()).hexdigest(),
                                    'type':kind, 'executable_path':executable_from_command(value)}
                    except FileNotFoundError:
                        pass
                    yield scope,values

    def service_snapshot(self):
        import win32service
        handle = win32service.OpenSCManager(None,None,win32service.SC_MANAGER_ENUMERATE_SERVICE)
        snapshot = {}
        try:
            services = win32service.EnumServicesStatus(handle)
            if len(services) > self.config.persistence_max_files:
                raise OverflowError()
            for name, _, _ in services:
                service = win32service.OpenService(handle,name,win32service.SERVICE_QUERY_CONFIG)
                try:
                    settings = win32service.QueryServiceConfig(service)
                    snapshot[name] = {'sha256':hashlib.sha256(json.dumps(settings,default=str).encode()).hexdigest(),
                        'executable_path':executable_from_command(settings[3]), 'start_type':settings[1]}
                finally:
                    win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(handle)
        return snapshot

    def collect_once(self):
        events, errors, unavailable = [], [], []
        deadline = time.monotonic() + 3
        for path in self.paths:
            try:
                snapshot = self.files_snapshot(path, deadline)
                events += self.changes('file:' + str(path), snapshot, 'file')
            except (OSError, ValueError, TimeoutError, OverflowError) as error:
                errors.append(type(error).__name__)
                unavailable.append(str(path))
        if self.config.persistence_registry_enabled:
            try:
                if self.system != 'windows':
                    raise ImportError()
                for scope,snapshot in self.registry_snapshots():
                    events += self.changes(scope,snapshot,'registry')
            except Exception as error:  # isolate optional native capability failures
                errors.append(type(error).__name__)
                unavailable.append('Windows Run/RunOnce registry views')
        if self.config.persistence_services_enabled:
            try:
                if self.system != 'windows':
                    raise ImportError()
                events += self.changes('windows:services',self.service_snapshot(),'service')
            except Exception as error:  # pywin32 errors need not subclass OSError
                errors.append(type(error).__name__)
                unavailable.append('Windows service configuration')
        self.status = replace(self.status, available=True, collection_errors=len(errors),
            last_error='persistence_snapshot: ' + errors[-1] if errors else None,
            unavailable_locations=tuple(unavailable),
            capabilities={'scope':'configured startup paths; metadata and hashes only',
                'registry':self.config.persistence_registry_enabled and self.system=='windows',
                'services':self.config.persistence_services_enabled and self.system=='windows'},
            detail=f'{len(self.paths)} configured locations; {len(errors)} unavailable or limited scopes; no contents stored')
        return events
