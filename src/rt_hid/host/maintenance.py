from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import closing
import threading

from .audit import canonical
from .migrations import MIGRATIONS
from .models import utc_now


def envelope(bundle):
    return {'algorithm':'SHA-256','sha256':hashlib.sha256(canonical(bundle).encode()).hexdigest(),'bundle':bundle,
            'integrity_note':'Detects changes to this export; does not provide tamper-proof host storage.'}


def validate_backup(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('backup is not a file')
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as connection:
        check = connection.execute('PRAGMA integrity_check').fetchone()[0]
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if check != 'ok' or not {'host_events','detections','alerts','incidents','auth_settings','schema_meta'} <= tables:
            raise ValueError('invalid RT-HID database backup')
        row = connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        if not row or not 1 <= int(row[0]) <= max(MIGRATIONS):
            raise ValueError('unsupported backup schema')
        required_by_version = {2:{'process_instances','rule_settings'},3:{'indicators','persistence_baselines'},
            5:{'background_jobs'},6:{'audit_history','response_requests'},7:{'detection_events','incident_detections','incident_events'}}
        if any(not required <= tables for version,required in required_by_version.items() if version <= int(row[0])):
            raise ValueError('backup is missing required schema tables')
        return {'integrity':'ok','schema_version':int(row[0])}


def restore_backup(source, destination):
    source, destination = Path(source).resolve(strict=True),Path(destination).absolute()
    validation = validate_backup(source)
    if destination.exists() or destination.is_symlink():
        raise ValueError('restore destination must not already exist; stop RT-HID before switching databases')
    destination.parent.mkdir(parents=True,exist_ok=True)
    descriptor = os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    try:
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original, closing(sqlite3.connect(destination)) as restored:
            original.backup(restored,pages=128)
        validate_backup(destination)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {**validation,'restored_path':str(destination)}


class Maintenance:
    def __init__(self, database, config, audit, pipeline_lock=None):
        self.database,self.config,self.audit = database,config,audit
        self.pipeline_lock = pipeline_lock or threading.RLock()

    def directory(self, name):
        path = self.database.path.parent / name
        if path.is_symlink():
            raise ValueError('maintenance directory cannot be linked')
        path.mkdir(mode=0o700,parents=True,exist_ok=True)
        if os.name == 'posix':
            os.chmod(path,0o700)
        return path

    def status(self):
        paths = [self.database.path,Path(str(self.database.path)+'-wal'),Path(str(self.database.path)+'-shm')]
        return {'schema_version':self.database.connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0],
            'storage_bytes':sum(path.stat().st_size for path in paths if path.exists()),
            'retention_enabled':self.config.retention_enabled,'retention_days':self.config.retention_days,
            'retention_scope':'Resolved incident evidence and unreferenced old raw events only; active incident evidence is preserved.',
            'last_integrity_check':self.database.get_checkpoint('maintenance:integrity'),
            'last_retention':self.database.get_checkpoint('maintenance:retention')}

    def integrity(self, cancelled=lambda:False):
        with closing(sqlite3.connect(self.database.path)) as connection:
            connection.set_progress_handler(lambda:int(cancelled()),10000)
            result = connection.execute('PRAGMA integrity_check').fetchone()[0]
        self.database.set_checkpoint('maintenance:integrity',json.dumps({'timestamp':utc_now(),'result':'ok' if result=='ok' else 'failed'}))
        self.audit.append('database_integrity',str(self.database.path),'ok' if result=='ok' else 'failed')
        return {'integrity':'ok' if result=='ok' else 'failed'}

    def backup(self, cancelled=lambda:False):
        path = self.directory('backups')/(uuid.uuid4().hex+'.sqlite3')
        self.audit.append('database_backup',str(path),'requested')
        try:
            def progress(*args):
                if cancelled():
                    raise InterruptedError()
            descriptor = os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.close(descriptor)
            with closing(sqlite3.connect(self.database.path)) as source, closing(sqlite3.connect(path)) as target:
                source.backup(target,pages=128,progress=progress,sleep=.01)
            if os.name == 'posix':
                os.chmod(path,0o600)
            result = validate_backup(path)
            self.audit.append('database_backup',str(path),'completed')
            return {**result,'path':str(path)}
        except Exception as error:
            path.unlink(missing_ok=True)
            self.audit.append('database_backup',str(path),'failed',type(error).__name__)
            raise

    def archive(self, content):
        path = self.directory('archives')/(uuid.uuid4().hex+'.json')
        data = envelope(content)
        descriptor = os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'w',encoding='utf-8') as file:
            json.dump(data,file,sort_keys=True)
            file.flush(); os.fsync(file.fileno())
        if os.name == 'posix':
            os.chmod(path,0o600)
        written = json.loads(path.read_text(encoding='utf-8'))
        if hashlib.sha256(canonical(written['bundle']).encode()).hexdigest() != data['sha256']:
            raise ValueError('archive verification failed; evidence retained')
        return path

    def retention(self, cancelled=lambda:False):
        if not self.config.retention_enabled:
            raise ValueError('retention deletion is disabled in host configuration')
        cutoff = (datetime.now(timezone.utc)-timedelta(days=self.config.retention_days)).isoformat()
        with self.database._lock:
            rows = self.database.connection.execute("SELECT incident_id FROM incidents WHERE state='resolved' AND last_seen<? ORDER BY last_seen LIMIT 25",(cutoff,)).fetchall()
        deleted, archives = 0, []
        self.audit.append('retention',cutoff,'requested','resolved evidence only, archived before deletion')
        for row in rows:
            if cancelled():
                break
            bundle = self.database.get_incident_detail(row[0])
            if len(bundle['detections']) > 100 or len(bundle['events']) > 1000:
                continue
            path = self.archive(bundle)
            archives.append(str(path))
            with self.pipeline_lock, self.database._lock, self.database.connection:
                current = self.database.get_incident_detail(row[0])
                if current != bundle or current['incident']['state'] != 'resolved':
                    continue
                self.database.connection.execute('DELETE FROM alerts WHERE incident_id=?',(row[0],))
                self.database.connection.execute('DELETE FROM incident_notes WHERE incident_id=?',(row[0],))
                self.database.connection.execute('DELETE FROM incidents WHERE incident_id=?',(row[0],))
                self.database.connection.execute('DELETE FROM incident_detections WHERE incident_id=?',(row[0],))
                self.database.connection.execute('DELETE FROM incident_events WHERE incident_id=?',(row[0],))
                for detection in bundle['detections']:
                    removed = self.database.connection.execute("DELETE FROM detections WHERE detection_id=? AND NOT EXISTS (SELECT 1 FROM incident_detections WHERE detection_id=?)",(detection['detection_id'],detection['detection_id'])).rowcount
                    if removed:
                        self.database.connection.execute('DELETE FROM detection_events WHERE detection_id=?',(detection['detection_id'],))
                deleted += 1
        if not cancelled():
            with self.database._lock:
                raw = self.database.connection.execute(
                    "SELECT event_id,payload FROM host_events WHERE timestamp<? "
                    "AND NOT EXISTS(SELECT 1 FROM detection_events WHERE event_id=host_events.event_id) "
                    "AND NOT EXISTS(SELECT 1 FROM incident_events WHERE event_id=host_events.event_id) "
                    "AND NOT EXISTS(SELECT 1 FROM process_instances WHERE process_instances.event_id=host_events.event_id) LIMIT 250",(cutoff,)).fetchall()
            if raw:
                archives.append(str(self.archive({'events':[json.loads(row['payload']) for row in raw]})))
                with self.pipeline_lock, self.database._lock, self.database.connection:
                    for row in raw:
                        self.database.connection.execute(
                            "DELETE FROM host_events WHERE event_id=? AND NOT EXISTS(SELECT 1 FROM detection_events WHERE event_id=host_events.event_id) "
                            "AND NOT EXISTS(SELECT 1 FROM incident_events WHERE event_id=host_events.event_id) "
                            "AND NOT EXISTS(SELECT 1 FROM process_instances WHERE event_id=host_events.event_id)", (row['event_id'],))
        result = {'incidents_archived_and_deleted':deleted,'archives':archives,'timestamp':utc_now()}
        self.database.set_checkpoint('maintenance:retention',json.dumps(result))
        self.audit.append('retention',cutoff,'completed',f'{deleted} resolved incidents')
        return result
