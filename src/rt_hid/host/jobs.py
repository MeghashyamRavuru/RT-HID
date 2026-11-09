from __future__ import annotations

import json
import queue
import threading
import uuid
import logging
from datetime import datetime, timezone

from .models import utc_now


class JobRunner:
    """One worker and at most four pending jobs; callbacks are trusted internal code."""
    def __init__(self, database):
        self.database = database
        self.queue = queue.Queue(maxsize=4)
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.audit = None
        self.last_error = None

    def write(self, key, kind, status, data):
        now = utc_now()
        with self.database._lock, self.database.connection:
            self.database.connection.execute(
                'INSERT INTO background_jobs VALUES (?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at,payload=excluded.payload',
                (key,kind,status,now,now,json.dumps(data)))

    def submit(self, kind, target, function, actor='admin'):
        with self.lock:
            if self.stop_event.is_set() or self.queue.full():
                raise ValueError('background job queue unavailable or full')
            key = uuid.uuid4().hex
            self.write(key,kind,'queued',{'target':target})
            if self.audit:
                self.audit.append('job_'+kind,target,'requested',actor=actor)
            self.queue.put_nowait((key,kind,target,function))
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self.run,name='rt-hid-jobs',daemon=True)
                self.thread.start()
        return key

    def recover(self):
        if self.thread is None and self.queue.empty():
            with self.database._lock,self.database.connection:
                count = self.database.connection.execute("UPDATE background_jobs SET status='interrupted',updated_at=? WHERE status IN ('queued','running')",(utc_now(),)).rowcount
                if count and self.audit:
                    self.audit.append('job_recovery','background queue','interrupted',str(count)+' jobs from previous run',actor='system')

    def cancelled(self, key):
        with self.database._lock:
            row = self.database.connection.execute('SELECT status FROM background_jobs WHERE job_id=?',(key,)).fetchone()
        return self.stop_event.is_set() or row is None or row[0] == 'cancelled'

    def cancel(self, key):
        with self.database._lock, self.database.connection:
            row = self.database.connection.execute('SELECT status,kind,payload FROM background_jobs WHERE job_id=?',(key,)).fetchone()
            if row is None:
                raise KeyError(key)
            if row[0] not in {'queued','running'}:
                raise ValueError('job has already completed')
            self.database.connection.execute("UPDATE background_jobs SET status='cancelled',updated_at=? WHERE job_id=?",(utc_now(),key))
            if self.audit:
                self.audit.append('job_'+row['kind'],json.loads(row['payload']).get('target',''),'cancellation_requested')

    def run(self):
        while not self.stop_event.is_set():
            try:
                key,kind,target,function = self.queue.get(timeout=.2)
            except queue.Empty:
                continue
            try:
                if self.cancelled(key):
                    continue
                self.write(key,kind,'running',{'target':target})
                result = function(lambda:self.cancelled(key))
                if not self.cancelled(key):
                    self.write(key,kind,'completed',{'target':target,'result':result})
                    if self.audit:
                        self.audit.append('job_'+kind,target,'completed',actor='system')
                elif self.audit:
                    self.audit.append('job_'+kind,target,'cancelled',actor='system')
            except Exception as error:
                if not self.stop_event.is_set():
                    try:
                        self.write(key,kind,'failed',{'target':target,'error':type(error).__name__})
                        if self.audit:
                            self.audit.append('job_'+kind,target,'failed',type(error).__name__,actor='system')
                    except Exception as storage_error:
                        self.last_error='job_state: '+type(storage_error).__name__
                        logging.getLogger('rt_hid.host').exception('Background job state could not be persisted')
            finally:
                self.queue.task_done()

    def page(self, limit=25, offset=0):
        with self.database._lock:
            total = self.database.connection.execute('SELECT COUNT(*) FROM background_jobs').fetchone()[0]
            oldest = self.database.connection.execute("SELECT MIN(created_at) FROM background_jobs WHERE status='queued'").fetchone()[0]
            rows = self.database.connection.execute('SELECT * FROM background_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?',(limit,offset)).fetchall()
        return {'items':[{**dict(row),'payload':json.loads(row['payload'])} for row in rows], 'total':total,'limit':limit,'offset':offset,
            'queue_depth':self.queue.qsize(),'queue_capacity':4,'workers':1,'worker_running':bool(self.thread and self.thread.is_alive()),
            'oldest_queued_seconds':max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(oldest)).total_seconds()) if oldest else 0,'last_error':self.last_error}

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=70)
        with self.database._lock, self.database.connection:
            self.database.connection.execute("UPDATE background_jobs SET status='cancelled',updated_at=? WHERE status IN ('queued','running')",(utc_now(),))
