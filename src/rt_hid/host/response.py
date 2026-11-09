from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

from .identity import instance_id, process_name

PROTECTED = {'system','registry','smss.exe','csrss.exe','lsass.exe','wininit.exe','winlogon.exe','services.exe','svchost.exe','systemd','init','kernel_task'}


class ResponseService:
    def __init__(self, config, database, graph, audit):
        self.config,self.database,self.graph,self.audit = config,database,graph,audit

    def status(self):
        return {'enabled':self.config.response_enabled, 'supported_actions':['terminate_process'],
                'unsupported_actions':['disable_persistence','firewall_block'],
                'confirmation_seconds':60,'rollback':'Process termination cannot be undone. Restart approved software through its normal launcher or service manager.'}

    def prepare(self, data, actor_version):
        target = data.get('instance_id','')
        reason = data.get('reason','')
        self.audit.append('terminate_process',str(target),'requested')
        if set(data) != {'instance_id','reason','password'} or not isinstance(target,str) or len(target)!=64 or not isinstance(reason,str) or not 1 <= len(reason.strip()) <= 512 or not isinstance(data.get('password'),str):
            self.audit.append('terminate_process',str(target),'denied','invalid request')
            raise ValueError('instance_id, reason and password are required')
        if not self.config.response_enabled or not self.database.verify_admin_password(data.get('password','')):
            self.audit.append('terminate_process',target,'denied','disabled or administrator verification failed')
            raise PermissionError('response is disabled or administrator verification failed')
        node = self.graph.get(target)
        if not node:
            self.audit.append('terminate_process',target,'denied','unknown process instance')
            raise ValueError('unknown process instance')
        token = secrets.token_urlsafe(32)
        with self.database._lock, self.database.connection:
            self.database.connection.execute('DELETE FROM response_requests WHERE expires_at<?',(time.time(),))
            count = self.database.connection.execute('SELECT COUNT(*) FROM response_requests').fetchone()[0]
            if count >= 100:
                raise ValueError('too many pending response confirmations')
            self.database.connection.execute('INSERT INTO response_requests VALUES (?,?,?,?,?)',
                (hashlib.sha256(token.encode()).hexdigest(),str(actor_version),time.time()+60,0,
                 json.dumps({'instance_id':target,'pid':node['pid'],'host_id':node['host_id'],'reason':reason.strip()})))
        return {'confirmation_token':token,'expires_in_seconds':60,'target_pid':node['pid'],'action':'terminate_process'}

    def execute(self, data, actor_version):
        token = data.get('confirmation_token')
        if set(data) != {'confirmation_token','confirm'} or data.get('confirm') is not True or not isinstance(token,str) or len(token)>256:
            self.audit.append('terminate_process','unknown','denied','confirmation required')
            raise ValueError('explicit confirmation required')
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.database._lock, self.database.connection:
            row = self.database.connection.execute('SELECT * FROM response_requests WHERE token_hash=?',(token_hash,)).fetchone()
            if not row or row['used'] or row['expires_at'] < time.time() or row['actor_version'] != str(actor_version):
                self.audit.append('terminate_process','unknown','denied','invalid or expired authorization')
                raise PermissionError('invalid or expired response authorization')
            target = json.loads(row['payload'])
            self.database.connection.execute('UPDATE response_requests SET used=1 WHERE token_hash=?',(token_hash,))
        try:
            if not self.config.response_enabled:
                raise PermissionError('response disabled')
            import psutil
            process = psutil.Process(target['pid'])
            if instance_id(target['host_id'],target['pid'],process.create_time()) != target['instance_id']:
                raise ValueError('process instance changed or exited')
            own = psutil.Process(os.getpid())
            protected_pids = {0,1,4,os.getpid(),*[parent.pid for parent in own.parents()]}
            if process.pid in protected_pids or process_name(process.name()) in PROTECTED:
                raise PermissionError('protected process')
            process.terminate()
            self.audit.append('terminate_process',target['instance_id'],'termination_requested',target['reason'])
            return {'status':'termination_requested','pid':target['pid'],'rollback':self.status()['rollback']}
        except Exception as error:
            self.audit.append('terminate_process',target['instance_id'],'failed',type(error).__name__)
            raise ValueError('response failed: '+type(error).__name__) from None
