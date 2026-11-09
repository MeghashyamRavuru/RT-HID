from __future__ import annotations

import hashlib
import json

from .models import utc_now


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


class AuditLog:
    def __init__(self, database):
        self.database = database

    def append(self, action, target, result, reason='', actor='admin'):
        values = [utc_now(),actor[:128],str(action)[:128],str(target)[:1024],str(result)[:128],str(reason)[:512]]
        with self.database._lock, self.database.connection:
            last = self.database.connection.execute('SELECT entry_hash FROM audit_history ORDER BY sequence DESC LIMIT 1').fetchone()
            previous = last[0] if last else '0'*64
            digest = hashlib.sha256((previous+canonical(values)).encode()).hexdigest()
            self.database.connection.execute('INSERT INTO audit_history(timestamp,actor,action,target,result,reason,previous_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?)',(*values,previous,digest))

    def page(self, limit, offset):
        with self.database._lock:
            total = self.database.connection.execute('SELECT COUNT(*) FROM audit_history').fetchone()[0]
            rows = self.database.connection.execute('SELECT * FROM audit_history ORDER BY sequence DESC LIMIT ? OFFSET ?',(limit,offset)).fetchall()
        return {'items':[dict(row) for row in rows],'total':total,'limit':limit,'offset':offset,
                'integrity_scope':'Append-only application history with hash chaining; host administrators can still alter storage.'}

    def verify(self):
        previous = '0'*64
        with self.database._lock:
            for row in self.database.connection.execute('SELECT * FROM audit_history ORDER BY sequence'):
                values = [row[key] for key in ('timestamp','actor','action','target','result','reason')]
                digest = hashlib.sha256((previous+canonical(values)).encode()).hexdigest()
                if row['previous_hash'] != previous or row['entry_hash'] != digest:
                    return False
                previous = digest
        return True
