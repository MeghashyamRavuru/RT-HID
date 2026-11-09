from __future__ import annotations

import json

from .identity import event_instance, instance_id
from .models import HostEvent


class ProcessGraph:
    def __init__(self, database) -> None:
        self.database = database

    def observe(self, event: HostEvent) -> None:
        key = event_instance(event)
        if key is None:
            return
        with self.database._lock, self.database.connection:
            if event.event_type == "process_stop":
                self.database.connection.execute(
                    "UPDATE process_instances SET stopped_at=?, last_seen=? WHERE instance_id=?",
                    (event.timestamp, event.timestamp, key))
            elif event.event_type == "process_start":
                created = event.metadata.get("create_time", event.evidence.get("create_time"))
                parent = instance_id(event.host_id, event.parent_process_id, event.metadata.get("parent_create_time"))
                if parent and float(event.metadata['parent_create_time']) > float(created):
                    parent = None
                self.database.connection.execute(
                    "INSERT OR IGNORE INTO process_instances(instance_id,host_id,pid,created,parent_id,first_seen,last_seen,event_id,payload) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (key, event.host_id, event.process_id, float(event.metadata.get("create_time", event.evidence.get("create_time"))),
                     parent, event.timestamp, event.timestamp, event.event_id, json.dumps(event.to_dict())))

    def get(self, key: str) -> dict | None:
        with self.database._lock:
            row = self.database.connection.execute("SELECT * FROM process_instances WHERE instance_id=?", (key,)).fetchone()
        if not row:
            return None
        return self.decode(row)

    @staticmethod
    def decode(row):
        result = dict(row)
        result["event"] = json.loads(result.pop("payload"))
        return result

    def ancestry(self, key: str, depth: int = 16) -> dict:
        with self.database._lock:
            rows = self.database.connection.execute(
                'WITH RECURSIVE lineage(instance_id,depth) AS (SELECT instance_id,0 FROM process_instances WHERE instance_id=? '
                'UNION ALL SELECT process_instances.parent_id,lineage.depth+1 FROM process_instances JOIN lineage '
                'ON process_instances.instance_id=lineage.instance_id WHERE lineage.depth<? AND process_instances.parent_id IS NOT NULL) '
                'SELECT process_instances.* FROM lineage JOIN process_instances ON process_instances.instance_id=lineage.instance_id ORDER BY lineage.depth',
                (key,max(0,min(depth,32)-1))).fetchall()
        nodes,seen = [],set()
        for row in rows:
            if row['instance_id'] in seen:
                break
            seen.add(row['instance_id']); nodes.append(self.decode(row))
        current = nodes[-1]['parent_id'] if nodes else key
        return {"nodes": nodes, "complete": bool(nodes and not current and nodes[-1]['event'].get('parent_process_id') == 0),
                "missing_parent_id": current if current and current not in {item['instance_id'] for item in nodes} else None,
                "missing_parent_pid":nodes[-1]['event'].get('parent_process_id') if nodes and not current else None,
                "identity": "host, PID and creation time; missing parents are not inferred from PID"}

    def children(self, key: str, limit: int = 100) -> list[dict]:
        with self.database._lock:
            rows = self.database.connection.execute(
                "SELECT * FROM process_instances WHERE parent_id=? ORDER BY first_seen LIMIT ?", (key, limit)).fetchall()
        return [self.decode(row) for row in rows]
