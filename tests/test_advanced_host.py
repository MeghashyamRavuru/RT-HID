import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

from rt_hid.host.agent import HostAgent
from rt_hid.host.config import HostConfig
from rt_hid.host.models import HostEvent
from rt_hid.host.identity import instance_id


class AdvancedHostTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = HostConfig(host_id="test-host", database_path=Path(self.directory.name) / "test.sqlite3", enabled_collectors=set())
        self.agent = HostAgent(self.config)
        self.addCleanup(self.agent.stop)

    def process(self, pid, created, name, parent=None, parent_created=None, **kwargs):
        event = HostEvent.create("test-host", "process_start", "fixture", process_id=pid, process_name=name,
            parent_process_id=parent, metadata={"create_time": created, "parent_create_time": parent_created,
            "parent_name": kwargs.pop("parent_name", None)}, **kwargs)
        self.agent.ingest_event(event)
        return event

    def test_process_ancestry_uses_creation_time_and_survives_restart(self):
        parent = self.process(10, 100, "winword.exe")
        child = self.process(11, 101, "powershell.exe", 10, 100, parent_name="winword.exe")
        self.process(10, 200, "unrelated.exe")
        nodes = self.agent.processes.ancestry(instance_id("test-host", 11, 101))["nodes"]
        self.assertEqual([item["event_id"] for item in nodes], [child.event_id, parent.event_id])
        alerts = self.agent.database.list_alerts()
        self.assertEqual(alerts[0]["rule_id"], "HIDS-BEH-001")
        self.assertEqual(alerts[0]["evidence"]["pid"], 11)
        self.assertTrue(alerts[0]["evidence"]["parent_identity_verified"])

    def test_unknown_parent_is_not_linked_by_pid(self):
        self.process(10, 100, "parent")
        self.process(11, 101, "child", 10)
        self.assertEqual(len(self.agent.processes.ancestry(instance_id("test-host", 11, 101))["nodes"]), 1)
        self.assertIsNone(instance_id("test-host", 10, "nan"))

    def test_rule_allowlist_and_disable_persist(self):
        registry = self.agent.detector.registry
        registry.update("HIDS-BEH-001", {"allowlist": [{"username": "developer"}]})
        self.process(11, 101, "powershell.exe", parent_name="winword.exe", username="developer")
        self.assertEqual(self.agent.database.list_alerts(), [])
        registry.update("HIDS-BEH-001", {"enabled": False})
        from rt_hid.host.detection.registry import RuleRegistry
        self.assertFalse(RuleRegistry(self.config, self.agent.database).settings["HIDS-BEH-001"]["enabled"])
        with self.assertRaises(ValueError):
            registry.update("HIDS-BEH-001", {"python": "print('no')"})

    def test_migration_preserves_events(self):
        event = self.process(10, 100, "normal")
        self.assertGreaterEqual(int(self.agent.database.connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]), 2)
        self.assertEqual(json.loads(self.agent.database.connection.execute("SELECT payload FROM host_events WHERE event_id=?", (event.event_id,)).fetchone()[0])["process_id"], 10)

    def test_network_polling_baseline_dedup_and_pid_reuse(self):
        from rt_hid.host.collectors.linux import LinuxNetworkCollector
        address = lambda ip, port: SimpleNamespace(ip=ip, port=port)
        socket = SimpleNamespace(pid=42, type=1, laddr=address('192.0.2.1', 50000), raddr=address('198.51.100.2', 4444), status='ESTABLISHED')
        collector = LinuxNetworkCollector('test-host', lambda event: None)
        created = [100.0]
        with patch('psutil.net_connections', return_value=[]), patch('psutil.Process') as process:
            process.return_value.create_time.side_effect = lambda: created[0]
            process.return_value.name.return_value = 'powershell.exe'
            process.return_value.username.return_value = 'analyst'
            self.assertEqual(collector.run_once(), [])
            with patch('psutil.net_connections', return_value=[socket]):
                events = collector.run_once()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].event_type, 'network_connection')
                self.assertEqual(events[0].metadata['direction'], 'inferred_outbound')
                self.assertEqual(collector.run_once(), [])
                created[0] = 200.0
                self.assertEqual(len(collector.run_once()), 1)

    def test_ioc_import_matching_expiry_and_disable(self):
        self.config.threat_intelligence_enabled = True
        data = [{'type':'ip', 'value':'2001:0db8::1', 'source':'test-feed', 'confidence':.8},
                {'type':'sha256', 'value':'A'*64, 'expires_at':'2000-01-01T00:00:00Z'},
                {'type':'domain','value':'Example.TEST.','source':'domain-feed'}]
        self.agent.intelligence.import_data(json.dumps(data))
        self.agent.intelligence.import_data('type,value,source\nip,2001:db8::1,test-feed', 'csv')
        page = self.agent.intelligence.page(25, 0)
        self.assertEqual(page['total'], 3)
        event = HostEvent.create('test-host', 'network_connection', 'fixture', destination_ip='2001:db8::1', destination_port=443)
        self.agent.ingest_event(event)
        self.assertEqual(self.agent.database.list_alerts()[0]['rule_id'], 'HIDS-IOC-001')
        for item in page['items']:
            if item['type'] == 'ip':
                self.agent.intelligence.set_enabled(item['indicator_id'], False)
        self.assertEqual(self.agent.intelligence.match(event), [])
        expired = HostEvent.create('test-host', 'process_start', 'fixture', metadata={'executable_sha256':'a'*64})
        self.assertEqual(self.agent.intelligence.match(expired), [])
        domain = HostEvent.create('test-host','network_connection','fixture',destination_ip='198.51.100.1',destination_port=443,
            metadata={'destination_domain':'eXaMpLe.test.'})
        with patch('socket.getaddrinfo',side_effect=AssertionError('DNS must not be called')):
            self.assertEqual(self.agent.intelligence.match(domain)[0].evidence['indicators'][0]['value'],'example.test')
        with self.assertRaises(ValueError):
            self.agent.intelligence.import_data('[{"type":"ip","value":"not-an-ip"}]')
        with self.assertRaises(ValueError):
            self.agent.intelligence.import_data('[{"type":"domain","value":"192.0.2.1"}]')

    def test_persistence_baseline_changes_and_permission_preservation(self):
        from rt_hid.host.collectors.persistence import PersistenceCollector
        root = Path(self.directory.name) / 'startup'
        root.mkdir()
        self.config.persistence_paths = [root]
        self.config.persistence_verify_every_scans = 1
        collector = PersistenceCollector('test-host',self.config,self.agent.database,self.agent.ingest_event,'linux')
        path = root / 'example.service'
        path.write_text('initial')
        self.assertEqual(collector.run_once(), [])
        path.write_text('changed')
        events = collector.run_once()
        self.assertEqual(events[0].action, 'modify')
        self.assertNotIn('changed', json.dumps(events[0].evidence))
        with patch.object(collector,'files_snapshot',side_effect=PermissionError('private-message')):
            self.assertEqual(collector.run_once(), [])
            self.assertEqual(collector.status.collection_errors, 1)
            self.assertNotIn('private-message', collector.status.last_error)
        self.assertEqual(collector.run_once(), [])
        path.unlink()
        self.assertEqual(collector.run_once()[0].action,'delete')
        (root/'id_rsa').write_text('not read')
        self.assertEqual(collector.run_once(), [])

    def test_windows_registry_baseline_with_native_api_mock(self):
        import sys
        from rt_hid.host.collectors.persistence import PersistenceCollector
        self.config.persistence_paths = [Path(self.directory.name)/'missing']
        self.config.persistence_registry_enabled = True
        collector = PersistenceCollector('test-host',self.config,self.agent.database,lambda event: None,'windows')
        class Key:
            def __enter__(self): return self
            def __exit__(self,*args): pass
        values = []
        native = SimpleNamespace(HKEY_CURRENT_USER=1,HKEY_LOCAL_MACHINE=2,KEY_READ=1,
            OpenKey=lambda *args:Key(),QueryInfoKey=lambda key:(0,len(values),0),EnumValue=lambda key,index:values[index])
        with patch.dict(sys.modules, {'winreg':native}):
            self.assertEqual(collector.run_once(), [])
            values.append(('Updater', '"C:\\Tools\\updater.exe" --token=private-value', 1))
            events = collector.run_once()
            self.assertTrue(events)
            self.assertTrue(all(event.event_type == 'persistence_change' for event in events))
            self.assertNotIn('private-value',json.dumps([event.to_dict() for event in events]))

    def test_windows_task_event_excludes_arguments_and_raw_xml(self):
        from rt_hid.host.collectors.windows import parse_security_event
        import html
        task = '<Task><Actions><Exec><Command>C:\\Tools\\example.exe</Command><Arguments>--token=private</Arguments></Exec></Actions></Task>'
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4698</EventID>'
               '<EventRecordID>99</EventRecordID></System><EventData><Data Name="TaskName">Example</Data>'
               f'<Data Name="TaskContent">{html.escape(task)}</Data></EventData></Event>')
        event = parse_security_event(xml,'test-host')[1]
        self.assertEqual(event.event_type,'persistence_change')
        self.assertEqual(event.metadata['target_path'],r'C:\Tools\example.exe')
        self.assertNotIn('private',json.dumps(event.to_dict()))

    def test_correlation_requires_same_instance_host_and_time_window(self):
        self.config.correlation_window_seconds = 60
        process = self.process(42,100,'example',executable_path='/tmp/example', timestamp='2026-01-01T00:00:00+00:00')
        def connection(created, timestamp, host='test-host'):
            event = HostEvent.create(host,'network_connection','fixture',process_id=42,process_name='example',
                destination_ip='192.0.2.8',destination_port=443,metadata={'create_time':created},timestamp=timestamp)
            self.agent.ingest_event(event)
            return event
        connection(200,'2026-01-01T00:00:10+00:00')
        connection(100,'2026-01-01T00:00:10+00:00','other-host')
        connection(100,'2026-01-01T00:01:01+00:00')
        self.assertFalse(any(item['rule_id'].startswith('HIDS-CORR') for item in self.agent.database.list_alerts()))
        event = connection(100,'2026-01-01T00:00:30+00:00')
        alerts = [item for item in self.agent.database.list_alerts() if item['rule_id']=='HIDS-CORR-001']
        self.assertEqual(len(alerts),1)
        detail = self.agent.database.get_incident_detail(alerts[0]['incident_id'])
        self.assertEqual(set(item['event_id'] for item in detail['events']),{process.event_id,event.event_id})
        connection(100,'2026-01-01T00:00:40+00:00')
        self.assertEqual(len([item for item in self.agent.database.list_incidents() if item['rule_id']=='HIDS-CORR-001']),1)
        self.agent.ingest_event(event)
        self.assertEqual(len([item for item in self.agent.database.list_alerts() if item['rule_id']=='HIDS-CORR-001']),2)

    def test_process_chain_uses_verified_ancestry(self):
        self.process(1,100,'powershell.exe', timestamp='2026-01-01T00:00:00+00:00')
        self.process(2,101,'curl.exe',1,100,timestamp='2026-01-01T00:00:01+00:00')
        self.process(3,102,'payload.exe',2,101,executable_path='/tmp/payload',timestamp='2026-01-01T00:00:02+00:00')
        alerts = self.agent.database.list_alerts()
        self.assertTrue(any(item['rule_id']=='HIDS-BEH-005' for item in alerts))
        chain = next(item for item in alerts if item['rule_id']=='HIDS-BEH-005')
        detail = self.agent.database.get_incident_detail(chain['incident_id'])
        self.assertEqual(len(detail['events']),3)

    def test_yara_optional_scanning_is_scoped_and_records_no_contents(self):
        import sys
        with self.assertRaises(ValueError):
            self.agent.scanner.submit('any-file')
        root = Path(self.directory.name) / 'scans'; root.mkdir()
        sample = root/'example.bin'; sample.write_bytes(b'harmless test marker')
        rule = Path(self.directory.name)/'example.yar'; rule.write_text('rule example { condition: true }')
        self.config.yara_enabled = True
        self.config.yara_rule_paths = [rule]
        self.config.yara_scan_paths = [root]
        fake = SimpleNamespace(compile=lambda **kwargs:SimpleNamespace(match=lambda **args:[SimpleNamespace(rule='example')]))
        with patch.dict(sys.modules,{'yara':fake}):
            key = self.agent.scanner.submit(str(sample))
            self.agent.jobs.queue.join()
        result = self.agent.jobs.page()['items'][0]
        self.assertEqual(result['job_id'],key)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['payload']['result']['matched_rules'],['example'])
        alert = self.agent.database.list_alerts()[0]
        self.assertEqual(alert['rule_id'],'HIDS-YARA-001')
        self.assertNotIn('harmless test marker',json.dumps(alert))
        with self.assertRaises(ValueError):
            self.agent.scanner.validate_path(str(rule))
        with patch('rt_hid.host.scanning.importlib.import_module',side_effect=ImportError()):
            self.assertFalse(self.agent.scanner.status()['available'])

    def test_rule_thresholds_are_safe_and_effective(self):
        registry = self.agent.detector.registry
        with self.assertRaises(ValueError):
            registry.update('HIDS-AUTH-001',{'threshold':1})
        with self.assertRaises(ValueError):
            registry.update('HIDS-BEH-001',{'threshold':2})
        registry.update('HIDS-AUTH-001',{'threshold':2})
        for index in range(2):
            self.agent.ingest_event(HostEvent.create('test-host','auth','fixture',action='ssh_login',outcome='failure',source_ip='192.0.2.2'))
        self.assertEqual(self.agent.database.list_alerts()[0]['rule_id'],'HIDS-AUTH-001')

    def test_response_authorization_identity_and_append_only_audit(self):
        import os
        import sqlite3
        self.process(42,100,'example.exe')
        key = instance_id('test-host',42,100)
        self.agent.database.set_admin_password('example-local-admin-password')
        version = self.agent.database.auth_version()
        request = {'instance_id':key,'reason':'test authorization','password':'example-local-admin-password'}
        with self.assertRaises(PermissionError):
            self.agent.response.prepare(request,version)
        self.config.response_enabled = True
        confirmation = self.agent.response.prepare(request,version)
        target = SimpleNamespace(pid=42,create_time=lambda:100,name=lambda:'example.exe',terminate=Mock())
        own = SimpleNamespace(parents=lambda:[])
        with patch('psutil.Process', side_effect=lambda pid:own if pid==os.getpid() else target):
            result = self.agent.response.execute({'confirmation_token':confirmation['confirmation_token'],'confirm':True},version)
            self.assertEqual(result['status'],'termination_requested')
            target.terminate.assert_called_once()
            with self.assertRaises(PermissionError):
                self.agent.response.execute({'confirmation_token':confirmation['confirmation_token'],'confirm':True},version)
            confirmation = self.agent.response.prepare(request,version)
            target.create_time = lambda:200
            with self.assertRaises(ValueError):
                self.agent.response.execute({'confirmation_token':confirmation['confirmation_token'],'confirm':True},version)
            target.terminate.assert_called_once()
        self.assertTrue(self.agent.audit.verify())
        self.assertNotIn('example-local-admin-password',json.dumps(self.agent.audit.page(100,0)))
        with self.assertRaises(sqlite3.IntegrityError):
            self.agent.database.connection.execute('DELETE FROM audit_history')
        self.agent.database.connection.rollback()

    def test_backup_restore_validation_and_retention_protect_active_evidence(self):
        from rt_hid.host.maintenance import validate_backup, restore_backup
        old = HostEvent.create('test-host','file_change','fixture',file_path='/etc/old.conf',action='modify',timestamp='2000-01-01T00:00:00+00:00')
        active = HostEvent.create('test-host','file_change','fixture',file_path='/etc/active.conf',action='modify',timestamp='2000-01-01T00:00:01+00:00')
        self.agent.ingest_event(old); self.agent.ingest_event(active)
        alerts = self.agent.database.list_alerts()
        resolved = next(item for item in alerts if item['file_path']=='/etc/old.conf')
        active_alert = next(item for item in alerts if item['file_path']=='/etc/active.conf')
        active_incident = self.agent.database.get_incident(active_alert['incident_id'])
        active_incident['detection_ids'].append(resolved['detection_id'])
        self.agent.database.save_incident(active_incident)
        self.agent.alerts.resolve(resolved['incident_id'])
        backup = self.agent.maintenance.backup()
        self.assertEqual(validate_backup(Path(backup['path']))['integrity'],'ok')
        restored = Path(self.directory.name)/'restored.sqlite3'
        self.assertEqual(restore_backup(Path(backup['path']),restored)['integrity'],'ok')
        with self.assertRaises(ValueError):
            restore_backup(Path(backup['path']),restored)
        with self.assertRaises(ValueError):
            self.agent.maintenance.retention()
        self.config.retention_enabled = True
        result = self.agent.maintenance.retention()
        self.assertEqual(result['incidents_archived_and_deleted'],1)
        self.assertIsNone(self.agent.database.get_incident(resolved['incident_id']))
        self.assertIsNotNone(self.agent.database.connection.execute('SELECT 1 FROM host_events WHERE event_id=?',(active.event_id,)).fetchone())
        self.assertIsNotNone(self.agent.database.connection.execute('SELECT 1 FROM host_events WHERE event_id=?',(old.event_id,)).fetchone())
        self.assertIsNotNone(self.agent.database.connection.execute('SELECT 1 FROM detections WHERE detection_id=?',(resolved['detection_id'],)).fetchone())
        self.assertEqual(self.agent.maintenance.integrity()['integrity'],'ok')
        self.assertTrue(result['archives'])
        archive = json.loads(Path(result['archives'][0]).read_text())
        self.assertEqual(archive['bundle']['incident']['incident_id'],resolved['incident_id'])

    def test_existing_v1_database_migrates_without_losing_event(self):
        import sqlite3
        from rt_hid.host.storage import HostDatabase
        path = Path(self.directory.name)/'legacy.sqlite3'
        event = HostEvent.create('test-host','system_snapshot','fixture')
        with sqlite3.connect(path) as connection:
            connection.execute('CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            connection.execute("INSERT INTO schema_meta VALUES ('schema_version','1')")
            connection.execute('CREATE TABLE host_events(event_id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,host_id TEXT NOT NULL,event_type TEXT NOT NULL,source TEXT NOT NULL,payload TEXT NOT NULL)')
            connection.execute('INSERT INTO host_events VALUES (?,?,?,?,?,?)',(event.event_id,event.timestamp,event.host_id,event.event_type,event.source,json.dumps(event.to_dict())))
        connection.close()
        database = HostDatabase(path)
        try:
            self.assertEqual(database.connection.execute('SELECT COUNT(*) FROM host_events').fetchone()[0],1)
            self.assertEqual(database.connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0],'7')
        finally:
            database.close()

    def test_job_queue_is_bounded_and_cancellation_is_recorded(self):
        import threading
        entered, release = threading.Event(),threading.Event()
        def blocked(cancelled):
            entered.set(); release.wait(timeout=3); return {}
        self.agent.jobs.submit('test','bounded fixture',blocked)
        self.assertTrue(entered.wait(timeout=2))
        try:
            keys = [self.agent.jobs.submit('test','queued fixture',lambda cancelled:{}) for _ in range(4)]
            with self.assertRaises(ValueError):
                self.agent.jobs.submit('test','overflow fixture',lambda cancelled:{})
            self.agent.jobs.cancel(keys[0])
        finally:
            release.set()
        self.agent.jobs.queue.join()
        self.assertEqual(next(item for item in self.agent.jobs.page()['items'] if item['job_id']==keys[0])['status'],'cancelled')

    def test_persistence_sink_failure_keeps_baseline_and_retry_event_identity(self):
        from rt_hid.host.collectors.persistence import PersistenceCollector
        root = Path(self.directory.name)/'retry-startup'; root.mkdir()
        self.config.persistence_paths = [root]
        collector = PersistenceCollector('test-host',self.config,self.agent.database,lambda event:None,'linux')
        collector.run_once()
        (root/'example.service').write_text('test service')
        delivered=[]
        def fail(event):
            delivered.append(event.event_id)
            raise RuntimeError('private failure')
        collector.sink=fail
        self.assertEqual(collector.run_once(),[])
        collector.sink=lambda event:delivered.append(event.event_id)
        self.assertEqual(len(collector.run_once()),1)
        self.assertEqual(delivered[0],delivered[1])
        self.assertEqual(collector.run_once(),[])

    def test_temporary_script_and_persistence_mappings(self):
        event = HostEvent.create('test-host','process_start','fixture',process_name='wscript.exe',
            executable_path='D:/Windows/System32/wscript.exe',metadata={'command_line':['wscript.exe','D:/Windows/Temp/example.vbs']})
        findings = self.agent.detector.evaluate(event)
        self.assertTrue(any(item.rule_id=='HIDS-BEH-007' for item in findings))
        for path,technique in [('/etc/cron.d/example','T1053.003'),('/etc/systemd/system/example.timer','T1053.006'),('/home/test/.ssh/authorized_keys','T1098.004')]:
            event=HostEvent.create('test-host','persistence_change','fixture',file_path=path,action='modify')
            finding=self.agent.detector.evaluate(event)[0]
            self.assertEqual(finding.technique_id,technique)

    def test_unchanged_persistence_scan_does_not_write_database(self):
        from rt_hid.host.collectors.persistence import PersistenceCollector
        root=Path(self.directory.name)/'quiet-startup';root.mkdir()
        (root/'example.service').write_text('harmless fixture')
        self.config.persistence_paths=[root]
        self.config.persistence_verify_every_scans=1
        collector=PersistenceCollector('test-host',self.config,self.agent.database,lambda event:None,'linux')
        collector.run_once()
        written=self.agent.database.connection.total_changes
        self.assertEqual(collector.run_once(),[])
        self.assertEqual(self.agent.database.connection.total_changes,written)

    def test_sysmon_network_direction_and_pid_reuse(self):
        from rt_hid.host.collectors.windows import parse_sysmon_network_event
        fields={'ProcessId':'42','Image':r'C:\Tools\client.exe','Initiated':'true','SourceIp':'192.0.2.1','SourcePort':'50000',
            'DestinationIp':'198.51.100.1','DestinationPort':'443','Protocol':'tcp','DestinationHostname':'example.test'}
        xml=('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>3</EventID>'
            '<EventRecordID>10</EventRecordID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/></System><EventData>'+
            ''.join(f'<Data Name="{key}">{value}</Data>' for key,value in fields.items())+'</EventData></Event>')
        with patch('psutil.Process') as process:
            process.return_value.create_time.return_value=2000000000.0
            process.return_value.exe.return_value=fields['Image']
            event=parse_sysmon_network_event(xml,'test-host')[1]
        self.assertIsNone(event.metadata['create_time'])
        self.assertEqual(event.metadata['direction'],'outbound')
        self.assertEqual(event.metadata['destination_domain'],'example.test')
        self.assertIsNone(parse_sysmon_network_event(xml.replace('>true<','>false<'),'test-host'))
