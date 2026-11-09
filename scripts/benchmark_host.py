"""Synthetic host-monitoring benchmark; no production process, network or persistence changes."""
import json
import os
import platform
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psutil

from rt_hid.host.agent import HostAgent
from rt_hid.host.collectors.linux import LinuxNetworkCollector
from rt_hid.host.config import HostConfig
from rt_hid.host.models import HostEvent


def main():
    own = psutil.Process(os.getpid())
    with tempfile.TemporaryDirectory() as temporary:
        agent = HostAgent(HostConfig(host_id='benchmark-fixture',database_path=Path(temporary)/'benchmark.sqlite3',enabled_collectors=set()))
        try:
            cpu_start, rss_start = sum(own.cpu_times()[:2]),own.memory_info().rss
            started = time.perf_counter()
            for index in range(500):
                agent.ingest_event(HostEvent.create('benchmark-fixture','process_start','synthetic_benchmark',
                    process_id=index+1000, process_name='fixture.exe',
                    executable_path='/tmp/fixture' if index%50==0 else '/usr/bin/fixture',
                    metadata={'create_time':1000.+index}))
            elapsed = time.perf_counter()-started
            cpu, rss = sum(own.cpu_times()[:2])-cpu_start, own.memory_info().rss-rss_start
            collector = LinuxNetworkCollector('benchmark-fixture',lambda event:None)
            sockets = [SimpleNamespace(pid=None,type=1,status='ESTABLISHED',
                laddr=SimpleNamespace(ip='192.0.2.1',port=10000+index),raddr=SimpleNamespace(ip='198.51.100.1',port=443)) for index in range(1000)]
            with patch('psutil.net_connections',return_value=[]):
                collector.run_once()
            with patch('psutil.net_connections',return_value=sockets):
                collector.run_once()
            print(json.dumps({'platform':platform.system(),'python':platform.python_version(),'fixture_events':500,
                'elapsed_seconds':round(elapsed,4),'cpu_seconds':round(cpu,4),'cpu_percent_one_core':round(100*cpu/elapsed,2),
                'rss_delta_bytes':rss,'rss_total_bytes':own.memory_info().rss,'events_per_second':round(500/elapsed,2),
                'synthetic_socket_count':1000,'socket_scan_seconds':round(collector.status.last_duration_seconds,4),
                'scope':'Synthetic event ingestion and mocked socket snapshots; not a long-running production load test.'},indent=2))
        finally:
            agent.stop()


if __name__=='__main__':
    main()
