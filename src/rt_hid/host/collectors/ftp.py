"""IIS FTP authentication outcomes from W3C site logs."""
from __future__ import annotations

from pathlib import Path

from ..auth_telemetry import remote_auth_address
from ..config import HostConfig
from ..models import CollectorStatus, HostEvent
from ..storage import HostDatabase
from .base import Collector, EventSink


def parse_iis_ftp_line(line: str, fields: list[str], host_id: str) -> HostEvent | None:
    values = line.split()
    if len(values) != len(fields):
        return None
    record = dict(zip(fields, values))
    if record.get('cs-method', '').upper() != 'PASS':
        return None
    status = record.get('sc-status')
    if status not in {'230', '530'}:
        return None
    address = remote_auth_address(record.get('c-ip'))
    if address is None:
        return None
    username = record.get('cs-username')
    outcome = 'failure' if status == '530' else 'success'
    return HostEvent.create(host_id, 'auth', 'windows_iis_ftp_log', action='ftp_login', outcome=outcome,
        source_ip=address, username=username if username and username != '-' else None,
        metadata={'ftp_server': 'iis'}, evidence={'ftp_server': 'iis', 'ftp_status': status})


class WindowsFtpCollector(Collector):
    collector_id = 'windows_ftp'

    def __init__(self, host_id: str, config: HostConfig, database: HostDatabase, sink: EventSink) -> None:
        super().__init__(host_id, sink)
        self.paths = config.windows_ftp_log_paths
        self.database = database
        self.status = CollectorStatus(self.collector_id, 'windows', False, True,
                                      capabilities={'mechanism': 'IIS FTP W3C log'})

    def _log_files(self) -> list[Path]:
        files: set[Path] = set()
        for path in self.paths:
            if path.is_file():
                files.add(path)
            elif path.is_dir():
                files.update(path.glob('FTPSVC*/u_ex*.log'))
                files.update(path.glob('u_ex*.log'))
        return sorted(files)[:256]

    def collect_once(self) -> list[HostEvent]:
        files = self._log_files()
        if not files:
            raise RuntimeError('IIS FTP log unavailable; check the configured log paths')
        initialized_key = 'windows_ftp:initialized'
        initialized = self.database.get_checkpoint(initialized_key) is not None
        events: list[HostEvent] = []
        remaining = 2048
        for path in files:
            if remaining == 0:
                break
            checkpoint_id = f'windows_ftp:{path}'
            saved = self.database.get_checkpoint(checkpoint_id)
            with path.open('r', encoding='utf-8-sig', errors='replace') as stream:
                fields: list[str] = []
                for _ in range(32):
                    header = stream.readline()
                    if not header:
                        break
                    if header.startswith('#Fields: '):
                        fields = header[9:].strip().split()
                        break
                if not fields:
                    continue
                offset = int(saved) if saved and saved.isdigit() else path.stat().st_size if not initialized else 0
                if offset > path.stat().st_size:
                    offset = 0
                stream.seek(offset)
                while remaining:
                    line = stream.readline()
                    if not line:
                        break
                    remaining -= 1
                    if line.startswith('#Fields: '):
                        fields = line[9:].strip().split()
                    elif not line.startswith('#'):
                        event = parse_iis_ftp_line(line, fields, self.host_id)
                        if event:
                            events.append(event)
                self.database.set_checkpoint(checkpoint_id, str(stream.tell()))
        self.database.set_checkpoint(initialized_key, '1')
        return events
