"""Normalize authentication outcomes, without counting secondary log messages as attempts."""
from __future__ import annotations

import ipaddress
import re

from .models import HostEvent


_SSH_DAEMON = re.compile(r'(?:^|\s)sshd(?:-session|-auth)?(?:\[(?P<pid>\d{1,10})\])?:\s*', re.IGNORECASE)
_SSH_RESULT = re.compile(
    r'(?P<result>Failed|Accepted)\s+(?P<method>[a-z0-9/._-]{1,64})\s+for\s+'
    r'(?:(?P<invalid>invalid user)\s+)?(?P<username>\S{1,128})\s+from\s+'
    r'(?P<address>\S{1,128})\s+port\s+(?P<port>\d{1,5})(?=\s|$)', re.IGNORECASE)
_SUDO_FAILURE = re.compile(
    r'(?:^|\s)sudo(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<username>[^\s:;]{1,128})\s*:\s*'
    r'(?P<attempts>\d{1,4})\s+incorrect password attempts?\b', re.IGNORECASE)
_VSFTPD_LOGIN = re.compile(
    r'(?:\[pid\s+\d+\]|\bvsftpd(?:\[\d+\])?:)\s*'
    r'(?:\[(?P<username>[^\]\r\n]{1,128})\]\s*)?'
    r'(?P<result>FAIL|OK)\s+LOGIN:\s+Client\s+"(?P<address>[^"\r\n]{1,128})"', re.IGNORECASE)
_VSFTPD_CONNECT = re.compile(
    r'(?:\[pid\s+\d+\]|\bvsftpd(?:\[\d+\])?:)\s*'
    r'CONNECT:\s+Client\s+"(?P<address>[^"\r\n]{1,128})"', re.IGNORECASE)
_PROFTPD_LOGIN = re.compile(
    r'\bproftpd\[\d+\]:\s+[^\r\n]{0,256}?\('
    r'[^\[\]\r\n]{0,128}\[(?P<address>[^\]\r\n]{1,128})\]\)\s*[-:]?\s*'
    r'(?:-\s*)?USER\s+(?P<username>\S{1,128})'
    r'(?:\s+\(Login failed\):|:\s+Login successful\b)', re.IGNORECASE)


def remote_auth_address(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def redact_auth_line(line: str) -> str:
    return re.sub(r'(password|passwd|token|secret)=?\S*', r'\1=<redacted>', line, flags=re.IGNORECASE).strip()


def parse_linux_auth_line(line: str, host_id: str) -> HostEvent | None:
    daemon = _SSH_DAEMON.search(line)
    result = _SSH_RESULT.match(line, daemon.end()) if daemon else _SSH_RESULT.match(line.lstrip())
    if daemon or result:
        if result is None:
            # PAM failures, Invalid user notices and aggregate summaries describe
            # authentication context, not an additional password attempt.
            return None
        method = result['method'].lower()
        outcome = 'failure' if result['result'].lower() == 'failed' else 'success'
        supported = {'password', 'keyboard-interactive', 'challenge-response'} if outcome == 'failure' else {
            'password', 'publickey', 'keyboard-interactive', 'challenge-response', 'hostbased', 'gssapi-with-mic'}
        address = remote_auth_address(result['address'])
        port = int(result['port'])
        if method.split('/', 1)[0] not in supported or address is None or not 1 <= port <= 65535:
            return None
        return HostEvent.create(host_id, 'auth', 'linux_auth_log', action='ssh_login', outcome=outcome,
            username=result['username'], source_ip=address,
            metadata={'auth_method': method, 'source_port': port,
                      'daemon_pid': int(daemon['pid']) if daemon and daemon['pid'] else None,
                      'invalid_user': result['invalid'] is not None},
            evidence={'line': redact_auth_line(line)})

    sudo = _SUDO_FAILURE.search(line)
    if sudo and int(sudo['attempts']) > 0:
        return HostEvent.create(host_id, 'auth', 'linux_auth_log', action='sudo', outcome='failure',
            username=sudo['username'], metadata={'reported_attempts': int(sudo['attempts'])},
            evidence={'line': redact_auth_line(line)})
    return None


def parse_linux_ftp_line(line: str, host_id: str) -> HostEvent | None:
    vsftpd = _VSFTPD_LOGIN.search(line)
    proftpd = _PROFTPD_LOGIN.search(line) if vsftpd is None else None
    result = vsftpd or proftpd
    if result is None:
        return None
    address = remote_auth_address(result['address'])
    if address is None:
        return None
    outcome = ('failure' if result['result'].upper() == 'FAIL' else 'success') if vsftpd else (
        'failure' if '(login failed)' in result.group(0).lower() else 'success')
    username = result['username'] if result['username'] else None
    return HostEvent.create(host_id, 'auth', 'linux_ftp_log', action='ftp_login', outcome=outcome,
        username=username, source_ip=address, metadata={'ftp_server': 'vsftpd' if vsftpd else 'proftpd'},
        evidence={'ftp_server': 'vsftpd' if vsftpd else 'proftpd', 'outcome': outcome})


def parse_vsftpd_connection_line(line: str, host_id: str) -> HostEvent | None:
    result = _VSFTPD_CONNECT.search(line)
    if result is None:
        return None
    address = remote_auth_address(result['address'])
    if address is None:
        return None
    return HostEvent.create(host_id, 'network_connection', 'linux_ftp_log', action='connect', outcome='observed',
        source_ip=address, protocol='TCP', metadata={'ftp_server': 'vsftpd', 'direction': 'inbound'},
        evidence={'ftp_server': 'vsftpd', 'direction': 'inbound'})
