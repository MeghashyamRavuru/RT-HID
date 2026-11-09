import tempfile
import unittest
from pathlib import Path

from rt_hid.host.agent import HostAgent
from rt_hid.host.auth_telemetry import parse_linux_auth_line, parse_linux_ftp_line, remote_auth_address
from rt_hid.host.collectors.ftp import WindowsFtpCollector, parse_iis_ftp_line
from rt_hid.host.collectors.linux import LinuxAuthCollector
from rt_hid.host.config import HostConfig
from rt_hid.host.models import HostEvent


class AuthTelemetryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.log = Path(directory.name) / 'auth.log'
        self.log.write_text('', encoding='utf-8')
        self.config = HostConfig(host_id='ssh-host', database_path=Path(directory.name) / 'host.sqlite3',
                                 auth_log_paths=[self.log], enabled_collectors=set())
        self.agent = HostAgent(self.config)
        self.addCleanup(self.agent.stop)
        self.collector = LinuxAuthCollector('ssh-host', self.config, self.agent.database, self.agent.ingest_event)

    def line(self, message, daemon='sshd', pid=100):
        return f'Nov 9 12:00:00 host {daemon}[{pid}]: {message}\n'

    def append(self, lines):
        with self.log.open('a', encoding='utf-8') as stream:
            stream.writelines(lines)

    def attempt_lines(self, count, invalid=False):
        for index in range(count):
            if invalid:
                yield self.line('Invalid user sshuser from 192.0.2.129 port 50000', pid=100 + index)
            yield self.line('pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh '
                            'ruser= rhost=192.0.2.129 user=sshuser', pid=100 + index)
            yield self.line('Failed password for ' + ('invalid user ' if invalid else '') +
                            'sshuser from 192.0.2.129 port 50000 ssh2', pid=100 + index)
            yield self.line('PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh '
                            'ruser= rhost=192.0.2.129 user=sshuser', pid=100 + index)

    def test_mixed_ssh_logs_count_one_attempt_and_create_one_ip_incident(self):
        self.assertEqual(self.collector.run_once(), [])
        self.append(self.attempt_lines(4))
        self.assertEqual(len(self.collector.run_once()), 4)
        self.assertEqual(self.agent.database.list_alerts(), [])
        self.append(self.attempt_lines(1))
        self.assertEqual(len(self.collector.run_once()), 1)
        alerts = self.agent.database.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(self.agent.database.list_incidents()), 1)
        self.assertEqual(alerts[0]['evidence'], {'action': 'ssh_login', 'attempts': 5,
                                              'source_ip': '192.0.2.129', 'username': 'sshuser'})
        self.assertEqual(self.collector.run_once(), [])

    def test_invalid_user_notice_does_not_double_count_password_failure(self):
        self.collector.run_once()
        self.append(self.attempt_lines(5, invalid=True))
        events = self.collector.run_once()
        self.assertEqual(len(events), 5)
        self.assertTrue(all(event.metadata['invalid_user'] for event in events))
        alert = self.agent.database.list_alerts()[0]
        self.assertEqual(alert['evidence']['attempts'], 5)
        self.assertEqual(alert['evidence']['username'], 'sshuser')
        self.assertEqual(len(self.agent.database.list_incidents()), 1)

    def test_pam_context_and_other_daemons_are_not_ssh_attempts(self):
        for text in (
            self.line('pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1 user=alice'),
            self.line('error: PAM: Authentication failure for alice from 192.0.2.1'),
            self.line('Invalid user alice from 192.0.2.1 port 50000'),
            self.line('pam_unix(sudo:auth): authentication failure; user=root', daemon='sudo'),
            self.line('authentication failure; user=alice', daemon='login'),
            self.line('Failed password for alice from 192.0.2.1 port 50000 ssh2', daemon='other-app'),
        ):
            with self.subTest(text=text):
                self.assertIsNone(parse_linux_auth_line(text, 'ssh-host'))

    def test_direct_sshd_log_output_is_still_supported(self):
        event = parse_linux_auth_line('Failed password for sshuser from 192.0.2.129 port 50000 ssh2\n', 'ssh-host')
        self.assertEqual(event.username, 'sshuser')
        self.assertEqual(event.source_ip, '192.0.2.129')
        self.assertIsNone(event.metadata['daemon_pid'])

    def test_ipv6_split_daemons_and_success_after_failures(self):
        for _ in range(5):
            self.agent.ingest_event(parse_linux_auth_line(self.line(
                'Failed keyboard-interactive/pam for alice from 2001:0db8::1 port 50000 ssh2',
                daemon='sshd-auth'), 'ssh-host'))
        success = parse_linux_auth_line(self.line(
            'Accepted publickey for alice from 2001:db8::1 port 50000 ssh2: ED25519 SHA256:test',
            daemon='sshd-session'), 'ssh-host')
        self.assertEqual(success.source_ip, '2001:db8::1')
        self.assertEqual(success.outcome, 'success')
        self.agent.ingest_event(success)
        alerts = self.agent.database.list_alerts()
        self.assertEqual({item['rule_id'] for item in alerts}, {'HIDS-AUTH-001', 'HIDS-AUTH-003'})
        self.assertTrue(all(item['evidence']['source_ip'] == '2001:db8::1' for item in alerts))

    def test_unknown_or_invalid_ssh_sources_do_not_fall_back_to_host(self):
        for source in (None, '', '-', 'not-an-ip', '0.0.0.0'):
            for _ in range(5):
                self.agent.ingest_event(HostEvent.create('ssh-host', 'auth', 'fixture', action='ssh_login',
                    outcome='failure', source_ip=source, username=None))
        self.assertEqual(self.agent.database.list_alerts(), [])
        self.assertEqual(self.agent.database.list_incidents(), [])
        self.assertEqual(self.agent.database.connection.execute('SELECT COUNT(*) FROM host_events').fetchone()[0], 25)

    def test_sudo_retains_local_username_and_is_not_classified_as_ssh(self):
        for _ in range(5):
            event = parse_linux_auth_line(self.line(
                'alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/true',
                daemon='sudo'), 'ssh-host')
            self.assertEqual(event.action, 'sudo')
            self.assertEqual(event.username, 'alice')
            self.agent.ingest_event(event)
        alert = self.agent.database.list_alerts()[0]
        self.assertEqual(alert['rule_id'], 'HIDS-AUTH-002')
        self.assertEqual(alert['evidence']['username'], 'alice')

    def test_identical_primary_results_are_not_collapsed_into_one_guess(self):
        self.collector.run_once()
        primary = self.line('Failed password for sshuser from 192.0.2.129 port 50000 ssh2')
        self.append([primary] * 5)
        self.assertEqual(len(self.collector.run_once()), 5)
        self.assertEqual(self.agent.database.list_alerts()[0]['evidence']['attempts'], 5)

    def test_ip_normalization_and_malformed_results(self):
        self.assertEqual(remote_auth_address('::ffff:192.0.2.129'), '192.0.2.129')
        self.assertEqual(remote_auth_address('2001:0db8::1'), '2001:db8::1')
        for message in (
            'Failed password for alice from not-an-ip port 50000 ssh2',
            'Failed password for alice from 192.0.2.1 port 99999 ssh2',
            'Failed password for alice',
            'Failed none for alice from 192.0.2.1 port 50000 ssh2',
        ):
            self.assertIsNone(parse_linux_auth_line(self.line(message), 'ssh-host'))

    def test_vsftpd_outcomes_ignore_connections_and_create_one_ip_incident(self):
        ftp_log = self.log.parent / 'vsftpd.log'
        ftp_log.write_text('', encoding='utf-8')
        self.collector.paths.append(ftp_log)
        self.assertEqual(self.collector.run_once(), [])
        with ftp_log.open('a', encoding='utf-8') as stream:
            stream.write('Mon Nov  9 18:52:26 2026 [pid 24627] CONNECT: Client "192.0.2.129"\n')
            stream.write('Mon Nov  9 18:52:27 2026 [pid 24624] [ftpuser] OK LOGIN: Client "192.0.2.129"\n')
            for index in range(5):
                stream.write(f'Mon Nov  9 18:52:29 2026 [pid {24628 + index}] '
                             '[ftpuser] FAIL LOGIN: Client "192.0.2.129"\n')
        events = self.collector.run_once()
        self.assertEqual(len(events), 6)
        self.assertTrue(all(event.action == 'ftp_login' for event in events))
        alerts = self.agent.database.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(self.agent.database.list_incidents()), 1)
        self.assertEqual(alerts[0]['evidence'], {'action': 'ftp_login', 'attempts': 5,
                                               'source_ip': '192.0.2.129', 'username': 'ftpuser'})
        self.assertEqual(self.collector.run_once(), [])

    def test_vsftpd_rejects_missing_source_and_does_not_store_password_text(self):
        self.assertIsNone(parse_linux_ftp_line('Mon Nov 9 [pid 1] [ftpuser] FAIL LOGIN: Client "-"', 'ssh-host'))
        event = parse_linux_ftp_line('Mon Nov 9 [pid 1] [ftpuser] FAIL LOGIN: Client "192.0.2.129", '
                                          'anon password "secret-value"', 'ssh-host')
        self.assertEqual(event.username, 'ftpuser')
        self.assertNotIn('secret-value', str(event.to_dict()))
        self.assertIsNone(parse_linux_ftp_line('Mon Nov 9 [pid 1] CONNECT: Client "192.0.2.129"', 'ssh-host'))

    def test_proftpd_login_outcomes(self):
        prefix = 'Nov 9 host proftpd[123]: host (client[::ffff:192.0.2.129]): '
        failure = parse_linux_ftp_line(prefix + 'USER alice (Login failed): Incorrect password', 'ssh-host')
        success = parse_linux_ftp_line(prefix + 'USER alice: Login successful', 'ssh-host')
        self.assertEqual((failure.outcome, failure.source_ip, failure.username),
                         ('failure', '192.0.2.129', 'alice'))
        self.assertEqual(success.outcome, 'success')
        mixed_case = parse_linux_ftp_line(prefix + 'USER alice (login FAILED): Incorrect password', 'ssh-host')
        self.assertEqual(mixed_case.outcome, 'failure')

    def test_iis_ftp_w3c_collector_counts_pass_530_once_and_handles_new_file(self):
        site = self.log.parent / 'FTPSVC1'
        site.mkdir()
        first = site / 'u_ex261109.log'
        fields = 'date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status'
        first.write_text('#Software: Microsoft Internet Information Services\n#Fields: ' + fields + '\n',
                         encoding='utf-8')
        config = HostConfig(host_id='ssh-host', database_path=self.config.database_path,
                            windows_ftp_log_paths=[self.log.parent], enabled_collectors=set())
        collector = WindowsFtpCollector('ssh-host', config, self.agent.database, self.agent.ingest_event)
        self.assertEqual(collector.run_once(), [])
        with first.open('a', encoding='utf-8') as stream:
            stream.write('2026-11-09 10:00:00 192.0.2.129 - 192.0.2.1 21 USER ftpuser 331\n')
            for index in range(5):
                stream.write(f'2026-11-09 10:00:0{index + 1} 192.0.2.129 ftpuser '
                             '192.0.2.1 21 PASS *** 530\n')
        self.assertEqual(len(collector.run_once()), 5)
        self.assertEqual(len(self.agent.database.list_alerts()), 1)
        self.assertEqual(len(self.agent.database.list_incidents()), 1)
        second = site / 'u_ex261110.log'
        second.write_text('#Fields: ' + fields + '\n'
                          '2026-11-10 10:00:00 192.0.2.129 ftpuser 192.0.2.1 21 PASS *** 230\n',
                          encoding='utf-8')
        self.assertEqual(collector.run_once()[0].outcome, 'success')
        self.assertEqual(collector.run_once(), [])
        self.assertNotIn('***', str(self.agent.database.list_alerts()))

    def test_iis_ftp_parser_ignores_other_commands_and_missing_sources(self):
        fields = 'date time c-ip cs-username cs-method sc-status'.split()
        for line in ('2026-11-09 10:00:00 192.0.2.129 alice USER 530',
                     '2026-11-09 10:00:00 192.0.2.129 alice PASS 331',
                     '2026-11-09 10:00:00 - alice PASS 530'):
            self.assertIsNone(parse_iis_ftp_line(line, fields, 'ssh-host'))
