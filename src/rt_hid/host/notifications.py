"""Best-effort desktop notifications from the running host monitor."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any


_RULE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_LINUX_ACTION_ID = re.compile(r"^\s*uint32 (\d+)\s*$")
_LINUX_ACTION_NAME = re.compile(r'^\s*string "(default|open)"\s*$')
_LINUX_NOTIFY_ID = re.compile(r"^\(uint32 (\d+),\)\s*$")
_LINUX_BROWSERS = (
    "x-www-browser", "firefox", "chromium", "chromium-browser",
    "google-chrome", "google-chrome-stable", "brave-browser",
    "microsoft-edge", "vivaldi", "epiphany", "falkon", "konqueror", "midori",
)
_WINDOWS_APP_ID = "RTHID.HostNotifications"
_WINDOWS_TOAST_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$message = [Console]::In.ReadToEnd() | ConvertFrom-Json
$title = [System.Security.SecurityElement]::Escape([string]$message.title)
$body = [System.Security.SecurityElement]::Escape([string]$message.body)
$url = [System.Security.SecurityElement]::Escape([string]$message.url)
$content = '<toast activationType="protocol" launch="' + $url + '"><visual><binding template="ToastGeneric"><text>' + $title + '</text><text>' + $body + '</text></binding></visual></toast>'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$xml = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]::new()
$xml.LoadXml($content)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('RTHID.HostNotifications').Show($toast)
"""


class DesktopNotifier:
    """Deliver non-sensitive alert summaries without blocking event ingestion."""

    def __init__(self, enabled: bool, logger: logging.Logger, dashboard_port: int) -> None:
        self.enabled = enabled
        self.logger = logger
        self.dashboard_url = f"http://127.0.0.1:{dashboard_port}/"
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=256)
        self._stop = threading.Event()
        self._start_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._linux_command: list[str] = []
        self._linux_dbus_command: list[str] = []
        self._linux_dbus_monitor_command: list[str] = []
        self._linux_open_commands: list[list[str]] = []
        self._linux_browser_processes: list[subprocess.Popen[str]] = []
        self._linux_env: dict[str, str] | None = None
        self.available, self.reason = self._availability()
        if enabled and not self.available:
            logger.warning("Desktop notifications unavailable: %s", self.reason)

    def _availability(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled in configuration"
        if sys.platform == "win32":
            try:
                import pythoncom  # noqa: F401
                from win32com.propsys import propsys  # noqa: F401
                from win32com.shell import shell  # noqa: F401
                session = ctypes.c_ulong()
                if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
                    return False, "desktop session unavailable"
                if session.value == 0:
                    return False, "monitor runs in a non-interactive Windows service session"
            except (ImportError, OSError, AttributeError):
                return False, "Windows notification support unavailable; install project dependencies"
            if not self._windows_powershell().is_file():
                return False, "Windows PowerShell is unavailable"
            return True, "interactive Windows desktop"
        if sys.platform.startswith("linux"):
            notify_send = shutil.which("notify-send")
            if not notify_send:
                return False, "notify-send is not installed"
            gdbus = shutil.which("gdbus")
            dbus_monitor = shutil.which("dbus-monitor")
            browser_path = os.pathsep.join((os.environ.get("PATH", ""), "/snap/bin"))
            browsers = [path for name in _LINUX_BROWSERS
                        if (path := shutil.which(name, path=browser_path))]
            if os.geteuid() == 0:
                import pwd

                try:
                    sudo_uid = int(os.environ["SUDO_UID"])
                    if sudo_uid <= 0:
                        raise ValueError
                    sudo_user = pwd.getpwuid(sudo_uid)
                except (KeyError, ValueError):
                    return False, "run from a signed-in desktop user with sudo"
                if os.environ.get("SUDO_USER") != sudo_user.pw_name:
                    return False, "sudo desktop user could not be verified"
                runuser = shutil.which("runuser")
                if not runuser:
                    return False, "runuser is not installed"
                env_command = shutil.which("env")
                if not env_command:
                    return False, "env is not installed"
                runtime_dir = Path(f"/run/user/{sudo_uid}")
                try:
                    directory = runtime_dir.stat()
                    bus = (runtime_dir / "bus").stat()
                except OSError:
                    return False, "signed-in user's notification session unavailable"
                if (directory.st_uid != sudo_uid or not stat.S_ISDIR(directory.st_mode)
                        or bus.st_uid != sudo_uid or not stat.S_ISSOCK(bus.st_mode)):
                    return False, "signed-in user's notification session unavailable"
                user_command = [
                    runuser, "-u", sudo_user.pw_name, "--", env_command,
                    f"XDG_RUNTIME_DIR={runtime_dir}",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus",
                ]
                desktop_keys = {"DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XAUTHORITY"}
                desktop_env: dict[str, str] = {}
                systemctl = shutil.which("systemctl")
                if systemctl:
                    try:
                        session = subprocess.run(
                            [*user_command, systemctl, "--user", "show-environment"],
                            env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True,
                            timeout=3, check=False,
                        )
                        if session.returncode == 0:
                            for line in session.stdout.splitlines():
                                key, separator, value = line.partition("=")
                                if separator and key in desktop_keys:
                                    desktop_env[key] = value
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                for key in desktop_keys:
                    if key not in desktop_env and key in os.environ:
                        desktop_env[key] = os.environ[key]
                user_command.extend(f"{key}={value}" for key, value in desktop_env.items())
                self._linux_command = [*user_command, notify_send]
                if gdbus:
                    self._linux_dbus_command = [*user_command, gdbus]
                if dbus_monitor:
                    self._linux_dbus_monitor_command = [*user_command, dbus_monitor]
                self._linux_open_commands = [[*user_command, browser] for browser in browsers]
                self._linux_env = {
                    "PATH": "/usr/bin:/bin:/snap/bin",
                    "HOME": sudo_user.pw_dir,
                    "USER": sudo_user.pw_name,
                    "LOGNAME": sudo_user.pw_name,
                    "XDG_RUNTIME_DIR": str(runtime_dir),
                    "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
                }
                for key in ("LANG", "LC_ALL"):
                    if key in os.environ:
                        self._linux_env[key] = os.environ[key]
                self._linux_env.update(desktop_env)
                if not self._linux_open_commands:
                    return True, "Linux notifications available; install a graphical web browser for clicks"
                if not self._linux_dbus_command or not self._linux_dbus_monitor_command:
                    return True, "Linux notifications available; install gdbus and dbus-monitor for clicks"
                return True, "signed-in sudo user's Linux desktop session"
            if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
                runtime_dir = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
                try:
                    bus = (runtime_dir / "bus").stat()
                except OSError:
                    return False, "desktop notification session unavailable"
                if bus.st_uid != os.getuid() or not stat.S_ISSOCK(bus.st_mode):
                    return False, "desktop notification session unavailable"
                self._linux_env = dict(os.environ)
                self._linux_env["XDG_RUNTIME_DIR"] = str(runtime_dir)
                self._linux_env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime_dir}/bus"
            self._linux_command = [notify_send]
            if gdbus:
                self._linux_dbus_command = [gdbus]
            if dbus_monitor:
                self._linux_dbus_monitor_command = [dbus_monitor]
            self._linux_open_commands = [[browser] for browser in browsers]
            if not self._linux_open_commands:
                return True, "Linux notifications available; install a graphical web browser for clicks"
            if not self._linux_dbus_command or not self._linux_dbus_monitor_command:
                return True, "Linux notifications available; install gdbus and dbus-monitor for clicks"
            return True, "Linux desktop session"
        return False, "unsupported platform"

    def status(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "available": self.available, "detail": self.reason}

    def set_dashboard_address(self, host: str, port: int) -> None:
        local_host = "[::1]" if host == "::1" else host
        self.dashboard_url = f"http://{local_host}:{port}/"

    def publish(self, alert: dict[str, Any], *, new_incident: bool) -> None:
        if not self.available or self._stop.is_set():
            return
        severity = str(alert.get("severity", "informational")).lower()
        if severity not in _SEVERITIES:
            severity = "informational"
        rule = str(alert.get("rule_id", ""))
        rule = rule if _RULE_ID.fullmatch(rule) else "Security detection"
        kind = "New incident" if new_incident else "New alert"
        title = f"RT-HID: {kind}"
        body = f"{severity.capitalize()} · {rule} · Open RT-HID to investigate"
        try:
            self._queue.put_nowait((title, body, severity))
        except queue.Full:
            self.logger.warning("Desktop notification queue full; a notification was dropped")
            return
        with self._start_lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="rt-hid-notifications", daemon=True)
                try:
                    self._thread.start()
                except RuntimeError:
                    self.available = False
                    self.reason = "desktop notification worker unavailable"
                    self.logger.warning("Desktop notification worker could not start")

    def _run(self) -> None:
        try:
            if sys.platform == "win32":
                self._run_windows()
            else:
                self._run_linux()
        except Exception as error:
            self.available = False
            self.reason = "desktop notification delivery failed"
            self.logger.warning("Desktop notification delivery failed: %s", type(error).__name__)

    def _next(self) -> tuple[str, str, str] | None:
        try:
            return self._queue.get(timeout=0.25)
        except queue.Empty:
            return None

    def _run_linux(self) -> None:
        if (self._linux_dbus_command and self._linux_dbus_monitor_command
                and self._linux_open_commands and self._run_linux_dbus()):
            return
        self._run_linux_notify_send()

    def _run_linux_dbus(self) -> bool:
        try:
            monitor = subprocess.Popen(
                [*self._linux_dbus_monitor_command, "--session", "--monitor",
                 "type='signal',interface='org.freedesktop.Notifications',member='ActionInvoked'"],
                env=self._linux_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1, start_new_session=True,
            )
        except OSError as error:
            self.logger.warning("Desktop notification click listener failed to start: %s", type(error).__name__)
            self.reason = "Linux notification click listener unavailable"
            return False

        actions: queue.Queue[int] = queue.Queue(maxsize=256)
        ready = threading.Event()
        assert monitor.stdout is not None
        listener = threading.Thread(
            target=self._linux_read_dbus_actions, args=(monitor.stdout, actions, ready),
            name="rt-hid-notification-actions", daemon=True,
        )
        listener.start()
        try:
            ready.wait(timeout=1)
            self._stop.wait(0.1)
            if monitor.poll() is not None:
                self.logger.warning("Desktop notification click listener unavailable")
                self.reason = "Linux notification click listener unavailable"
                return False
            self.reason = "Linux D-Bus click listener ready"
            notification_ids: dict[int, None] = {}
            while not self._stop.is_set():
                if monitor.poll() is not None:
                    self.logger.warning("Desktop notification click listener stopped")
                    self.reason = "Linux notification click listener stopped"
                    return False
                self._linux_reap_browsers()
                while True:
                    try:
                        notification_id = actions.get_nowait()
                    except queue.Empty:
                        break
                    if notification_id in notification_ids:
                        del notification_ids[notification_id]
                        self.logger.info("Desktop notification action received")
                        self._linux_open_dashboard()
                item = self._next()
                if item is None:
                    continue
                notification_id = self._linux_dbus_send(item)
                if notification_id is None:
                    if not self._linux_send_plain(item):
                        return True
                    continue
                notification_ids[notification_id] = None
                self.reason = "Linux D-Bus notification ready; waiting for click"
                if len(notification_ids) > 128:
                    del notification_ids[next(iter(notification_ids))]
            return True
        finally:
            if monitor.poll() is None:
                try:
                    os.killpg(monitor.pid, signal.SIGTERM)
                except OSError:
                    pass
            try:
                monitor.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(monitor.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    monitor.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    self.logger.warning("Desktop notification click listener did not stop promptly")
            listener.join(timeout=1)
            if monitor.stdout:
                monitor.stdout.close()

    @staticmethod
    def _linux_read_dbus_actions(stream: Any, actions: queue.Queue[int], ready: threading.Event) -> None:
        action_id: int | None = None
        awaiting_action = False
        try:
            for line in stream:
                if "member=NameAcquired" in line:
                    ready.set()
                if line.startswith("signal "):
                    action_id = None
                    awaiting_action = "interface=org.freedesktop.Notifications; member=ActionInvoked" in line
                    continue
                if not awaiting_action:
                    continue
                if action_id is None:
                    match = _LINUX_ACTION_ID.fullmatch(line.strip())
                    if match:
                        action_id = int(match.group(1))
                    continue
                match = _LINUX_ACTION_NAME.fullmatch(line.strip())
                if match:
                    try:
                        actions.put_nowait(action_id)
                    except queue.Full:
                        pass
                awaiting_action = False
        except (OSError, ValueError):
            pass

    def _linux_dbus_send(self, item: tuple[str, str, str]) -> int | None:
        title, body, severity = item
        urgency = 2 if severity == "critical" else 1
        try:
            result = subprocess.run(
                [*self._linux_dbus_command, "call", "--session", "--dest", "org.freedesktop.Notifications",
                 "--object-path", "/org/freedesktop/Notifications", "--method",
                 "org.freedesktop.Notifications.Notify", "--timeout", "3",
                 "--",
                 "RT-HID", "0", "", title, body,
                 "['default', 'Open RT-HID', 'open', 'Open RT-HID']",
                 "{'urgency': <byte " + str(urgency) + ">}", "-1"],
                env=self._linux_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=4, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            self.logger.warning("Desktop notification D-Bus delivery failed: %s", type(error).__name__)
            self.reason = "Linux D-Bus notification delivery failed"
            return None
        match = _LINUX_NOTIFY_ID.fullmatch(result.stdout.strip()) if result.returncode == 0 else None
        if match is None:
            if result.returncode:
                if "Unknown option" in result.stderr:
                    stage = "option parsing"
                elif "Error parsing parameter" in result.stderr or "Could not parse" in result.stderr:
                    stage = "argument parsing"
                else:
                    stage = "service call"
            else:
                stage = "response parsing"
            self.logger.warning("Desktop notification D-Bus delivery failed at %s: gdbus exit %d", stage, result.returncode)
            self.reason = f"Linux D-Bus notification {stage} failed"
            return None
        return int(match.group(1))

    def _run_linux_notify_send(self) -> None:
        pending: dict[subprocess.Popen[str], tuple[str, str, str]] = {}
        clickable = bool(self._linux_open_commands)
        try:
            while not self._stop.is_set():
                self._linux_reap_browsers()
                for process, item in list(pending.items()):
                    if process.poll() is None:
                        continue
                    output, error_output = process.communicate()
                    del pending[process]
                    if process.returncode:
                        clickable = False
                        if "Actions are not supported by this notifications server" in error_output:
                            self.reason = "Linux notification server does not support click actions"
                            self.logger.warning("Desktop notification server does not support click actions")
                        else:
                            self.reason = "Linux notifications available; notify-send click action failed"
                            self.logger.warning("Desktop notification action failed: notify-send exit %d", process.returncode)
                            if not self._linux_send_plain(item):
                                return
                    elif output.strip() in {"default", "open"} and not self._stop.is_set():
                        self.logger.info("Desktop notification action received")
                        self._linux_open_dashboard()

                item = self._next()
                if item is None:
                    continue
                if clickable:
                    # Retire the oldest listener so each new notification retains a click action.
                    if len(pending) >= 32:
                        oldest = next(iter(pending))
                        del pending[oldest]
                        self._linux_stop_action(oldest)
                    process = subprocess.Popen(
                        self._linux_notify_args(item, clickable=True),
                        env=self._linux_env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, start_new_session=True,
                    )
                    pending[process] = item
                elif not self._linux_send_plain(item):
                    return
        finally:
            for process in pending:
                self._linux_stop_action(process)
            self._linux_reap_browsers()

    @staticmethod
    def _linux_stop_action(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
        try:
            process.communicate(timeout=0.1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                if process.stdout:
                    process.stdout.close()

    def _linux_reap_browsers(self) -> None:
        for process in list(self._linux_browser_processes):
            if process.poll() is None:
                continue
            self._linux_browser_processes.remove(process)
            if process.returncode:
                self.reason = "Linux notifications available; browser opener failed"
                self.logger.warning("Desktop notification browser opener exited %d", process.returncode)

    def _linux_notify_args(self, item: tuple[str, str, str], *, clickable: bool) -> list[str]:
        title, body, severity = item
        command = [*self._linux_command, "--app-name=RT-HID",
                   "--urgency=" + ("critical" if severity == "critical" else "normal")]
        if clickable:
            command.append("--action=default=Open RT-HID")
            command.append("--action=open=Open RT-HID")
        return [*command, title, body]

    def _linux_send_plain(self, item: tuple[str, str, str]) -> bool:
        result = subprocess.run(
            self._linux_notify_args(item, clickable=False),
            env=self._linux_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
        if result.returncode:
            self.available = False
            self.reason = "desktop notification service unavailable"
            self.logger.warning("Desktop notification delivery failed: notify-send exit %d", result.returncode)
            return False
        return True

    def _linux_open_dashboard(self) -> None:
        # Launch a browser directly: generic URI openers can hand HTML to a text editor.
        # /login also remains reachable when the browser has no active login session.
        browser_url = self.dashboard_url.rstrip("/") + "/login"
        for command in self._linux_open_commands:
            try:
                process = subprocess.Popen(
                    [*command, browser_url], env=self._linux_env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                )
                try:
                    exit_code = process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    self._linux_browser_processes.append(process)
                    self.reason = "Linux notification clicked; browser launch requested"
                    self.logger.info("Desktop notification browser launch requested")
                    return
                if exit_code == 0:
                    self.reason = "Linux notification clicked; browser launch requested"
                    self.logger.info("Desktop notification browser launch requested")
                    return
                self.logger.warning("Desktop notification browser opener exited %d", exit_code)
            except OSError as error:
                self.logger.warning("Desktop notification browser launch failed: %s", type(error).__name__)
        self.reason = "Linux notifications available; browser opener failed"

    def _run_windows(self) -> None:
        self._register_windows_shortcut()

        while not self._stop.is_set():
            item = self._next()
            if item is None:
                continue
            title, body, _severity = item
            result = subprocess.run(
                [str(self._windows_powershell()), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                 "-Command", _WINDOWS_TOAST_SCRIPT],
                input=json.dumps({"title": title, "body": body, "url": self.dashboard_url}, ensure_ascii=True),
                text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW, check=False,
            )
            if result.returncode:
                self.available = False
                self.reason = "Windows toast delivery failed"
                self.logger.warning("Desktop notification delivery failed: PowerShell exit %d", result.returncode)
                return

    @staticmethod
    def _windows_powershell() -> Path:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"

    def _register_windows_shortcut(self) -> None:
        import pythoncom
        from win32com.propsys import propsys, pscon
        from win32com.shell import shell, shellcon

        pythoncom.CoInitialize()
        try:
            programs = Path(shell.SHGetSpecialFolderPath(0, shellcon.CSIDL_PROGRAMS, True))
            shortcut = programs / "RT-HID Host Notifications.lnk"
            if shortcut.exists() or shortcut.is_symlink():
                if shortcut.is_symlink():
                    raise RuntimeError("notification shortcut is a symbolic link")
                store = propsys.SHGetPropertyStoreFromParsingName(str(shortcut))
                if store.GetValue(pscon.PKEY_AppUserModel_ID).GetValue() != _WINDOWS_APP_ID:
                    raise RuntimeError("notification shortcut conflicts with an existing shortcut")
                return

            link = pythoncom.CoCreateInstance(shell.CLSID_ShellLink, None, pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IShellLink)
            link.SetPath(str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe"))
            link.SetArguments(self.dashboard_url)
            link.SetDescription("Open the RT-HID host security dashboard")
            properties = link.QueryInterface(propsys.IID_IPropertyStore)
            properties.SetValue(pscon.PKEY_AppUserModel_ID, propsys.PROPVARIANTType(_WINDOWS_APP_ID, pythoncom.VT_LPWSTR))
            properties.Commit()
            link.QueryInterface(pythoncom.IID_IPersistFile).Save(str(shortcut), 0)
        finally:
            pythoncom.CoUninitialize()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=4)
