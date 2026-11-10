"""Best-effort desktop notifications from the running host monitor."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any


_RULE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
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
            if not shutil.which("notify-send"):
                return False, "notify-send is not installed"
            if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
                return False, "desktop notification session unavailable"
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
        while not self._stop.is_set():
            item = self._next()
            if item is None:
                continue
            title, body, severity = item
            result = subprocess.run(
                ["notify-send", "--app-name=RT-HID", "--urgency=" + ("critical" if severity == "critical" else "normal"), title, body],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False,
            )
            if result.returncode:
                self.available = False
                self.reason = "desktop notification service unavailable"
                self.logger.warning("Desktop notification delivery failed: notify-send exit %d", result.returncode)
                return

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
