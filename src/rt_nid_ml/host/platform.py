from __future__ import annotations

import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformCapabilities:
    system: str
    release: str
    machine: str
    collectors: tuple[str, ...]


def detect_capabilities() -> PlatformCapabilities:
    system = platform.system().lower()
    if system == "linux":
        collectors = ("linux_auth", "linux_process", "linux_network", "linux_file_integrity", "linux_system")
    elif system == "windows":
        collectors = ("windows_event_log", "windows_system")
    else:
        collectors = ()
    return PlatformCapabilities(system, platform.release(), platform.machine(), collectors)
