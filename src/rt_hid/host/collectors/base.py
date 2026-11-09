from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import replace
from time import monotonic
from typing import Callable

from ..models import CollectorStatus, HostEvent, utc_now

EventSink = Callable[[HostEvent], None]


class Collector(ABC):
    collector_id: str

    def __init__(self, host_id: str, sink: EventSink) -> None:
        self.host_id = host_id
        self.sink = sink
        self.status = CollectorStatus(self.collector_id, "unknown", False, True, detail="not started")

    @abstractmethod
    def collect_once(self) -> list[HostEvent]:
        """Collect a bounded batch; failures should update status, not crash the agent."""

    def run_once(self) -> list[HostEvent]:
        started = monotonic()
        try:
            self.status = replace(self.status, available=False, state="collecting",
                                  last_error=None, detail="collecting")
            events = self.collect_once()
            for event in events:
                self.sink(event)
            self.status = replace(self.status, available=self.status.available if self.status.last_error else True,
                                  state="running" if self.status.available or not self.status.last_error else "degraded",
                                  last_success=utc_now(), last_duration_seconds=monotonic() - started,
                                  events_generated=len(events),
                                  detail=self.status.detail if self.status.last_error else f"{len(events)} event(s)")
            return events
        except Exception as error:  # collector isolation is intentional
            summary = type(error).__name__ if self.collector_id.endswith("_process") else str(error)
            self.status = replace(self.status, available=False, state="degraded",
                                  last_error=summary, detail="degraded",
                                  last_duration_seconds=monotonic() - started)
            return []
