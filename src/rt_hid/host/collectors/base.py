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
                                  last_error=None, detail="collecting", collection_errors=0, inaccessible_processes=0)
            events = self.collect_once()
            for event in events:
                self.sink(event)
            self.status = replace(self.status, available=self.status.available if self.status.last_error else True,
                                  state="running" if self.status.available or not self.status.last_error else "degraded",
                                  last_success=(self.status.last_success if self.status.last_error and not self.status.available
                                                else utc_now()),
                                  last_duration_seconds=monotonic() - started,
                                  events_generated=len(events),
                                  detail=self.status.detail if self.status.last_error else f"{len(events)} event(s)")
            return events
        except Exception as error:  # collector isolation is intentional
            summary = 'collection: ' + type(error).__name__
            self.status = replace(self.status, available=False, state="degraded",
                                  last_error=summary, detail="degraded",
                                  collection_errors=max(1,self.status.collection_errors),
                                  last_duration_seconds=monotonic() - started)
            return []
