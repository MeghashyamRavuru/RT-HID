from __future__ import annotations

from abc import ABC, abstractmethod
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
        try:
            self.status = CollectorStatus(self.collector_id, self.status.platform, False, True,
                                          last_success=self.status.last_success, detail="collecting")
            events = self.collect_once()
            for event in events:
                self.sink(event)
            if not self.status.last_error:
                self.status = CollectorStatus(self.collector_id, self.status.platform, True, True,
                                              last_success=utc_now(), detail=f"{len(events)} event(s)")
            return events
        except Exception as error:  # collector isolation is intentional
            self.status = CollectorStatus(self.collector_id, self.status.platform, False, True, last_error=str(error), detail="degraded")
            return []
