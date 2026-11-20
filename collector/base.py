"""Adapter contract. Every data source implements read() and returns Records.
RULE: adapters are READ-ONLY. They never write to, restart, or run commands on
the monitored system. Raw values stay on the collector; later stages redact them."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class Record:
    source_id: str      # raw id (hostname/device). Pseudonymized later, before egress
    metric: str         # cpu | mem | disk | latency | packet_loss | auth_failures ...
    value: float
    ts_utc: str         # ISO-8601 UTC, e.g. 2026-11-20T10:15:00Z
    source_tz: str      # timezone of the source, e.g. Asia/Kolkata

    def to_dict(self):
        return asdict(self)


def utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Adapter(ABC):
    name = "base"

    @abstractmethod
    def read(self) -> list[Record]:
        """One polling pass. Return a list of Records. Must not modify the source."""
