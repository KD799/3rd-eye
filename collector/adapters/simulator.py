"""Simulated telemetry with a daily pattern, noise, and faults injected at known times."""
import math
import random

from .base import Adapter, Record, utc_iso


PROFILES = {
    "cpu": (35.0, 3.0, 10.0),
    "mem": (50.0, 2.0, 4.0),
    "disk": (60.0, 0.1, 0.0),
    "latency": (20.0, 2.0, 5.0),
    "packet_loss": (0.2, 0.08, 0.0),
}
DEFAULT_SOURCES = {
    "switch-a": ["latency", "packet_loss"],
    "app-x": ["cpu", "mem"],
    "db-1": ["mem", "disk"],
}


class SimulatorAdapter(Adapter):
    name = "simulator"

    def __init__(self, sources=None, faults=None, start_epoch=1_700_000_000,
                 tick_s=5, seed=42, tz="Asia/Kolkata"):
        self.sources = sources or DEFAULT_SOURCES
        self.faults = faults or []
        self.t0 = start_epoch
        self.tick_s = tick_s
        self.tz = tz
        self.tick = 0
        self.rng = random.Random(seed)

    def _daily(self, epoch, swing):
        hour = (epoch % 86400) / 3600
        return swing * math.sin((hour - 6) / 24 * 2 * math.pi)

    def read(self):
        epoch = self.t0 + self.tick * self.tick_s
        ts = utc_iso(epoch)
        output = []
        for source, metrics in self.sources.items():
            for metric in metrics:
                base, noise, swing = PROFILES[metric]
                value = base + self._daily(epoch, swing) + self.rng.gauss(0, noise)
                for fault in self.faults:
                    if (
                        fault["source"] == source
                        and fault["metric"] == metric
                        and fault["at_tick"] <= self.tick < fault["at_tick"] + fault["duration"]
                    ):
                        value += fault["delta"]
                output.append(
                    Record(source, metric, round(max(value, 0.0), 3), ts, self.tz)
                )
        self.tick += 1
        return output
