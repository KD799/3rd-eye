"""Simulated telemetry with a daily pattern, noise, and faults injected at KNOWN times.
Uses a virtual clock so you can generate hours of data in seconds.
Faults are plain dicts, so they can later be loaded from faults.json."""
import json, math, random
from .base import Adapter, Record, utc_iso

# metric: (baseline, noise, daily_swing)
PROFILES = {
    "cpu":         (35.0, 3.0, 10.0),
    "mem":         (50.0, 2.0, 4.0),
    "disk":        (60.0, 0.1, 0.0),
    "latency":     (20.0, 2.0, 5.0),
    "packet_loss": (0.2, 0.08, 0.0),
}
DEFAULT_SOURCES = {"switch-a": ["latency", "packet_loss"], "app-x": ["cpu", "mem"], "db-1": ["mem", "disk"]}


def load_faults(path):
    with open(path) as f:
        return json.load(f)


class SimulatorAdapter(Adapter):
    name = "simulator"

    def __init__(self, sources=None, faults=None, start_epoch=1_700_000_000,
                 tick_s=5, seed=42, tz="Asia/Kolkata"):
        self.sources = sources or DEFAULT_SOURCES
        # fault = {"at_tick":80,"duration":40,"source":"switch-a","metric":"packet_loss","delta":6}
        self.faults = faults or []
        self.t0, self.tick_s, self.tz = start_epoch, tick_s, tz
        self.tick = 0
        self.rng = random.Random(seed)

    def _daily(self, epoch, swing):
        hour = (epoch % 86400) / 3600
        return swing * math.sin((hour - 6) / 24 * 2 * math.pi)   # busier in the day

    def read(self):
        epoch = self.t0 + self.tick * self.tick_s
        ts, out = utc_iso(epoch), []
        for src, metrics in self.sources.items():
            for m in metrics:
                base, noise, swing = PROFILES[m]
                v = base + self._daily(epoch, swing) + self.rng.gauss(0, noise)
                for f in self.faults:
                    if (f["source"] == src and f["metric"] == m
                            and f["at_tick"] <= self.tick < f["at_tick"] + f["duration"]):
                        v += f["delta"]
                out.append(Record(src, m, round(max(v, 0.0), 3), ts, self.tz))
        self.tick += 1
        return out
