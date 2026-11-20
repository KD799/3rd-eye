"""Reads REAL telemetry from the machine the collector runs on (read-only)."""
import socket, time
import psutil
from .base import Adapter, Record, utc_iso


class PsutilAdapter(Adapter):
    name = "psutil_local"

    def __init__(self, source_id=None, tz="Asia/Kolkata", disk_path="/"):
        self.source_id = source_id or socket.gethostname()
        self.tz, self.disk_path = tz, disk_path
        psutil.cpu_percent(interval=None)      # prime the counter

    def read(self):
        ts = utc_iso(time.time())
        vals = {
            "cpu": psutil.cpu_percent(interval=None),
            "mem": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(self.disk_path).percent,
        }
        return [Record(self.source_id, m, float(v), ts, self.tz) for m, v in vals.items()]
