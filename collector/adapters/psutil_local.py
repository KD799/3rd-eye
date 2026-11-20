"""Reads real telemetry from the machine the collector runs on."""
import socket
import time

import psutil

from .base import Adapter, Record, utc_iso


class PsutilAdapter(Adapter):
    name = "psutil_local"

    def __init__(self, source_id=None, tz="Asia/Kolkata", disk_path="/"):
        self.source_id = source_id or socket.gethostname()
        self.tz = tz
        self.disk_path = disk_path
        psutil.cpu_percent(interval=None)

    def read(self):
        ts = utc_iso(time.time())
        values = {
            "cpu": psutil.cpu_percent(interval=None),
            "mem": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(self.disk_path).percent,
        }
        return [
            Record(self.source_id, metric, float(value), ts, self.tz)
            for metric, value in values.items()
        ]
