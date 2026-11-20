"""Append-only, hash-chained record of payloads approved to leave."""
import hashlib
import json
import os
import time


class EgressLog:
    def __init__(self, path="egress_log.jsonl"):
        self.path = path
        self.prev = "0" * 64
        if os.path.exists(path):
            with open(path, encoding="utf-8") as file:
                for line in file:
                    if line.strip():
                        self.prev = json.loads(line)["hash"]

    def write(self, kind, payload_id, payload=None, extra=None):
        entry = {
            "ts": time.time(),
            "kind": kind,
            "payload_id": payload_id,
            "payload": payload,
            "extra": extra or {},
            "prev": self.prev,
        }
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        with open(self.path, "a", encoding="utf-8") as file:
            file.write(json.dumps(entry) + "\n")
        self.prev = entry["hash"]

    @staticmethod
    def verify(path="egress_log.jsonl"):
        prev = "0" * 64
        with open(path, encoding="utf-8") as file:
            for index, line in enumerate(file, 1):
                if not line.strip():
                    continue
                entry = json.loads(line)
                hash_value = entry.pop("hash")
                if entry["prev"] != prev:
                    return False, index
                expected = hashlib.sha256(
                    json.dumps(entry, sort_keys=True).encode()
                ).hexdigest()
                if expected != hash_value:
                    return False, index
                prev = hash_value
        return True, None
