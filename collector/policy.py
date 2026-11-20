"""DATA POLICY: default-deny allow-list, redaction, pseudonymization, final leak guard.
Nothing leaves the collector unless it passes through build_payload()."""
import hashlib
import hmac
import json
import os
import re
import time
import uuid

TENANT_KEY = os.environ.get("TENANT_KEY", "change-me-per-tenant-secret").encode()

ALLOWED_TOP = {
    "payload_id", "tenant_id", "collector_id", "collector_version",
    "sent_at_utc", "records", "events", "collector_health",
}
ALLOWED_RECORD = {"source_id", "metric", "value", "ts_utc", "source_tz"}
ALLOWED_EVENT = {"event_category", "severity", "count", "risk", "source_id", "ts_utc"}
ALLOWED_HEALTH = {"cpu_pct", "mem_pct", "uptime_s", "config_status"}
ALLOWED_METRICS = {"cpu", "mem", "disk", "latency", "packet_loss", "auth_failures", "iface_errors"}
ALLOWED_CATEGORIES = {"auth_failure_burst", "service_error", "config_change"}
ALLOWED_SEVERITY = {"low", "medium", "high"}

SECRET_PATTERNS = [
    ("password", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+")),
    ("api_key", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*\S+")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("sk_key", re.compile(r"sk_(live|test)_[A-Za-z0-9]{8,}")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("ipv4", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
]
CANARIES = ["CANARY-SECRET-7f3a9"]


class PolicyViolation(Exception):
    pass


def pseudonymize(raw_id: str) -> str:
    return hmac.new(TENANT_KEY, raw_id.encode(), hashlib.sha256).hexdigest()[:16]


def redact(text: str):
    actions = []
    for name, pattern in SECRET_PATTERNS:
        text, count = pattern.subn(f"[REDACTED:{name}]", text)
        if count:
            actions.append(f"{name} x{count}")
    return text, actions


def _filter(data: dict, allowed: set, dropped: list, where: str):
    output = {}
    for key, value in data.items():
        if key in allowed:
            output[key] = value
        else:
            dropped.append(f"{where}.{key}")
    return output


def new_payload_id():
    return f"{int(time.time() * 1000):013x}-{uuid.uuid4().hex[:12]}"


def build_payload(tenant_id, collector_id, version, sent_at, records, events, health):
    dropped = []
    filtered_records = []
    for record in records:
        record = dict(record)
        record["source_id"] = pseudonymize(record["source_id"])
        record = _filter(record, ALLOWED_RECORD, dropped, "record")
        if record.get("metric") not in ALLOWED_METRICS:
            dropped.append(f"record.metric={record.get('metric')}")
            continue
        record["value"] = float(record["value"])
        filtered_records.append(record)

    filtered_events = []
    for event in events:
        event = dict(event)
        event["source_id"] = pseudonymize(event["source_id"])
        event = _filter(event, ALLOWED_EVENT, dropped, "event")
        if event.get("event_category") not in ALLOWED_CATEGORIES or event.get("severity", "low") not in ALLOWED_SEVERITY:
            dropped.append("event.invalid_enum")
            continue
        filtered_events.append(event)

    payload = {
        "payload_id": new_payload_id(),
        "tenant_id": tenant_id,
        "collector_id": collector_id,
        "collector_version": version,
        "sent_at_utc": sent_at,
        "records": filtered_records,
        "events": filtered_events,
        "collector_health": _filter(health, ALLOWED_HEALTH, dropped, "health"),
    }
    payload = _filter(payload, ALLOWED_TOP, dropped, "payload")

    body = json.dumps(payload, sort_keys=True)
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(body):
            raise PolicyViolation(f"leak guard: {name} pattern found in outgoing payload")
    for canary in CANARIES:
        if canary in body:
            raise PolicyViolation("leak guard: canary secret found in outgoing payload")
    return payload, {"dropped_fields": dropped, "bytes": len(body.encode())}
