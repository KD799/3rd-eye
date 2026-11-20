"""3rd Eye SaaS API (metadata only). Run: uvicorn api:app --port 8000
Tenant comes from the API KEY, never from the request body, so one tenant cannot read another's data."""
import os, threading, time
from typing import Literal, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

import chat, remediation, scoring
import config as C
from engine import TenantEngine, iso, parse_ts
from store import Store, pct

clock = time.time                       # injectable for tests
LOCK = threading.RLock()
store = Store(os.getenv("THIRDEYE_DB", "thirdeye.db"))
ENGINES: dict = {}


def init(db_path):                      # used by tests
    global store, ENGINES
    store, ENGINES = Store(db_path), {}


def engine_for(tenant):
    if tenant not in ENGINES:
        cfg = store.get_config(tenant)
        ENGINES[tenant] = TenantEngine(tenant, cfg.get("topology", {}), cfg.get("aliases", {}))
    return ENGINES[tenant]


# ---------- strict schema: the SaaS re-validates what the collector already filtered (defense in depth) ----------
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class RecordIn(Strict):
    source_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    metric: str
    value: float
    ts_utc: str = Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    source_tz: str = Field(max_length=40)
    @field_validator("metric")
    @classmethod
    def known(cls, v):
        if v not in C.METRICS: raise ValueError("metric not allowed")
        return v

class EventIn(Strict):
    event_category: Literal["auth_failure_burst", "service_error", "config_change"]
    severity: Literal["low", "medium", "high"]
    count: int = 0
    risk: Optional[str] = None
    source_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    ts_utc: str = Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

class HealthIn(Strict):
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    uptime_s: Optional[float] = None
    config_status: str = "ok"

class PayloadIn(Strict):
    payload_id: str = Field(min_length=8, max_length=64)
    tenant_id: str
    collector_id: str
    collector_version: str
    sent_at_utc: str = Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    records: list[RecordIn] = Field(max_length=2000)
    events: list[EventIn] = []
    collector_health: Optional[HealthIn] = None


def principal(role):
    def dep(x_api_key: str = Header(None)):
        info = C.API_KEYS.get(x_api_key)
        if not info or info[1] != role: raise HTTPException(401, "invalid API key")
        return info[0]
    return dep


app = FastAPI(title="3rd Eye SaaS")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def refresh_states(tenant, now):
    """Compute Excellent/Good/Fair/Poor per source + collector; log every transition (UTC) with its reason."""
    eng, out = engine_for(tenant), {"sources": {}, "collectors": {}}
    for c in store.collectors(tenant):
        out["collectors"][c["collector_id"]] = dict(zip(("state", "reason"), scoring.collector_state(c, now)), **c)
    for src in eng.seen:
        out["sources"][src] = dict(zip(("state", "reason"), scoring.source_state(eng, src, now)), name=eng.name(src))
    for kind, d in out.items():
        for ent, v in d.items():
            key = f"{kind[:-1]}:{ent}"
            old = store.last_state(tenant, key)
            if old != v["state"]:
                store.add_transition(tenant, now, key, old, v["state"], v["reason"])
    return out


def forecast_all(tenant):
    eng, risks = engine_for(tenant), []
    for src, m in store.pairs(tenant, eng.clock - 900):
        f = scoring.forecast(store.series(tenant, src, m, eng.clock - 900), m, eng.clock)
        if f: risks.append(dict(f, component=eng.name(src)))
    return risks


# ============================ collector -> SaaS ============================
@app.post("/v1/ingest")
def ingest(p: PayloadIn, tenant: str = Depends(principal("collector"))):
    if p.tenant_id != tenant: raise HTTPException(403, "tenant mismatch for this collector key")
    if C.THIS_REGION and C.TENANT_REGION.get(tenant) != C.THIS_REGION:
        raise HTTPException(421, "wrong region for this tenant's data residency")
    now = clock()
    with LOCK:
        recs = sorted(p.records, key=lambda r: parse_ts(r.ts_utc))          # order by EVENT time
        rows = [(tenant, r.source_id, r.metric, parse_ts(r.ts_utc), r.ts_utc, r.source_tz, r.value, p.payload_id) for r in recs]
        newest = max((r[3] for r in rows), default=parse_ts(p.sent_at_utc))
        if not store.add_payload(tenant, p.model_dump(), parse_ts(p.sent_at_utc), now, now - newest, rows):
            store.bump(tenant, "duplicates_rejected")                       # idempotent: retries never double count
            return {"status": "duplicate", "payload_id": p.payload_id}
        eng = engine_for(tenant)
        late0 = eng.late
        for r in recs: eng.ingest(r.source_id, r.metric, r.value, parse_ts(r.ts_utc), now)
        for e in p.events: eng.add_event(e.source_id, parse_ts(e.ts_utc), e.event_category, e.severity, e.count)
        store.save_incidents(tenant, eng.flush())
        if eng.late > late0: store.bump(tenant, "late_events", eng.late - late0)
        refresh_states(tenant, now)
    return {"status": "accepted", "payload_id": p.payload_id, "records": len(recs)}


# ============================ dashboard reads ============================
@app.get("/v1/overview")
def overview(tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        eng, now = engine_for(tenant), clock()
        states = refresh_states(tenant, now)
        open_incs = [i for i in eng.incidents.values() if i["status"] == "open"]
        risks = forecast_all(tenant)
        return {"health": scoring.health_score(eng, now), "security": scoring.security_score(eng),
                "open_incidents": len(open_incs), "predicted_risks": risks,
                "noise_reduction": {"raw_alerts": eng.raw_alerts, "incidents": len(eng.incidents)},
                "collectors": states["collectors"], "sources": states["sources"]}

@app.get("/v1/health")
def health(tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        states = refresh_states(tenant, clock())
        return {**states, "history": store.history(tenant)}

@app.get("/v1/incidents")
def incidents(tenant: str = Depends(principal("dashboard"))):
    with LOCK: return store.incidents(tenant)

@app.get("/v1/incidents/{iid}")
def incident(iid: str, tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        i = next((x for x in store.incidents(tenant) if x["id"] == iid), None)
        if not i: raise HTTPException(404, "not found")
        return i

@app.get("/v1/series")
def series(source: str, metric: str, minutes: int = Query(15, le=1440), tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        eng = engine_for(tenant)
        return {"source": source, "metric": metric, "points": [{"ts_utc": iso(t), "value": v} for t, v in
                store.series(tenant, source, metric, eng.clock - minutes * 60)]}

@app.get("/v1/forecast")
def forecast(tenant: str = Depends(principal("dashboard"))):
    with LOCK: return forecast_all(tenant)

@app.get("/v1/received")
def received(limit: int = Query(20, le=200), tenant: str = Depends(principal("dashboard"))):
    """What the SaaS actually received (compare with the collector's egress log by payload_id)."""
    with LOCK: return store.received(tenant, limit)

@app.get("/v1/reliability")
def reliability(tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        l = store.latencies(tenant)
        return {"payloads": store.payload_count(tenant), "duplicates_rejected": store.counter(tenant, "duplicates_rejected"),
                "late_events": store.counter(tenant, "late_events"),
                "collection_to_saas_latency_s": {"p50": pct(l, .5), "p95": pct(l, .95), "target_p95": 10}}


# ============================ chat, remediation, config ============================
class ChatIn(BaseModel):
    question: str = Field(max_length=500)
    incident_id: Optional[str] = None

@app.post("/v1/chat")
def chat_ep(b: ChatIn, tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        ov = overview(tenant)
        incs = store.incidents(tenant)
        inc = next((i for i in incs if i["id"] == b.incident_id), None) if b.incident_id else \
              next((i for i in incs if i["status"] == "open"), None)
        return chat.answer(b.question, chat.build_facts(ov, inc))

class ProposeIn(BaseModel):
    incident_id: str
    action_id: str

def _rem(fn, *a):
    try: return fn(*a)
    except remediation.RemediationError as e: raise HTTPException(409, str(e))

@app.post("/v1/remediation/propose")
def propose(b: ProposeIn, tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        inc = next((i for i in store.incidents(tenant) if i["id"] == b.incident_id), None)
        if not inc: raise HTTPException(404, "incident not found")
        return _rem(remediation.propose, store, tenant, inc, b.action_id, "operator")

@app.post("/v1/remediation/{rid}/approve")
def approve(rid: int, tenant: str = Depends(principal("dashboard"))):
    with LOCK: return _rem(remediation.decide, store, tenant, rid, True, "operator")

@app.post("/v1/remediation/{rid}/reject")
def reject(rid: int, tenant: str = Depends(principal("dashboard"))):
    with LOCK: return _rem(remediation.decide, store, tenant, rid, False, "operator")

@app.post("/v1/remediation/{rid}/rollback")
def rollback(rid: int, tenant: str = Depends(principal("dashboard"))):
    with LOCK: return _rem(remediation.rollback, store, tenant, rid, "operator")

@app.get("/v1/remediation")
def rem_list(tenant: str = Depends(principal("dashboard"))):
    with LOCK: return store.rem_list(tenant)

@app.get("/v1/audit")
def audit(tenant: str = Depends(principal("dashboard"))):
    with LOCK: return store.audit(tenant)

class ConfigIn(BaseModel):
    topology: dict[str, str] = {}      # child source_id -> parent source_id (pseudonymous ids)
    aliases: dict[str, str] = {}       # source_id -> friendly name chosen by the customer

@app.put("/v1/config")
def set_config(b: ConfigIn, tenant: str = Depends(principal("dashboard"))):
    with LOCK:
        store.set_config(tenant, b.model_dump())
        eng = engine_for(tenant); eng.topology, eng.aliases = b.topology, b.aliases
        return {"status": "ok"}

@app.post("/v1/recompute")
def recompute(tenant: str = Depends(principal("dashboard"))):
    """Replay stored records in EVENT-time order (fixes detection after late/out-of-order delivery)."""
    with LOCK:
        cfg = store.get_config(tenant)
        ENGINES[tenant] = eng = TenantEngine(tenant, cfg.get("topology", {}), cfg.get("aliases", {}))
        store.clear_incidents(tenant)
        for src, m, v, ts in store.all_records(tenant): eng.ingest(src, m, v, ts, clock())
        store.save_incidents(tenant, eng.flush())
        return {"status": "recomputed", "incidents": len(eng.incidents)}

@app.get("/healthz")
def healthz(): return {"ok": True}
