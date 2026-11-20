"""End-to-end: simulator -> collector policy (redact/allow-list/hash) -> SaaS API -> AI engine -> answers.
Run from third-eye/:  python tests/e2e_test.py"""
import os, random, sys, tempfile, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "saas"), os.path.join(ROOT, "collector")]
os.chdir(os.path.join(ROOT, "collector"))

from fastapi.testclient import TestClient
import api
from adapters import build, load_faults
from adapters.base import utc_iso
from policy import build_payload, pseudonymize

api.init(os.path.join(tempfile.mkdtemp(), "t.db"))
T0 = 1_700_000_000
now = [T0]
api.clock = lambda: now[0]                       # fake wall clock = event time (+latency below)
c = TestClient(api.app)
COL, DASH = {"X-API-Key": "collector-key-A"}, {"X-API-Key": "dash-key-A"}
H = {n: pseudonymize(n) for n in ("switch-a", "app-x", "db-1", "worker-1", "site-mumbai")}
c.put("/v1/config", headers=DASH, json={"topology": {H["app-x"]: H["switch-a"], H["db-1"]: H["switch-a"], H["switch-a"]: H["site-mumbai"]},
      "aliases": {H["switch-a"]: "Switch-A", H["app-x"]: "App-X", H["db-1"]: "DB-1", H["worker-1"]: "Worker-1", H["site-mumbai"]: "Site-Mumbai"}})

sim = build("simulator", faults=load_faults("faults.json"), start_epoch=T0, tick_s=1)
rng = random.Random(3)
first = None
def tick_payload(i, extra=True, shift=0):
    recs = [r.to_dict() for r in sim.read()] if shift == 0 else []
    ts = utc_iso(T0 + i + shift)
    if extra:
        recs.append(dict(source_id="app-x", metric="auth_failures", value=float(rng.choice([0, 0, 1]) + (25 if 88 <= i < 110 else 0)), ts_utc=ts, source_tz="Asia/Kolkata"))
        recs.append(dict(source_id="app-x", metric="api_response_time", value=120 + rng.gauss(0, 8) + (600 if 85 <= i < 115 else 0), ts_utc=ts, source_tz="Asia/Kolkata"))
        recs.append(dict(source_id="worker-1", metric="mem", value=60 + 0.15 * i + rng.gauss(0, .3), ts_utc=ts, source_tz="Asia/Kolkata"))
    ev = [dict(event_category="auth_failure_burst", severity="high", count=40, risk="high", source_id="app-x", ts_utc=ts)] if i == 92 else []
    p, _ = build_payload("tenantA", "collector-01", "0.1.0", ts, recs, ev, {"cpu_pct": 12.0, "mem_pct": 40.0, "uptime_s": i, "config_status": "ok"})
    return p

payloads = []
for i in range(140):
    now[0] = T0 + i + 0.8
    p = tick_payload(i); payloads.append(p)
    r = c.post("/v1/ingest", headers=COL, json=p); assert r.status_code == 200, r.text

print("== INCIDENTS ==")
incs = c.get("/v1/incidents", headers=DASH).json()
ov = c.get("/v1/overview", headers=DASH).json()
print("noise reduction:", ov["noise_reduction"])
inc = max(incs, key=lambda i: i["raw_alerts"])
print(inc["id"], inc["title"], "| conf", inc["confidence"], "| severity", inc["severity"], "| status", inc["status"])
print("components:", inc["components"], "| explained", inc["explained"])
print("RCA chain:", " -> ".join(s["label"] for s in inc["rca_chain"]))
print("tree:", json.dumps(inc["tree"])[:400])
print("timeline:"); [print("  ", t["ts_utc"], t["text"]) for t in inc["timeline"]]
print("recs:", [r["text"] for r in inc["recommendations"]])
print("\n== SCORES (now) ==", ov["health"]["score"], ov["security"]["score"])
print("forecast:", ov["predicted_risks"])

print("\n== REMEDIATION (simulated) ==")
rid = c.post("/v1/remediation/propose", headers=DASH, json={"incident_id": inc["id"], "action_id": inc["recommendations"][-1]["action_id"]}).json()
print(rid["status"], rid["text"])
print(c.post(f"/v1/remediation/{rid['id']}/approve", headers=DASH).json()["status"],
      c.post(f"/v1/remediation/{rid['id']}/rollback", headers=DASH).json()["status"])
print("audit:", [a["kind"] for a in c.get("/v1/audit", headers=DASH).json()])

print("\n== CHAT ==")
for q in ("Why is my server unhealthy?", "How can I fix it?"):
    print("Q:", q, "\nA:", c.post("/v1/chat", headers=DASH, json={"question": q}).json()["answer"], "\n")

print("== RELIABILITY / SECURITY CHECKS ==")
d = c.post("/v1/ingest", headers=COL, json=payloads[5]).json(); print("replay same payload ->", d["status"])
late = tick_payload(50, extra=False, shift=0) if False else None
lp, _ = build_payload("tenantA", "collector-01", "0.1.0", utc_iso(T0 + 150), [dict(source_id="switch-a", metric="latency", value=21.0, ts_utc=utc_iso(T0 + 10), source_tz="Asia/Kolkata")], [], {})
now[0] = T0 + 150; print("out-of-order payload ->", c.post("/v1/ingest", headers=COL, json=lp).json()["status"])
print("reliability:", c.get("/v1/reliability", headers=DASH).json())
bad = dict(payloads[0], payload_id="zzzzzzzzzz1", records=[dict(payloads[0]["records"][0], raw_log="password=123")])
print("extra/unknown field ->", c.post("/v1/ingest", headers=COL, json=bad).status_code, "(422 = rejected by SaaS schema)")
print("wrong tenant key ->", c.post("/v1/ingest", headers={"X-API-Key": "collector-key-B"}, json=payloads[0]).status_code)
print("tenantB sees tenantA incidents? ->", len(c.get("/v1/incidents", headers={"X-API-Key": "dash-key-B"}).json()), "incidents;",
      c.get("/v1/received", headers={"X-API-Key": "dash-key-B"}).json())
print("dashboard key can't ingest ->", c.post("/v1/ingest", headers=DASH, json=payloads[0]).status_code)

print("\n== STALE DATA / OFFLINE ==")
now[0] = T0 + 140 + 90
ov2 = c.get("/v1/overview", headers=DASH).json()
print({k: v["state"] + " (" + v["reason"] + ")" for k, v in ov2["collectors"].items()})
print("state history:", [(h["entity"][:14], h["old"], "->", h["new"]) for h in c.get("/v1/health", headers=DASH).json()["history"][:4]])
