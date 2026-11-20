"""All persistence. Every method takes tenant_id and filters on it. Swap this file for Supabase later."""
import hashlib, json, sqlite3, threading, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS payloads(tenant_id TEXT, payload_id TEXT, collector_id TEXT, sent_at REAL, received_at REAL,
  latency_s REAL, body TEXT, PRIMARY KEY(tenant_id, payload_id));
CREATE TABLE IF NOT EXISTS records(tenant_id TEXT, source_id TEXT, metric TEXT, ts REAL, ts_utc TEXT, source_tz TEXT,
  value REAL, payload_id TEXT);
CREATE INDEX IF NOT EXISTS ix_rec ON records(tenant_id, source_id, metric, ts);
CREATE TABLE IF NOT EXISTS collectors(tenant_id TEXT, collector_id TEXT, last_seen REAL, version TEXT, cpu REAL,
  mem REAL, uptime_s REAL, config_status TEXT, PRIMARY KEY(tenant_id, collector_id));
CREATE TABLE IF NOT EXISTS tenant_config(tenant_id TEXT PRIMARY KEY, body TEXT);
CREATE TABLE IF NOT EXISTS counters(tenant_id TEXT, name TEXT, value INTEGER, PRIMARY KEY(tenant_id, name));
CREATE TABLE IF NOT EXISTS state_history(tenant_id TEXT, ts REAL, entity TEXT, old TEXT, new TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS incidents(tenant_id TEXT, id TEXT, body TEXT, PRIMARY KEY(tenant_id, id));
CREATE TABLE IF NOT EXISTS remediations(tenant_id TEXT, id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT,
  action_id TEXT, text TEXT, status TEXT, risk TEXT, rollback TEXT, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS audit(tenant_id TEXT, seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, kind TEXT,
  details TEXT, prev TEXT, hash TEXT);
"""


def pct(vals, p):
    if not vals: return None
    v = sorted(vals); return round(v[int(p * (len(v) - 1))], 3)


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False); self.lock = threading.RLock()
        self.db.executescript(SCHEMA); self.db.commit()

    def q(self, sql, args=()):
        with self.lock: return self.db.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self.lock, self.db: return self.db.execute(sql, args)

    # ---- ingest (atomic; returns False for a duplicate payload_id) ----
    def add_payload(self, tenant, p, sent_at, now, latency, rec_rows):
        try:
            with self.lock, self.db:
                self.db.execute("INSERT INTO payloads VALUES (?,?,?,?,?,?,?)",
                                (tenant, p["payload_id"], p["collector_id"], sent_at, now, latency, json.dumps(p)))
                self.db.executemany("INSERT INTO records VALUES (?,?,?,?,?,?,?,?)", rec_rows)
                h = p.get("collector_health") or {}
                self.db.execute("INSERT OR REPLACE INTO collectors VALUES (?,?,?,?,?,?,?,?)",
                                (tenant, p["collector_id"], now, p["collector_version"], h.get("cpu_pct"),
                                 h.get("mem_pct"), h.get("uptime_s"), h.get("config_status", "ok")))
            return True
        except sqlite3.IntegrityError:
            return False

    def bump(self, tenant, name, n=1):
        self.x("INSERT INTO counters VALUES (?,?,?) ON CONFLICT(tenant_id,name) DO UPDATE SET value=value+?",
               (tenant, name, n, n))

    def counter(self, tenant, name):
        r = self.q("SELECT value FROM counters WHERE tenant_id=? AND name=?", (tenant, name)); return r[0][0] if r else 0

    # ---- reads (always tenant scoped) ----
    def series(self, tenant, source, metric, since=0):
        return self.q("SELECT ts, value FROM records WHERE tenant_id=? AND source_id=? AND metric=? AND ts>=? ORDER BY ts",
                      (tenant, source, metric, since))

    def pairs(self, tenant, since):
        return self.q("SELECT DISTINCT source_id, metric FROM records WHERE tenant_id=? AND ts>=?", (tenant, since))

    def all_records(self, tenant):
        return self.q("SELECT source_id, metric, value, ts FROM records WHERE tenant_id=? ORDER BY ts", (tenant,))

    def collectors(self, tenant):
        cols = ["collector_id", "last_seen", "version", "cpu", "mem", "uptime_s", "config_status"]
        return [dict(zip(cols, r)) for r in self.q(
            "SELECT collector_id,last_seen,version,cpu,mem,uptime_s,config_status FROM collectors WHERE tenant_id=?", (tenant,))]

    def received(self, tenant, limit=20):
        return [json.loads(r[0]) for r in self.q(
            "SELECT body FROM payloads WHERE tenant_id=? ORDER BY received_at DESC, rowid DESC LIMIT ?", (tenant, limit))]

    def latencies(self, tenant, limit=500):
        return [r[0] for r in self.q("SELECT latency_s FROM payloads WHERE tenant_id=? ORDER BY received_at DESC LIMIT ?",
                                     (tenant, limit))]

    def payload_count(self, tenant): return self.q("SELECT COUNT(*) FROM payloads WHERE tenant_id=?", (tenant,))[0][0]

    # ---- config, history, incidents ----
    def get_config(self, tenant):
        r = self.q("SELECT body FROM tenant_config WHERE tenant_id=?", (tenant,)); return json.loads(r[0][0]) if r else {}

    def set_config(self, tenant, cfg):
        self.x("INSERT OR REPLACE INTO tenant_config VALUES (?,?)", (tenant, json.dumps(cfg)))

    def last_state(self, tenant, entity):
        r = self.q("SELECT new FROM state_history WHERE tenant_id=? AND entity=? ORDER BY rowid DESC LIMIT 1", (tenant, entity))
        return r[0][0] if r else None

    def add_transition(self, tenant, ts, entity, old, new, reason):
        self.x("INSERT INTO state_history VALUES (?,?,?,?,?,?)", (tenant, ts, entity, old, new, reason))

    def history(self, tenant, limit=50):
        return [dict(ts=r[0], entity=r[1], old=r[2], new=r[3], reason=r[4]) for r in self.q(
            "SELECT ts,entity,old,new,reason FROM state_history WHERE tenant_id=? ORDER BY rowid DESC LIMIT ?", (tenant, limit))]

    def save_incidents(self, tenant, incs):
        for i in incs:
            self.x("INSERT OR REPLACE INTO incidents VALUES (?,?,?)", (tenant, i["id"], json.dumps(i)))

    def clear_incidents(self, tenant): self.x("DELETE FROM incidents WHERE tenant_id=?", (tenant,))

    def incidents(self, tenant):
        return [json.loads(r[0]) for r in self.q("SELECT body FROM incidents WHERE tenant_id=? ORDER BY id DESC", (tenant,))]

    # ---- remediation + tamper-evident audit ----
    def audit_add(self, tenant, actor, kind, details):
        with self.lock:
            r = self.db.execute("SELECT hash FROM audit WHERE tenant_id=? ORDER BY seq DESC LIMIT 1", (tenant,)).fetchone()
            prev, ts = (r[0] if r else "0" * 64), time.time()
            body = json.dumps(dict(ts=ts, actor=actor, kind=kind, details=details, prev=prev), sort_keys=True)
            h = hashlib.sha256(body.encode()).hexdigest()
            self.x("INSERT INTO audit(tenant_id,ts,actor,kind,details,prev,hash) VALUES (?,?,?,?,?,?,?)",
                   (tenant, ts, actor, kind, json.dumps(details, sort_keys=True), prev, h))

    def audit(self, tenant):
        return [dict(seq=r[0], ts=r[1], actor=r[2], kind=r[3], details=json.loads(r[4]), hash=r[5][:12]) for r in self.q(
            "SELECT seq,ts,actor,kind,details,hash FROM audit WHERE tenant_id=? ORDER BY seq", (tenant,))]

    def rem_create(self, tenant, inc_id, action_id, text, risk, rollback):
        now = time.time()
        c = self.x("INSERT INTO remediations(tenant_id,incident_id,action_id,text,status,risk,rollback,created,updated) "
                   "VALUES (?,?,?,?,?,?,?,?,?)", (tenant, inc_id, action_id, text, "pending_approval", risk, rollback, now, now))
        return c.lastrowid

    def rem_get(self, tenant, rid):
        r = self.q("SELECT id,incident_id,action_id,text,status,risk,rollback FROM remediations WHERE tenant_id=? AND id=?",
                   (tenant, rid))
        return dict(zip(["id", "incident_id", "action_id", "text", "status", "risk", "rollback"], r[0])) if r else None

    def rem_list(self, tenant):
        cols = ["id", "incident_id", "action_id", "text", "status", "risk", "rollback"]
        return [dict(zip(cols, r)) for r in self.q(
            "SELECT id,incident_id,action_id,text,status,risk,rollback FROM remediations WHERE tenant_id=? ORDER BY id DESC", (tenant,))]

    def rem_status(self, tenant, rid, status):
        self.x("UPDATE remediations SET status=?, updated=? WHERE tenant_id=? AND id=?", (status, time.time(), tenant, rid))
