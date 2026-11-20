"""
Explainable AIOps engine (metadata-only, runs on the SaaS tier).
Pipeline: baseline -> anomaly (persistence) -> correlation -> root cause -> recommendation -> health.
Pure stdlib. Every output carries the evidence that produced it.
"""
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from statistics import median
import time

# ---------- config (make this a YAML/settings page in the UI) ----------
CFG = {
    "window": 60,            # samples kept per baseline
    "min_samples": 20,       # warm-up before scoring
    "z_threshold": 3.5,      # robust z-score to count as deviating
    "persist_k": 3, "persist_n": 5,   # k of last n samples must deviate
    "corr_window_s": 120,    # alerts within this window can merge
    "stale_s": 60,           # no heartbeat -> Poor
    "hard_limits": {"cpu": 98, "mem": 98, "disk": 97},  # safety net, not the main detector
}
# How "upstream"/causal a metric is when ranking likely causes
METRIC_WEIGHT = {"packet_loss": 1.0, "iface_errors": 0.9, "latency": 0.8,
                 "auth_failures": 0.7, "cpu": 0.5, "mem": 0.5, "disk": 0.4}
# Dependency topology: child -> parent it depends on
TOPOLOGY = {"app-x": "switch-a", "db-1": "switch-a", "switch-a": "site-mumbai"}

# ---------- data structures ----------
@dataclass
class Anomaly:
    tenant: str; source: str; metric: str
    ts: float; value: float; baseline: float; z: float; severity: str
    def why(self):
        return (f"{self.metric} on {self.source} = {self.value:.1f} vs baseline "
                f"{self.baseline:.1f} (robust z={self.z:+.1f})")

@dataclass
class Incident:
    id: str; tenant: str; anomalies: list
    components: list = field(default_factory=list)
    cause: str = ""; confidence: float = 0.0
    reasoning: list = field(default_factory=list)
    recommendation: dict = field(default_factory=dict)
    severity: str = "medium"

# ---------- 1. baseline + anomaly detection ----------
class AnomalyDetector:
    def __init__(self, cfg=CFG):
        self.cfg = cfg
        self.hist = defaultdict(lambda: deque(maxlen=cfg["window"]))
        self.recent = defaultdict(lambda: deque(maxlen=cfg["persist_n"]))

    @staticmethod
    def _robust_z(x, data):
        med = median(data)
        mad = median(abs(v - med) for v in data) or 1e-9
        mad = max(mad, 0.05 * abs(med), 1e-3)   # floor stops tiny MAD exploding z
        return 0.6745 * (x - med) / mad, med

    def ingest(self, tenant, source, metric, value, ts):
        key = (tenant, source, metric)
        h = self.hist[key]
        out = None
        if len(h) >= self.cfg["min_samples"]:
            z, base = self._robust_z(value, h)
            dev = abs(z) >= self.cfg["z_threshold"]
            self.recent[key].append(dev)
            hard = value >= self.cfg["hard_limits"].get(metric, float("inf"))
            persistent = sum(self.recent[key]) >= self.cfg["persist_k"]
            if persistent or hard:
                sev = "high" if abs(z) > 2 * self.cfg["z_threshold"] or hard else "medium"
                out = Anomaly(tenant, source, metric, ts, value, base, z, sev)
            if not dev:                       # don't poison the baseline with anomalies
                h.append(value)
        else:
            h.append(value)
        return out

# ---------- 2. correlation ----------
def _related(a, b):
    if a.source == b.source: return True
    pa, pb = TOPOLOGY.get(a.source), TOPOLOGY.get(b.source)
    return pa == b.source or pb == a.source or (pa and pa == pb)

class Correlator:
    def __init__(self, cfg=CFG): self.cfg = cfg; self.n = 0
    def group(self, anomalies):
        groups = []                            # simple union by relatedness + time
        for a in sorted(anomalies, key=lambda x: x.ts):
            for g in groups:
                if g[0].tenant == a.tenant and any(
                    abs(a.ts - m.ts) <= self.cfg["corr_window_s"] and _related(a, m) for m in g):
                    g.append(a); break
            else:
                groups.append([a])
        incidents = []
        for g in groups:
            self.n += 1
            incidents.append(Incident(f"INC-{self.n:04d}", g[0].tenant, g))
        return incidents

# ---------- 3. root cause + recommendation (transparent rules + weights) ----------
PLAYBOOK = {
    "network_link_degradation": ("Check interface errors/duplex and upstream link on {up}; "
                                 "fail over traffic if loss persists.", "reversible: re-enable link"),
    "resource_saturation": ("Investigate top processes on {up}; consider scaling out or "
                            "restarting the offending service.", "reversible: restore previous replica count"),
    "credential_attack": ("Rate-limit or temporarily block the source; force MFA reset for "
                          "targeted accounts.", "reversible: remove block rule"),
    "unknown_anomaly": ("Investigate {up}; no strong pattern matched.", "n/a"),
}

def diagnose(inc: Incident):
    an = inc.anomalies
    metrics = {a.metric for a in an}
    inc.components = sorted({a.source for a in an} | {TOPOLOGY[a.source] for a in an if a.source in TOPOLOGY})
    # score each hypothesis from the signals present
    h = {
        "network_link_degradation": 1.0*("packet_loss" in metrics) + 0.9*("iface_errors" in metrics) + 0.6*("latency" in metrics),
        "resource_saturation": 0.7*("cpu" in metrics) + 0.7*("mem" in metrics) + 0.3*("disk" in metrics),
        "credential_attack": 1.2*("auth_failures" in metrics),
    }
    cause, score = max(h.items(), key=lambda kv: kv[1])
    if score == 0: cause = "unknown_anomaly"
    total = sum(h.values()) or 1
    inc.cause = cause
    inc.confidence = round(min(0.95, 0.4 + 0.5 * score / total * min(1, score)), 2)
    # root component = earliest-onset, most causal metric on the most upstream source
    root = min(an, key=lambda a: (a.ts, -METRIC_WEIGHT.get(a.metric, .3)))
    up = root.source   # the component where the earliest causal signal appeared
    # reasoning path, ordered by onset
    inc.reasoning = [f"{i+1}. {a.why()}" for i, a in enumerate(sorted(an, key=lambda a: a.ts))]
    inc.reasoning.append(f"=> hypothesis '{cause}' (signals present: {sorted(metrics)})")
    step, rollback = PLAYBOOK[cause]
    inc.recommendation = {"action": step.format(up=up), "why": f"Earliest/most causal signal is "
        f"{root.metric} on {root.source}", "rollback": rollback, "requires_approval": True}
    inc.severity = "high" if any(a.severity == "high" for a in an) else "medium"
    return inc

# ---------- 4. health state (Excellent/Good/Fair/Poor) ----------
def health(last_seen_ts, now, active_anoms, critical_event=False, cfg=CFG):
    if now - last_seen_ts > cfg["stale_s"] or critical_event:
        return "Poor", f"no heartbeat for {now-last_seen_ts:.0f}s" if now - last_seen_ts > cfg["stale_s"] else "critical event"
    if any(a.severity == "high" for a in active_anoms): return "Poor", "severe degradation"
    if len(active_anoms) >= 2: return "Fair", "multiple deviations"
    if active_anoms: return "Good", "minor deviation"
    return "Excellent", "all metrics within baseline"

# ---------- demo / self-test ----------
if __name__ == "__main__":
    import random, json
    random.seed(1)
    det, cor = AnomalyDetector(), Correlator()
    found, t0 = [], 1_700_000_000
    for i in range(120):
        ts = t0 + i * 5
        inject = i >= 80        # fault begins: loss first, then latency on switch-a, cpu on app-x
        for src, m, base, noise in [("switch-a","packet_loss",0.2,.1),("switch-a","latency",20,3),
                                    ("app-x","cpu",35,4),("db-1","mem",50,3)]:
            v = random.gauss(base, noise)
            if inject and (src, m) == ("switch-a","packet_loss"): v += 6
            if inject and i >= 84 and (src, m) == ("switch-a","latency"): v += 80
            if inject and i >= 86 and (src, m) == ("app-x","cpu"): v += 30
            a = det.ingest("tenantA", src, m, max(v, 0), ts)
            if a: found.append(a)
    for inc in map(diagnose, cor.group(found)):
        print(f"\n{inc.id} [{inc.severity}] cause={inc.cause} conf={inc.confidence} components={inc.components}")
        print("\n".join("  " + r for r in inc.reasoning[:4]), "\n  ...")
        print("  ACTION:", inc.recommendation["action"])
    print(f"\nNoise reduction: {len(found)} raw anomalies -> {len(cor.group(found))} incident(s)")

