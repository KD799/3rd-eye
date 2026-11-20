"""Explainable AIOps core (metadata only): baselines -> anomalies -> incidents -> root cause -> advice."""
import statistics
from collections import deque, defaultdict
from datetime import datetime, timezone
from config import CFG, METRICS, EDGES, CATEGORY, CATEGORY_TITLE, CATEGORY_CAUSE, PLAYBOOK


def iso(ts): return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def parse_ts(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


class Detector:
    """Per-series robust baseline (median/MAD) + persistence. Learns online: no training data needed."""
    def __init__(self):
        self.hist = defaultdict(lambda: deque(maxlen=CFG["window"]))
        self.recent = defaultdict(lambda: deque(maxlen=CFG["persist_n"]))

    def learning(self, key): return len(self.hist[key]) < CFG["min_samples"]

    def score(self, key, metric, x):
        h, m = self.hist[key], METRICS[metric]
        if len(h) < CFG["min_samples"]:
            h.append(x); return None                         # learning phase: no alerts yet
        med = statistics.median(h)
        mad = max(statistics.median(abs(v - med) for v in h), m["floor"], 0.05 * abs(med))
        z = 0.6745 * (x - med) / mad
        dev = z >= CFG["z"]                                  # only upward deviations are "bad" here
        self.recent[key].append(dev)
        if not dev: h.append(x)                              # never let anomalies poison the baseline
        hard = m["hard"] is not None and x >= m["hard"]
        if not ((dev and sum(self.recent[key]) >= CFG["persist_k"]) or hard):
            return None
        pct = (x - med) / med * 100 if med >= 1 else None
        return {"value": x, "baseline": med, "z": z, "pct": pct,
                "severity": "high" if z >= 2 * CFG["z"] or hard else "medium", "hard": hard}


class TenantEngine:
    def __init__(self, tenant, topology=None, aliases=None):
        self.tenant, self.topology, self.aliases = tenant, topology or {}, aliases or {}
        self.det = Detector()
        self.signals, self.incidents, self.events = {}, {}, deque(maxlen=300)
        self.clock = 0.0; self.raw_alerts = 0; self.late = 0
        self.newest, self.seen, self.dirty, self.n_inc = {}, {}, set(), 0

    # ---- topology helpers (ids are pseudonymous; aliases are friendly names set by the customer) ----
    def name(self, src): return self.aliases.get(src, src[:6])
    def anc(self, src):
        out, cur = set(), src
        while cur in self.topology and self.topology[cur] not in out:
            cur = self.topology[cur]; out.add(cur)
        return out
    def related(self, a, b):
        pa = self.topology.get(a)
        return a == b or a in self.anc(b) or b in self.anc(a) or (pa is not None and pa == self.topology.get(b))

    # ---- ingestion ----
    def ingest(self, source, metric, value, ts, now_wall):
        key = f"{source}|{metric}"
        self.seen[source] = now_wall
        if ts < self.newest.get(key, 0):                     # late/out-of-order: stored by event time,
            self.late += 1; return None                      # skipped by the live detector (see recompute)
        self.newest[key] = ts; self.clock = max(self.clock, ts)
        a = self.det.score(key, metric, value)
        if a is None: return None
        a.update(source=source, metric=metric, ts=ts)
        self.raw_alerts += 1
        self._attach(a, key)
        return a

    def add_event(self, source, ts, category, severity, count):
        self.clock = max(self.clock, ts)
        self.events.append({"source": source, "ts": ts, "category": category, "severity": severity, "count": count})

    def _attach(self, a, key):
        sig = self.signals.get(key)
        inc = self.incidents.get(sig["inc"]) if sig else None
        if sig and inc and inc["status"] == "open":
            if a["z"] >= sig["peak_z"]: sig.update(peak_z=a["z"], peak_value=a["value"], peak_pct=a["pct"])
            sig.update(last=a["ts"], value=a["value"], z=a["z"], pct=a["pct"], count=sig["count"] + 1,
                       severity="high" if "high" in (sig["severity"], a["severity"]) else a["severity"])
        else:
            sig = dict(source=a["source"], metric=a["metric"], onset=a["ts"], last=a["ts"], value=a["value"],
                       baseline=a["baseline"], z=a["z"], peak_z=a["z"], peak_value=a["value"], peak_pct=a["pct"],
                       pct=a["pct"], severity=a["severity"], count=1)
            inc = self._find_incident(a) or self._new_incident(a)
            sig["inc"] = inc["id"]; inc["keys"].append(key)
            self.signals[key] = sig
        inc["last"] = a["ts"]; inc["raw_alerts"] += 1; self.dirty.add(inc["id"])

    def _find_incident(self, a):
        for inc in self.incidents.values():
            if inc["status"] == "open" and a["ts"] - inc["last"] <= CFG["corr_window"] and \
               any(self.related(a["source"], self.signals[k]["source"]) for k in inc["keys"]):
                return inc
        return None

    def _new_incident(self, a):
        self.n_inc += 1
        inc = {"id": f"INC-{self.n_inc:04d}", "tenant": self.tenant, "status": "open", "opened": a["ts"],
               "last": a["ts"], "keys": [], "raw_alerts": 0}
        self.incidents[inc["id"]] = inc
        return inc

    def active_signals(self):
        return [s for s in self.signals.values() if self.incidents.get(s["inc"], {}).get("status") == "open"
                and self.clock - s["last"] <= CFG["active_s"]]

    def flush(self):
        for inc in self.incidents.values():
            if inc["status"] == "open" and self.clock - inc["last"] > CFG["resolve_after"]:
                inc["status"] = "resolved"; inc["resolved"] = inc["last"]; self.dirty.add(inc["id"])
        changed = []
        for iid in list(self.dirty):
            self._diagnose(self.incidents[iid]); changed.append(self.incidents[iid])
        self.dirty.clear()
        return changed

    # ---- root cause, explanation, recommendation ----
    def _diagnose(self, inc):
        sigs = [self.signals[k] for k in inc["keys"]]
        bm = {}                                              # aggregate per metric across components
        for s in sigs:
            b = bm.setdefault(s["metric"], {"onset": s["onset"], "peak_z": s["peak_z"], "sig": s, "peak": s})
            if s["onset"] < b["onset"]: b["onset"], b["sig"] = s["onset"], s
            if s["peak_z"] >= b["peak_z"]: b["peak_z"], b["peak"] = s["peak_z"], s
        active = set(bm)
        roots = [m for m in active if not any(c == m and p in active for p, c in EDGES)]
        root = min(roots, key=lambda m: (bm[m]["onset"], -METRICS[m]["w"]))
        reach, todo = {root}, [root]
        while todo:
            cur = todo.pop()
            for p, c in EDGES:
                if p == cur and c in active and c not in reach: reach.add(c); todo.append(c)
        explained = len(reach) / len(active)
        ordered = all(bm[c]["onset"] >= bm[p]["onset"] - 5 for p, c in EDGES if p in reach and c in reach)
        conf = 0.45 + 0.30 * explained + 0.12 * min(1, bm[root]["peak_z"] / 20) + (0.10 if ordered else 0)
        if len(active) == 1: conf -= 0.10
        conf = round(max(0.35, min(0.97, conf)), 2)

        cat = CATEGORY[root]
        rs = bm[root]["sig"]; comp = self.name(rs["source"])
        chain = sorted(reach, key=lambda m: bm[m]["onset"])
        steps = [{"metric": m, "label": METRICS[m]["label"], "component": self.name(bm[m]["sig"]["source"]),
                  "onset_utc": iso(bm[m]["onset"]), "text": f"{METRICS[m]['label']} increased on {self.name(bm[m]['sig']['source'])}"}
                 for m in chain]
        reasoning = [f"Earliest abnormal signal: {METRICS[root]['label']} on {comp} at {iso(bm[root]['onset'])}"]
        for p, c in EDGES:
            if p in reach and c in reach:
                reasoning.append(f"{METRICS[p]['label']} -> {METRICS[c]['label']} "
                                 f"(started {bm[c]['onset'] - bm[p]['onset']:+.0f}s later; known causal link)")
        extra = sorted(active - reach)
        if extra: reasoning.append("Also deviating, not explained by the chain: " + ", ".join(METRICS[m]["label"] for m in extra))
        reasoning.append(f"Hypothesis: {CATEGORY_CAUSE[cat]} (explains {len(reach)}/{len(active)} deviating metrics)")

        # contribution of each signal to the incident (normalized weight x strength)
        raw = {m: METRICS[m]["w"] * min(1, bm[m]["peak_z"] / 20) for m in active}
        tot = sum(raw.values()) or 1
        contrib = sorted(({"metric": m, "label": METRICS[m]["label"], "component": self.name(bm[m]["sig"]["source"]),
                           "value": round(bm[m]["peak"]["peak_value"], 2), "baseline": round(bm[m]["peak"]["baseline"], 2),
                           "pct": None if bm[m]["peak"]["peak_pct"] is None else round(bm[m]["peak"]["peak_pct"]),
                           "z": round(bm[m]["peak_z"], 1), "contribution": round(100 * raw[m] / tot)}
                          for m in active), key=lambda d: -d["contribution"])

        sev = "high" if any(s["severity"] == "high" for s in sigs) or len(active) >= 4 else "medium"
        state = "Poor" if sev == "high" else "Fair" if len(active) >= 2 else "Good"
        def leaf(c):
            d = f"+{c['pct']}%" if c["pct"] is not None else f"{c['value']} (baseline {c['baseline']})"
            return {"label": f"{c['label']} {d}", "contribution": c["contribution"]}
        tree = {"label": f"{state} health", "children": [leaf(c) for c in contrib]}

        tl = [(s["onset"], f"{METRICS[s['metric']]['label']} increased on {self.name(s['source'])}") for s in sigs]
        comps_raw = {s["source"] for s in sigs}
        for e in self.events:
            if inc["opened"] - 60 <= e["ts"] <= inc["last"] + 60 and any(self.related(e["source"], c) for c in comps_raw):
                tl.append((e["ts"], f"Security: {e['category'].replace('_', ' ')} (risk {e['severity']}, count {e['count']})"))
        tl.append((inc["last"], f"Health state: {state}"))
        timeline = [{"ts_utc": iso(t), "text": x} for t, x in sorted(tl)]

        recs = [{"id": f"{inc['id']}:{i}", "action_id": a, "text": t.format(t=comp), "remediable": r,
                 "target": comp, "confidence": conf} for i, (a, t, r) in enumerate(PLAYBOOK[cat])]
        inc.update(title=f"{CATEGORY_TITLE[cat]} at {comp}", category=cat, cause=CATEGORY_CAUSE[cat], confidence=conf,
                   severity=sev, health_state=state, root_metric=root, root_component=comp,
                   components=sorted({self.name(s["source"]) for s in sigs}), rca_chain=steps, reasoning=reasoning,
                   contributions=contrib, tree=tree, timeline=timeline, recommendations=recs,
                   opened_utc=iso(inc["opened"]), last_utc=iso(inc["last"]), explained=f"{len(reach)}/{len(active)}")
