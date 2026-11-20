"""Health states, health/security scores and the predictive forecast. All computed, nothing hard-coded."""
import statistics
from config import CFG, METRICS


def source_state(eng, source, now_wall):
    """Excellent / Good / Fair / Poor with a human-readable reason. Stale data downgrades the state."""
    age = now_wall - eng.seen.get(source, 0)
    if age > CFG["stale_s"]:
        return "Poor", f"no data for {age:.0f}s (stale)"
    act = [s for s in eng.active_signals() if s["source"] == source]
    crit = [e for e in eng.events if e["source"] == source and e["severity"] == "high" and eng.clock - e["ts"] <= 60]
    if crit: return "Poor", "critical security event: " + crit[-1]["category"].replace("_", " ")
    if any(s["severity"] == "high" for s in act):
        w = max(act, key=lambda s: s["peak_z"])
        return "Poor", f"severe degradation: {METRICS[w['metric']]['label']}"
    if len(act) >= 2: return "Fair", f"{len(act)} metrics deviating: " + ", ".join(METRICS[s['metric']]['label'] for s in act)
    if act: return "Good", f"minor deviation: {METRICS[act[0]['metric']]['label']}"
    learning = any(eng.det.learning(f"{source}|{m}") for m in {k.split('|')[1] for k in eng.newest if k.startswith(source + '|')})
    return "Excellent", "learning baseline (no alerts yet)" if learning else "all metrics within baseline"


def collector_state(c, now_wall):
    age = now_wall - c["last_seen"]
    if age > CFG["stale_s"]: return "Poor", f"offline: last heartbeat {age:.0f}s ago"
    if c["config_status"] != "ok": return "Fair", f"config status: {c['config_status']}"
    if (c["cpu"] or 0) > 90 or (c["mem"] or 0) > 90: return "Fair", "collector resource usage high"
    return "Excellent", "reporting normally"


def health_score(eng, now_wall):
    groups = {"infra": 0.0, "network": 0.0, "app": 0.0, "db": 0.0}
    for s in eng.active_signals():
        g = METRICS[s["metric"]]["group"]
        if g in groups:
            groups[g] += METRICS[s["metric"]]["w"] * (8 + 17 * min(1, s["peak_z"] / 30))
    stale = [src for src, t in eng.seen.items() if now_wall - t > CFG["stale_s"]]
    factors = [{"group": g, "penalty": round(min(40, p), 1)} for g, p in groups.items()]
    factors.append({"group": "stale_sources", "penalty": min(40, 30 * len(stale))})
    return {"score": round(max(0, 100 - sum(f["penalty"] for f in factors))), "factors": factors}


def security_score(eng):
    pen, factors = 0.0, []
    for s in eng.active_signals():
        if METRICS[s["metric"]]["group"] == "security":
            p = METRICS[s["metric"]]["w"] * (10 + 30 * min(1, s["peak_z"] / 30)); pen += p
            factors.append({"factor": METRICS[s["metric"]]["label"], "penalty": round(p, 1)})
    recent = [e for e in eng.events if eng.clock - e["ts"] <= 120]
    for sev, p in (("high", 20), ("medium", 10)):
        if any(e["severity"] == sev for e in recent):
            pen += p; factors.append({"factor": f"{sev}-risk security event", "penalty": p}); break
    return {"score": round(max(0, 100 - pen)), "factors": factors}


def forecast(points, metric, now_ts):
    """Linear trend on recent event-time points. Returns a risk dict or None. Heuristic, not a model."""
    warn = METRICS[metric]["warn"]
    if warn is None or len(points) < 12: return None
    xs, ys = [p[0] - points[0][0] for p in points], [p[1] for p in points]
    if statistics.pstdev(ys) < 1e-9: return None
    slope, intercept = statistics.linear_regression(xs, ys)
    r = statistics.correlation(xs, ys)
    if slope <= 0 or r < 0.8 or ys[-1] >= warn: return None
    eta = (warn - ys[-1]) / slope
    if eta > 3600: return None
    return {"metric": metric, "label": METRICS[metric]["label"], "current": round(ys[-1], 1), "threshold": warn,
            "slope_per_min": round(slope * 60, 2), "eta_minutes": round(eta / 60, 1), "fit_r": round(r, 2),
            "predicted_state": "Fair", "reason": f"{METRICS[metric]['label']} trending up and expected to reach {warn}{METRICS[metric]['unit']}"}
