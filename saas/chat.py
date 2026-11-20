"""'Infrastructure ChatGPT'. The engine computes the facts; the LLM may only phrase them.
Falls back to a deterministic template if no API key, a network error, or the LLM invents numbers."""
import json, os, re
import requests


def build_facts(overview, incident):
    return {"health_score": overview["health"]["score"], "security_score": overview["security"]["score"],
            "open_incidents": overview["open_incidents"],
            "incident": None if not incident else {k: incident.get(k) for k in (
                "id", "title", "cause", "confidence", "health_state", "components", "reasoning", "contributions",
                "rca_chain", "recommendations", "timeline")}}


def _intent(q):
    q = q.lower()
    if any(w in q for w in ("fix", "recommend", "what should", "how can", "resolve")): return "fix"
    if any(w in q for w in ("cause", "why did", "root", "what happened")): return "cause"
    return "why"


def _template(q, f):
    inc = f["incident"]
    if not inc:
        return f"No open incidents. Health score is {f['health_score']}/100 and security score is {f['security_score']}/100."
    top = inc["contributions"][:3]
    sig = "; ".join(f"{c['label']} on {c['component']} " + (f"up {c['pct']}%" if c["pct"] is not None
                    else f"at {c['value']} (baseline {c['baseline']})") for c in top)
    it = _intent(q)
    if it == "fix":
        return ("Recommended actions (confidence %d%%): " % round(inc["confidence"] * 100)) + \
               " ".join(f"{i+1}. {r['text']}." for i, r in enumerate(inc["recommendations"]))
    if it == "cause":
        return "Likely cause: " + inc["cause"] + ". Sequence: " + " -> ".join(s["text"] for s in inc["rca_chain"]) + "."
    return (f"Health is {inc['health_state'].upper()} because of '{inc['title']}'. Main signals: {sig}. "
            f"Likely cause: {inc['cause']} (confidence {round(inc['confidence']*100)}%).")


def _gemini(prompt):
    key = os.getenv("GEMINI_API_KEY")
    if not key: return None
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    try:
        r = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                          headers={"x-goog-api-key": key}, timeout=8,
                          json={"contents": [{"parts": [{"text": prompt}]}]})
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return None


def answer(question, facts):
    base = _template(question, facts)
    prompt = ("You are an infrastructure assistant. Answer the question in 2-4 sentences using ONLY the facts "
              "below. Never invent numbers or causes.\nFACTS:\n" + json.dumps(facts, default=str) + "\nQUESTION: " + question)
    text = _gemini(prompt)
    if text:
        allowed = set(re.findall(r"\d+(?:\.\d+)?", json.dumps(facts, default=str) + base))
        if all(n in allowed for n in re.findall(r"\d+(?:\.\d+)?", text)):     # hallucination guard
            return {"answer": text.strip(), "source": "gemini", "facts_used": facts}
    return {"answer": base, "source": "template", "facts_used": facts}
