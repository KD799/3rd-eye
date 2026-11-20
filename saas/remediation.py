"""Safe, SIMULATED remediation: policy check -> human approval -> audit -> rollback. Nothing is executed for real."""
from config import ALLOWED_ACTIONS


class RemediationError(Exception):
    pass


def propose(store, tenant, incident, action_id, actor):
    rec = next((r for r in incident.get("recommendations", []) if r["action_id"] == action_id), None)
    if not rec or not rec["remediable"]:
        raise RemediationError("action is not a remediable recommendation of this incident")
    pol = ALLOWED_ACTIONS.get(action_id)
    if not pol: raise RemediationError("policy check failed: action not on the allow-list")
    if incident["status"] != "open": raise RemediationError("policy check failed: incident is not open")
    if any(r["incident_id"] == incident["id"] and r["action_id"] == action_id and r["status"] in ("pending_approval", "executed_simulated")
           for r in store.rem_list(tenant)):
        raise RemediationError("an identical action is already pending or executed")
    rid = store.rem_create(tenant, incident["id"], action_id, rec["text"], pol["risk"], pol["rollback"])
    store.audit_add(tenant, actor, "proposed", {"id": rid, "incident": incident["id"], "action": action_id,
                                                "policy": "passed", "risk": pol["risk"], "rollback_plan": pol["rollback"]})
    return store.rem_get(tenant, rid)


def decide(store, tenant, rid, approve, actor):
    r = store.rem_get(tenant, rid)
    if not r: raise RemediationError("unknown remediation")
    if r["status"] != "pending_approval": raise RemediationError(f"cannot decide: status is {r['status']}")
    if not approve:
        store.rem_status(tenant, rid, "rejected"); store.audit_add(tenant, actor, "rejected", {"id": rid})
    else:
        store.audit_add(tenant, actor, "approved", {"id": rid})
        store.rem_status(tenant, rid, "executed_simulated")
        store.audit_add(tenant, "system", "executed_simulated", {"id": rid, "action": r["action_id"],
                        "note": "SIMULATION: no real change made", "rollback_available": True})
    return store.rem_get(tenant, rid)


def rollback(store, tenant, rid, actor):
    r = store.rem_get(tenant, rid)
    if not r or r["status"] != "executed_simulated": raise RemediationError("only an executed action can be rolled back")
    store.rem_status(tenant, rid, "rolled_back")
    store.audit_add(tenant, actor, "rolled_back", {"id": rid, "plan": r["rollback"]})
    return store.rem_get(tenant, rid)
