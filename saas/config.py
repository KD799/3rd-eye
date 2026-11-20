"""Shared settings for the SaaS AI layer. Metadata names MUST match collector/policy.py ALLOWED_METRICS."""
import os

CFG = {"window": 60, "min_samples": 20, "z": 3.5, "persist_k": 3, "persist_n": 5,
       "corr_window": 120,     # s (event time): alerts this close + related -> same incident
       "resolve_after": 30,    # s of silence -> incident resolved
       "active_s": 20,         # a signal counts as "active" if refreshed within this many s
       "stale_s": 60}          # no data for this long -> Poor (wall clock)

# group: scoring bucket | w: how causal/important | floor: smallest meaningful change (stops noise
# on very stable metrics) | hard: absolute safety limit | warn: level used by the forecaster
METRICS = {
 "cpu":               dict(group="infra",    w=0.5, floor=1.5, hard=98, warn=90,  label="CPU usage",          unit="%"),
 "mem":               dict(group="infra",    w=0.5, floor=1.5, hard=98, warn=90,  label="Memory usage",       unit="%"),
 "disk":              dict(group="infra",    w=0.4, floor=0.5, hard=97, warn=90,  label="Disk usage",         unit="%"),
 "bandwidth":         dict(group="infra",    w=0.3, floor=5,   hard=None, warn=None, label="Bandwidth",       unit="Mbps"),
 "latency":           dict(group="network",  w=0.8, floor=3,   hard=None, warn=200, label="Network latency",  unit="ms"),
 "packet_loss":       dict(group="network",  w=1.0, floor=0.1, hard=None, warn=None, label="Packet loss",     unit="%"),
 "iface_errors":      dict(group="network",  w=0.9, floor=0.5, hard=None, warn=None, label="Interface errors", unit=""),
 "auth_failures":     dict(group="security", w=0.7, floor=1.5, hard=None, warn=None, label="Failed logins",   unit=""),
 "suspicious_activity": dict(group="security", w=0.6, floor=1, hard=None, warn=None, label="Suspicious activity", unit=""),
 "api_response_time": dict(group="app",      w=0.5, floor=20,  hard=None, warn=1000, label="API response time", unit="ms"),
 "api_errors":        dict(group="app",      w=0.6, floor=1,   hard=None, warn=None, label="API errors",      unit=""),
 "app_crashes":       dict(group="app",      w=0.8, floor=0.5, hard=None, warn=None, label="Application crashes", unit=""),
 "db_query_time":     dict(group="db",       w=0.6, floor=5,   hard=None, warn=500,  label="DB query time",   unit="ms"),
 "db_connections":    dict(group="db",       w=0.4, floor=3,   hard=None, warn=None, label="DB connections",  unit=""),
 "deadlocks":         dict(group="db",       w=0.7, floor=0.5, hard=None, warn=None, label="DB deadlocks",    unit=""),
}

# cause -> effect. Used to build the root-cause chain from which metrics deviated and in what order.
EDGES = [("iface_errors", "packet_loss"), ("packet_loss", "latency"), ("bandwidth", "latency"),
         ("latency", "auth_failures"), ("latency", "api_response_time"), ("latency", "db_query_time"),
         ("auth_failures", "cpu"), ("suspicious_activity", "auth_failures"),
         ("deadlocks", "db_query_time"), ("db_connections", "db_query_time"),
         ("db_query_time", "api_response_time"), ("cpu", "api_response_time"), ("mem", "cpu"),
         ("api_errors", "api_response_time"), ("app_crashes", "api_errors")]

CATEGORY = {"iface_errors": "network", "packet_loss": "network", "latency": "network", "bandwidth": "traffic",
            "cpu": "resource", "mem": "resource", "disk": "disk", "auth_failures": "credential",
            "suspicious_activity": "credential", "db_query_time": "database", "db_connections": "database",
            "deadlocks": "database", "api_errors": "app_fault", "app_crashes": "app_fault",
            "api_response_time": "app_fault"}
CATEGORY_TITLE = {"network": "Network degradation", "resource": "Resource saturation",
                  "disk": "Disk pressure", "credential": "Credential attack", "database": "Database contention",
                  "app_fault": "Application fault", "traffic": "Traffic surge"}
CATEGORY_CAUSE = {"network": "network congestion or link degradation", "resource": "resource saturation on the host",
                  "disk": "disk filling up", "credential": "a brute-force or credential attack",
                  "database": "database contention", "app_fault": "an application fault",
                  "traffic": "a traffic surge"}

# category -> [(action_id, text, remediable?)]
PLAYBOOK = {
 "network":    [("investigate_route", "Investigate the network route / upstream link at {t}", False),
                ("failover_link", "Fail traffic over from {t} to the backup link", True)],
 "resource":   [("investigate_process", "Find the top resource-consuming process on {t}", False),
                ("restart_service", "Restart the affected service on {t} (after draining traffic)", True)],
 "disk":       [("free_space", "Free space or expand the volume on {t}", False)],
 "credential": [("block_source", "Rate-limit / temporarily block the attacking source against {t}", True),
                ("review_auth", "Review the authentication service on {t}", False)],
 "database":   [("review_queries", "Inspect blocking queries and the connection pool on {t}", False),
                ("reset_pool", "Reset the DB connection pool on {t}", True)],
 "app_fault":  [("restart_service", "Restart the application service on {t}", True),
                ("review_deploy", "Review recent deployments for {t}", False)],
 "traffic":    [("rate_limit", "Apply rate limiting / QoS on {t}", True)],
}
# Remediation policy: only these actions may ever be proposed, always with approval + rollback.
ALLOWED_ACTIONS = {
 "failover_link":   {"risk": "medium", "rollback": "Switch traffic back to the primary link"},
 "restart_service": {"risk": "medium", "rollback": "Restore the previous service state / replica count"},
 "block_source":    {"risk": "low",    "rollback": "Remove the block rule"},
 "reset_pool":      {"risk": "low",    "rollback": "Restore the previous pool size"},
 "rate_limit":      {"risk": "low",    "rollback": "Remove the rate limit"},
}

# Demo keys. In production these come from a secrets store; role decides what a key may do.
API_KEYS = {"collector-key-A": ("tenantA", "collector"), "dash-key-A": ("tenantA", "dashboard"),
            "collector-key-B": ("tenantB", "collector"), "dash-key-B": ("tenantB", "dashboard")}
TENANT_REGION = {"tenantA": "in", "tenantB": "eu"}          # data residency
THIS_REGION = os.getenv("THIRDEYE_REGION")                  # None = accept all (dev)
