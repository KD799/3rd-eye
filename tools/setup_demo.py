"""Set tenant aliases and topology in the live SaaS."""
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "collector"))

from policy import pseudonymize


url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
ids = {name: pseudonymize(name) for name in ("switch-a", "app-x", "db-1", "site-mumbai")}
body = {
    "topology": {
        ids["app-x"]: ids["switch-a"],
        ids["db-1"]: ids["switch-a"],
        ids["switch-a"]: ids["site-mumbai"],
    },
    "aliases": {
        ids["switch-a"]: "Switch-A",
        ids["app-x"]: "App-X",
        ids["db-1"]: "DB-1",
        ids["site-mumbai"]: "Site-Mumbai",
    },
}

response = requests.put(
    url + "/v1/config",
    json=body,
    headers={"X-API-Key": "dash-key-A"},
    timeout=5,
)
response.raise_for_status()
print(response.json())
