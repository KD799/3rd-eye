"""Proof of reliability: approved IDs compared with IDs received by mock SaaS."""
import json
from collections import Counter


approved = []
with open("egress_log.jsonl", encoding="utf-8") as file:
    for line in file:
        entry = json.loads(line)
        if entry["kind"] == "approved":
            approved.append(entry["payload_id"])

received = Counter()
with open("mock_saas_received.txt", encoding="utf-8") as file:
    received.update(line.strip() for line in file if line.strip())

lost = [payload_id for payload_id in approved if payload_id not in received]
duplicates = {payload_id: count for payload_id, count in received.items() if count > 1}
print(
    f"approved={len(approved)} received_unique={len(received)} "
    f"LOST={len(lost)} DUPLICATES={len(duplicates)}"
)
