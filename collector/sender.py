"""Sends approved payloads to the SaaS API or mock SaaS."""
import json
import os

import requests


class Sender:
    def __init__(self, url="mock", api_key="collector-key-A", mock_file="mock_saas_received.txt"):
        self.url = url
        self.api_key = api_key
        self.mock_file = mock_file

    def send(self, payload) -> bool:
        if self.url == "mock":
            if os.path.exists("OUTAGE"):
                return False
            with open(self.mock_file, "a", encoding="utf-8") as file:
                file.write(payload["payload_id"] + "\n")
            return True
        try:
            response = requests.post(
                self.url,
                json=payload,
                timeout=3,
                headers={"X-API-Key": self.api_key},
            )
            if response.status_code in (400, 422):
                with open("dead_letter.jsonl", "a", encoding="utf-8") as file:
                    file.write(json.dumps({
                        "payload_id": payload.get("payload_id"),
                        "status": response.status_code,
                    }) + "\n")
                return True
            return response.status_code in (200, 201, 409)
        except requests.RequestException:
            return False
