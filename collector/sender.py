"""Sends approved payloads. Mock SaaS deduplicates delivery IDs in a local file."""
import os

import requests


class Sender:
    def __init__(self, url="mock", api_key="dev-key", mock_file="mock_saas_received.txt"):
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
                headers={"X-Collector-Key": self.api_key},
            )
            return response.status_code in (200, 201, 409)
        except requests.RequestException:
            return False
