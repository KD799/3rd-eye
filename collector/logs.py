"""Simulated raw log source (stays local) and local failed-login analysis."""
import random
from collections import deque

from policy import redact


class LogSimulator:
    def __init__(self, secret_tick=10, burst=(20, 35), seed=7, host="app-x"):
        self.secret_tick = secret_tick
        self.burst = burst
        self.host = host
        self.rng = random.Random(seed)

    def read(self, tick):
        lines = [f"INFO  {self.host} request ok path=/health latency_ms={self.rng.randint(5, 40)}"]
        if tick == self.secret_tick:
            lines.append(
                "ERROR config load failed api_key=sk_live_9aF3kQ77xZ token=CANARY-SECRET-7f3a9 "
                "user=ravi@acme.com"
            )
        if self.burst[0] <= tick <= self.burst[1]:
            for _ in range(self.rng.randint(4, 7)):
                lines.append(
                    f"WARN  Failed login for user=admin@acme.com "
                    f"from 10.2.4.{self.rng.randint(2, 9)} "
                    f"password=Winter@{self.rng.randint(100, 999)}"
                )
        return lines


class AuthAnalyzer:
    def __init__(self, window=10, high=15, med=6):
        self.win = deque(maxlen=window)
        self.high = high
        self.med = med

    def update(self, lines):
        self.win.append(sum("Failed login" in line for line in lines))
        total = sum(self.win)
        risk = "high" if total >= self.high else "medium" if total >= self.med else "low"
        return total, risk


def local_view(lines):
    return [(line, *redact(line)) for line in lines]
