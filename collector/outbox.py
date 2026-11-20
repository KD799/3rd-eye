"""Durable local queue. A payload is deleted only after SaaS acknowledges it."""
import json
import random
import sqlite3
import time


class Outbox:
    def __init__(self, path="outbox.db"):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS outbox(
                payload_id TEXT PRIMARY KEY,
                body TEXT NOT NULL,
                created REAL,
                attempts INTEGER DEFAULT 0,
                next_attempt REAL DEFAULT 0
            )
        """)
        self.db.commit()

    def enqueue(self, payload):
        self.db.execute(
            "INSERT OR IGNORE INTO outbox(payload_id, body, created) VALUES (?, ?, ?)",
            (payload["payload_id"], json.dumps(payload, sort_keys=True), time.time()),
        )
        self.db.commit()

    def due(self, limit=50):
        rows = self.db.execute(
            "SELECT payload_id, body, attempts FROM outbox "
            "WHERE next_attempt<=? ORDER BY payload_id LIMIT ?",
            (time.time(), limit),
        ).fetchall()
        return [(payload_id, json.loads(body), attempts) for payload_id, body, attempts in rows]

    def ack(self, payload_id):
        self.db.execute("DELETE FROM outbox WHERE payload_id=?", (payload_id,))
        self.db.commit()

    def fail(self, payload_id, attempts, base=1.0, cap=30.0):
        delay = min(cap, base * 2 ** attempts) * random.uniform(0.8, 1.2)
        self.db.execute(
            "UPDATE outbox SET attempts=?, next_attempt=? WHERE payload_id=?",
            (attempts + 1, time.time() + delay, payload_id),
        )
        self.db.commit()

    def backlog(self):
        return self.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
