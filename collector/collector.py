"""Collector pipeline: adapters -> local analysis -> policy -> outbox -> sender."""
import argparse
import time

import psutil

from adapters import build, load_faults
from adapters.base import Record, utc_iso
from egress_log import EgressLog
from logs import AuthAnalyzer, LogSimulator, local_view
from outbox import Outbox
from policy import PolicyViolation, build_payload
from sender import Sender

VERSION = "0.1.0"
TENANT = "tenantA"
COLLECTOR = "collector-01"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ticks", type=int, default=60)
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--url", default="mock")
    args = parser.parse_args()

    simulator = build(
        "simulator",
        faults=load_faults("faults.json"),
        start_epoch=time.time(),
        tick_s=max(1, int(args.interval)),
    )
    log_source = LogSimulator()
    auth = AuthAnalyzer()
    outbox = Outbox()
    egress = EgressLog()
    sender = Sender(args.url)
    started = time.time()

    open("local_raw.log", "w", encoding="utf-8").close()

    for tick in range(args.ticks):
        records = [record.to_dict() for record in simulator.read()]
        now = utc_iso(time.time())

        lines = log_source.read(tick)
        with open("local_raw.log", "a", encoding="utf-8") as file:
            displayed_secret = False
            for raw, redacted, actions in local_view(lines):
                file.write(raw + "\n")
                if actions and not displayed_secret:
                    displayed_secret = True
                    print(
                        f"[LOCAL t={tick}] RAW     : {raw}\n"
                        f"[LOCAL t={tick}] REDACTED: {redacted} ({', '.join(actions)})"
                    )

        total, risk = auth.update(lines)
        records.append(
            Record("app-x", "auth_failures", float(total), now, "Asia/Kolkata").to_dict()
        )
        events = []
        if risk != "low":
            events.append({
                "event_category": "auth_failure_burst",
                "severity": risk,
                "count": total,
                "risk": risk,
                "source_id": "app-x",
                "ts_utc": now,
                "raw_sample": lines[-1],
            })

        health = {
            "cpu_pct": psutil.cpu_percent(),
            "mem_pct": psutil.virtual_memory().percent,
            "uptime_s": int(time.time() - started),
            "config_status": "ok",
        }

        try:
            payload, report = build_payload(
                TENANT, COLLECTOR, VERSION, now, records, events, health
            )
            egress.write(
                "approved",
                payload["payload_id"],
                payload,
                {
                    "bytes": report["bytes"],
                    "dropped_fields": report["dropped_fields"][:5],
                },
            )
            outbox.enqueue(payload)
        except PolicyViolation as error:
            egress.write("BLOCKED", "n/a", None, {"reason": str(error)})
            print(f"[BLOCKED t={tick}] {error}")

        for payload_id, body, attempts in outbox.due():
            if sender.send(body):
                outbox.ack(payload_id)
                egress.write("delivered", payload_id)
            else:
                outbox.fail(payload_id, attempts, base=args.interval)

        if tick % 10 == 0:
            print(
                f"[t={tick:3d}] backlog={outbox.backlog()} "
                f"risk={risk} auth_window={total}"
            )
        time.sleep(args.interval)

    for _ in range(40):
        if outbox.backlog() == 0:
            break
        time.sleep(args.interval * 2)
        for payload_id, body, attempts in outbox.due():
            if sender.send(body):
                outbox.ack(payload_id)
                egress.write("delivered", payload_id)
            else:
                outbox.fail(payload_id, attempts, base=args.interval)

    valid, bad_line = EgressLog.verify()
    print(
        f"\nDone. backlog={outbox.backlog()} "
        f"egress log chain valid={valid}"
        f"{' (line ' + str(bad_line) + ')' if bad_line else ''}"
    )


if __name__ == "__main__":
    main()
