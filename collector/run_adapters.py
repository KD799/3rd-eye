"""Quick check: python run_adapters.py"""
import time
from adapters import build, load_faults

print("== psutil_local (REAL data from this machine) ==")
real = build("psutil_local")
for _ in range(3):
    time.sleep(1)
    for r in real.read():
        print(r.to_dict())

print("\n== simulator (first 2 ticks, then tick 90 during the fault) ==")
sim = build("simulator", faults=load_faults("faults.json"))
for tick in range(95):
    recs = sim.read()
    if tick in (0, 1, 90):
        print(f"-- tick {tick}")
        for r in recs:
            print(r.to_dict())
