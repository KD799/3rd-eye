# Third Eye

## Project structure

```text
third-eye/
├── collector/
│   ├── collector.py
│   ├── faults.json
│   ├── run_adapters.py
│   └── adapters/
│       ├── __init__.py
│       ├── base.py
│       ├── psutil_local.py
│       └── simulator.py
├── saas/
│   ├── api.py
│   └── ai_engine.py
├── simulator/
│   └── simulate.py
├── dashboard/
└── README.md
```

## Run the collector adapters

```powershell
pip install psutil
cd collector
python run_adapters.py
```

## Run the collector pipeline

```powershell
python collector.py --ticks 60 --interval 0.2
python reconcile.py
```
