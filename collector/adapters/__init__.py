import json

from .base import Adapter, Record
from .simulator import SimulatorAdapter
from .psutil_local import PsutilAdapter

ADAPTERS = {
    "simulator": SimulatorAdapter,
    "psutil_local": PsutilAdapter,
}


def build(name, **kwargs):
    return ADAPTERS[name](**kwargs)


def load_faults(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)
