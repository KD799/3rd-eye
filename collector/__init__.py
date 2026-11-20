from .base import Adapter, Record
from .simulator import SimulatorAdapter, load_faults
from .psutil_local import PsutilAdapter

ADAPTERS = {"simulator": SimulatorAdapter, "psutil_local": PsutilAdapter}


def build(name, **kwargs):
    """Create an adapter from config, e.g. build('simulator', faults=[...])."""
    return ADAPTERS[name](**kwargs)
