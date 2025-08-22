from dataclasses import dataclass

from .constants import PLUGIN_KEY

@dataclass
class TraceFlowContext:
    """per-binaryview plugin state"""

    pass


def get_context(bv) -> TraceFlowContext:
    """get or create context for binaryview"""

    if PLUGIN_KEY not in bv.session_data:
        ctx = TraceFlowContext()
        bv.session_data[PLUGIN_KEY] = ctx
    return bv.session_data[PLUGIN_KEY]
