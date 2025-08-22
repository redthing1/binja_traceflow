# per-binaryview context management

from typing import Dict, Optional
from binaryninja import BinaryView
from .tracedb import TraceDB
from .trace_cursor import TraceCursor
from .log import log_info, log_error
from .constants import PLUGIN_KEY


class TraceContext:
    """context for a single binary view"""

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.tracedb = TraceDB()
        self.cursor = TraceCursor(self.tracedb)
        self.execution_state = "stopped"  # stopped, running, at_end
        self.last_highlight = None  # last highlighted address

    def clear(self):
        """clear all trace data and reset state"""
        self.tracedb.clear()
        self.cursor.reset()
        self.execution_state = "stopped"
        if self.last_highlight:
            self.bv.clear_auto_instr_highlight(self.last_highlight)
            self.last_highlight = None

    def update_highlight(self):
        """update instruction highlight for current position"""
        # clear previous highlight
        if self.last_highlight:
            self.bv.clear_auto_instr_highlight(self.last_highlight)
            self.last_highlight = None

        # set new highlight if we have a current position
        address = self.cursor.get_current_address()
        if address:
            self.bv.set_auto_instr_highlight(address)
            self.last_highlight = address

    def navigate_to_current(self):
        """navigate binary view to current trace position"""
        address = self.cursor.get_current_address()
        if address:
            self.bv.navigate(self.bv.file.view, address)


def get_context(bv: BinaryView) -> TraceContext:
    """get or create context for binary view"""
    if PLUGIN_KEY not in bv.session_data:
        ctx = TraceContext(bv)
        bv.session_data[PLUGIN_KEY] = ctx
        log_info(bv, "created new trace context")
    return bv.session_data[PLUGIN_KEY]


def clear_context(bv: BinaryView):
    """clear context for binary view"""
    if PLUGIN_KEY in bv.session_data:
        ctx = bv.session_data[PLUGIN_KEY]
        ctx.clear()
        del bv.session_data[PLUGIN_KEY]
        log_info(bv, "cleared trace context")


def has_trace(bv: BinaryView) -> bool:
    """check if binary view has loaded trace"""
    if PLUGIN_KEY not in bv.session_data:
        return False
    ctx = bv.session_data[PLUGIN_KEY]
    return not ctx.tracedb.is_empty()
