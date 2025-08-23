# per-binaryview context management

from typing import Dict, Optional
from enum import Enum
from binaryninja import BinaryView
from .tracedb import TraceDB
from .trace_cursor import TraceCursor
from .painter import TracePainter
from .log import log_info, log_error
from .constants import PLUGIN_KEY
from .settings import my_settings


class ExecutionState(Enum):
    """execution state for trace replay"""
    NOT_LOADED = "not_loaded"
    STOPPED = "stopped"
    RUNNING = "running"


class TraceContext:
    """context for a single binary view"""

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.tracedb = TraceDB()
        self.cursor = TraceCursor(self.tracedb)
        self.execution_state: ExecutionState = ExecutionState.NOT_LOADED

        # get frontier size from settings
        frontier_size = my_settings.get_integer(f"{PLUGIN_KEY}.frontierSize", bv)
        if frontier_size is None:
            frontier_size = 8  # default fallback
        self.painter = TracePainter(frontier_size)

        # lazy initialization to avoid circular import
        self._navigator = None

    def clear(self):
        """clear all trace data and reset state"""
        # clear highlights first
        self.painter.clear_all(self.bv)

        # reset data structures
        self.tracedb.clear()
        self.cursor.reset()
        self.execution_state = ExecutionState.NOT_LOADED
        self._navigator = None  # reset navigator

    @property
    def navigator(self):
        """get navigator instance (lazy initialization)"""
        if self._navigator is None:
            from .navigator import TraceNavigator

            self._navigator = TraceNavigator(self)
        return self._navigator

    def set_execution_state(self, new_state: ExecutionState):
        """set execution state with proper highlight management"""
        old_state = self.execution_state
        
        # clear highlights when leaving stopped state (any transition away from stopped)
        if old_state == ExecutionState.STOPPED and new_state != ExecutionState.STOPPED:
            self.painter.clear_all(self.bv)
            log_info(self.bv, f"cleared highlights on state transition: {old_state.value} -> {new_state.value}")
        
        self.execution_state = new_state
        
        # paint highlights when entering stopped state
        if new_state == ExecutionState.STOPPED and not self.tracedb.is_empty():
            self.painter.paint_frontier(self.bv, self.cursor)
            log_info(self.bv, f"painted frontier on state transition: {old_state.value} -> {new_state.value}")

    def update_highlight(self):
        """update frontier highlighting for current position"""
        if self.execution_state == ExecutionState.STOPPED and not self.tracedb.is_empty():
            self.painter.paint_frontier(self.bv, self.cursor)

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
