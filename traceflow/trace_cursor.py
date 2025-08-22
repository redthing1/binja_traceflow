# trace cursor for managing navigation state

from typing import Optional
from .tracedb import TraceDB, TraceEntry


class TraceCursor:
    """manages position and navigation state for a trace"""

    def __init__(self, tracedb: TraceDB):
        self.tracedb = tracedb
        self.current_position: int = -1  # current position in trace (-1 = not started)

    def get_current_entry(self) -> Optional[TraceEntry]:
        """get entry at current position"""
        return self.tracedb.get_entry(self.current_position)

    def get_current_address(self) -> Optional[int]:
        """get address at current position"""
        entry = self.get_current_entry()
        return entry.address if entry else None

    def get_context(self, context_size: int = 10) -> list[TraceEntry]:
        """get entries around current position"""
        if self.current_position < 0:
            return []
        return self.tracedb.get_context(self.current_position, context_size)

    # navigation methods
    def set_position(self, position: int) -> bool:
        """set current position in trace"""
        if 0 <= position < self.tracedb.get_total_entries():
            self.current_position = position
            return True
        return False

    def step_forward(self) -> bool:
        """move to next instruction in trace"""
        if self.current_position < self.tracedb.get_total_entries() - 1:
            self.current_position += 1
            return True
        return False

    def step_backward(self) -> bool:
        """move to previous instruction in trace"""
        if self.current_position > 0:
            self.current_position -= 1
            return True
        return False

    def go_to_start(self) -> bool:
        """go to beginning of trace"""
        if not self.tracedb.is_empty():
            self.current_position = 0
            return True
        return False

    def go_to_end(self) -> bool:
        """go to end of trace"""
        if not self.tracedb.is_empty():
            self.current_position = self.tracedb.get_total_entries() - 1
            return True
        return False

    def is_at_start(self) -> bool:
        """check if at beginning of trace"""
        return self.current_position == 0

    def is_at_end(self) -> bool:
        """check if at end of trace"""
        return self.current_position == self.tracedb.get_total_entries() - 1

    def is_started(self) -> bool:
        """check if cursor has been positioned"""
        return self.current_position >= 0

    def get_position_info(self) -> str:
        """get formatted position info string"""
        if self.current_position < 0:
            return "not started"
        return f"{self.current_position + 1}/{self.tracedb.get_total_entries()}"

    def reset(self):
        """reset cursor to initial state"""
        self.current_position = -1
