# trace database for storing execution traces

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class TraceEntry:
    """single entry in an execution trace"""

    address: int
    index: int  # position in trace
    thread_id: int = 0  # thread identifier
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )  # optional metadata (timestamp, etc)


class TraceDB:
    """database for storing execution traces (pure data, no state)"""

    def __init__(self):
        self.entries: List[TraceEntry] = []
        self.unique_addresses: set = set()

        # caches for faster lookups
        self._address_to_indices: Dict[int, List[int]] = (
            {}
        )  # address -> list of indices
        self._thread_entries: Dict[int, List[int]] = {}  # thread_id -> list of indices

    def add_entry(
        self,
        address: int,
        thread_id: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """add a new entry to the trace, returns the index"""
        index = len(self.entries)
        entry = TraceEntry(address, index, thread_id, metadata or {})
        self.entries.append(entry)

        # update unique addresses
        self.unique_addresses.add(address)

        # update address index
        if address not in self._address_to_indices:
            self._address_to_indices[address] = []
        self._address_to_indices[address].append(index)

        # update thread index
        if thread_id not in self._thread_entries:
            self._thread_entries[thread_id] = []
        self._thread_entries[thread_id].append(index)

        return index

    def get_entry(self, index: int) -> Optional[TraceEntry]:
        """get entry at specific index"""
        if 0 <= index < len(self.entries):
            return self.entries[index]
        return None

    def get_range(self, start: int, end: int) -> List[TraceEntry]:
        """get range of entries (inclusive)"""
        if start < 0:
            start = 0
        if end >= len(self.entries):
            end = len(self.entries) - 1
        if start > end:
            return []
        return self.entries[start : end + 1]

    def get_context(self, position: int, context_size: int = 10) -> List[TraceEntry]:
        """get entries around a position"""
        if position < 0 or position >= len(self.entries):
            return []

        start = max(0, position - context_size)
        end = min(len(self.entries) - 1, position + context_size)
        return self.entries[start : end + 1]

    def find_next_occurrence(self, address: int, start_from: int) -> Optional[int]:
        """find next occurrence of an address after given position"""
        if address not in self._address_to_indices:
            return None

        indices = self._address_to_indices[address]
        for idx in indices:
            if idx > start_from:
                return idx
        return None

    def find_prev_occurrence(self, address: int, start_from: int) -> Optional[int]:
        """find previous occurrence of an address before given position"""
        if address not in self._address_to_indices:
            return None

        indices = self._address_to_indices[address]
        for idx in reversed(indices):
            if idx < start_from:
                return idx
        return None

    def get_thread_entries(self, thread_id: int) -> List[int]:
        """get all entry indices for a specific thread"""
        return self._thread_entries.get(thread_id, [])

    def get_thread_ids(self) -> List[int]:
        """get all unique thread ids in trace"""
        return list(self._thread_entries.keys())

    # statistics
    def get_total_entries(self) -> int:
        """get total number of entries in trace"""
        return len(self.entries)

    def get_unique_address_count(self) -> int:
        """get number of unique addresses in trace"""
        return len(self.unique_addresses)

    def get_thread_count(self) -> int:
        """get number of unique threads in trace"""
        return len(self._thread_entries)

    def is_empty(self) -> bool:
        """check if trace is empty"""
        return len(self.entries) == 0

    def clear(self):
        """clear all trace data"""
        self.entries.clear()
        self.unique_addresses.clear()
        self._address_to_indices.clear()
        self._thread_entries.clear()
