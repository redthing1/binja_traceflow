# trace painting and highlighting with frontier effect

from typing import Set, List, Optional, Tuple
from binaryninja import BinaryView
from binaryninja.highlight import HighlightColor, HighlightStandardColor
from .trace_cursor import TraceCursor
from .tracedb import TraceEntry


class TracePainter:
    """manages highlighting with frontier effect showing past/present/future"""

    def __init__(self, frontier_size: int = 8):
        self.frontier_size = frontier_size
        self.highlighted_addresses: Set[int] = set()

    def paint_frontier(self, bv: BinaryView, cursor: TraceCursor):
        """paint the frontier effect around current position"""
        # debug logging
        from .log import log_info

        current_entry = cursor.get_current_entry()
        log_info(
            bv,
            f"painting frontier for position {cursor.current_position}, address {hex(current_entry.address) if current_entry else 'None'}",
        )

        # clear all existing highlights
        self.clear_all(bv)

        # get current entry
        if not current_entry:
            log_info(bv, "no current entry to paint")
            return

        # paint current as bright magenta
        self._highlight_address(
            bv,
            current_entry.address,
            HighlightColor(red=255, green=0, blue=255, alpha=255),
        )

        # get and paint past entries (red gradient with alpha)
        past_entries = self._get_past_entries(cursor, self.frontier_size)
        for i, entry in enumerate(past_entries):
            rgb_intensity, alpha = self._calculate_fade(
                i, len(past_entries), 200, 80, 200, 50
            )
            self._highlight_address(
                bv,
                entry.address,
                HighlightColor(red=rgb_intensity, green=0, blue=0, alpha=alpha),
            )

        # get and paint future entries (blue gradient with alpha)
        future_entries = self._get_future_entries(cursor, self.frontier_size)
        for i, entry in enumerate(future_entries):
            rgb_intensity, alpha = self._calculate_fade(
                i, len(future_entries), 200, 80, 200, 50
            )
            self._highlight_address(
                bv,
                entry.address,
                HighlightColor(red=0, green=0, blue=rgb_intensity, alpha=alpha),
            )

    def clear_all(self, bv: BinaryView):
        """clear all current highlights"""
        from .log import log_info, log_warn

        log_info(bv, f"clearing {len(self.highlighted_addresses)} highlights")
        cleared = 0
        failed = []

        for addr in self.highlighted_addresses:
            # get fresh function objects for this address
            funcs = bv.get_functions_containing(addr)
            for func in funcs:
                try:
                    func.set_auto_instr_highlight(
                        addr, HighlightStandardColor.NoHighlightColor
                    )
                    cleared += 1
                except Exception as e:
                    failed.append((addr, str(e)))

        if failed:
            log_warn(bv, f"failed to clear {len(failed)} highlights: {failed[:3]}")

        log_info(
            bv,
            f"successfully cleared {cleared} highlights from {len(self.highlighted_addresses)} addresses",
        )
        self.highlighted_addresses.clear()

    def _highlight_address(self, bv: BinaryView, address: int, color: HighlightColor):
        """highlight address in all functions containing it"""
        from .log import log_info, log_warn

        funcs = bv.get_functions_containing(address)
        log_info(bv, f"highlighting address {hex(address)} in {len(funcs)} functions")

        highlighted_in_any = False
        for func in funcs:
            try:
                func.set_auto_instr_highlight(address, color)
                highlighted_in_any = True
                log_info(bv, f"highlighted {hex(address)} in function {func.name}")
            except Exception as e:
                log_warn(bv, f"failed to highlight {hex(address)} in {func.name}: {e}")

        if highlighted_in_any:
            self.highlighted_addresses.add(address)

    def _get_past_entries(self, cursor: TraceCursor, count: int) -> List[TraceEntry]:
        """get entries before current position"""
        entries = []
        pos = cursor.current_position - 1

        while len(entries) < count and pos >= 0:
            entry = cursor.tracedb.get_entry(pos)
            if entry:
                entries.append(entry)
            pos -= 1

        return entries

    def _get_future_entries(self, cursor: TraceCursor, count: int) -> List[TraceEntry]:
        """get entries after current position"""
        entries = []
        pos = cursor.current_position + 1
        total = cursor.tracedb.get_total_entries()

        while len(entries) < count and pos < total:
            entry = cursor.tracedb.get_entry(pos)
            if entry:
                entries.append(entry)
            pos += 1

        return entries

    def _calculate_fade(
        self,
        index: int,
        total: int,
        rgb_start: int,
        rgb_end: int,
        alpha_start: int,
        alpha_end: int,
    ) -> Tuple[int, int]:
        """calculate rgb and alpha values for gradient fade"""
        if total <= 1:
            return rgb_start, alpha_start

        # linear interpolation for both rgb and alpha
        ratio = index / (total - 1)
        rgb_value = int(rgb_start + (rgb_end - rgb_start) * ratio)
        alpha_value = int(alpha_start + (alpha_end - alpha_start) * ratio)

        # clamp values
        rgb_value = max(0, min(255, rgb_value))
        alpha_value = max(0, min(255, alpha_value))

        return rgb_value, alpha_value
