# simple statistics view

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtCore import Qt

from ..context import get_context


class StatsView(QWidget):
    """simple statistics display using labels"""

    def __init__(self, frame):
        QWidget.__init__(self)
        self.frame = frame

        # create stats labels
        self.total_instructions_label = QLabel("Total instructions: 0")
        self.unique_addresses_label = QLabel("Unique addresses: 0")
        self.current_position_label = QLabel("Current position: 0/0")
        self.thread_count_label = QLabel("")

        # set label styling
        label_style = "padding: 4px; border-bottom: 1px solid gray;"
        self.total_instructions_label.setStyleSheet(label_style)
        self.unique_addresses_label.setStyleSheet(label_style)
        self.current_position_label.setStyleSheet(label_style)
        self.thread_count_label.setStyleSheet(label_style)

        # layout
        layout = QVBoxLayout()
        layout.addWidget(self.total_instructions_label)
        layout.addWidget(self.unique_addresses_label)
        layout.addWidget(self.current_position_label)
        layout.addWidget(self.thread_count_label)
        layout.addStretch()  # push everything to top
        layout.setSpacing(2)
        layout.setContentsMargins(4, 4, 4, 4)
        self.setLayout(layout)

    def update_frame(self, frame):
        """update frame reference when context changes"""
        self.frame = frame

    def update_stats(self, bv):
        """refresh statistics for given binary view"""
        if bv is None:
            self._clear_stats()
            return

        ctx = get_context(bv)

        if ctx.tracedb.is_empty():
            self._clear_stats()
            return

        # get statistics from trace database
        total_entries = ctx.tracedb.get_total_entries()
        unique_addresses = ctx.tracedb.get_unique_address_count()
        current_pos = (
            ctx.cursor.current_position + 1 if ctx.cursor.current_position >= 0 else 0
        )  # 1-based for display
        thread_count = ctx.tracedb.get_thread_count()

        # update labels
        self.total_instructions_label.setText(f"Total instructions: {total_entries:,}")
        self.unique_addresses_label.setText(f"Unique addresses: {unique_addresses:,}")
        self.current_position_label.setText(
            f"Current position: {current_pos:,}/{total_entries:,}"
        )

        # show thread count only if more than 1 thread
        if thread_count > 1:
            self.thread_count_label.setText(f"Thread count: {thread_count}")
            self.thread_count_label.show()
        else:
            self.thread_count_label.hide()

    def _clear_stats(self):
        """clear all statistics when no trace is loaded"""
        self.total_instructions_label.setText("Total instructions: -")
        self.unique_addresses_label.setText("Unique addresses: -")
        self.current_position_label.setText("Current position: -")
        self.thread_count_label.hide()
