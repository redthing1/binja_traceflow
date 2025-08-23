# trace entry list view

from PySide6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QListWidgetItem
from PySide6.QtCore import Qt, Signal

from ..context import get_context
from ..constants import TRACE_VIEW_WINDOW_SIZE


class TraceView(QWidget):
    """list widget showing trace entries around current position"""

    # signal emitted when user clicks on trace entry
    trace_changed = Signal()

    def __init__(self, frame):
        QWidget.__init__(self)
        self.frame = frame

        # create list widget
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)

        # layout
        layout = QVBoxLayout()
        layout.addWidget(self.list_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        # track current binary view for updates
        self.current_bv = None

    def update_frame(self, frame):
        """update frame reference when context changes"""
        self.frame = frame

    def update_trace_view(self, bv):
        """refresh trace view for given binary view"""
        self.current_bv = bv
        self.list_widget.clear()

        if bv is None:
            return

        ctx = get_context(bv)
        if ctx.tracedb.is_empty():
            item = QListWidgetItem("No trace loaded")
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.list_widget.addItem(item)
            return

        # get current position and show ±10 entries around it
        current_pos = ctx.cursor.current_position
        total_entries = ctx.tracedb.get_total_entries()

        # if not started, show beginning of trace
        if current_pos < 0:
            current_pos = 0

        # calculate range to show
        start_pos = max(0, current_pos - TRACE_VIEW_WINDOW_SIZE)
        end_pos = min(total_entries, current_pos + TRACE_VIEW_WINDOW_SIZE + 1)

        # populate list with entries in range
        for i in range(start_pos, end_pos):
            entry = ctx.tracedb.get_entry(i)
            if entry:
                # format: "[index] 0xADDRESS (thread N)"
                thread_info = (
                    f" (thread {entry.thread_id})" if entry.thread_id != 0 else ""
                )
                text = f"[{i}] 0x{entry.address:x}{thread_info}"

                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, i)  # store index for clicking

                # highlight current entry (only if cursor is actually positioned)
                if (
                    i == ctx.cursor.current_position
                    and ctx.cursor.current_position >= 0
                ):
                    item.setBackground(
                        item.listWidget().palette().highlight()
                        if item.listWidget()
                        else Qt.blue
                    )
                    item.setForeground(Qt.white)

                self.list_widget.addItem(item)

        # scroll to show current item
        self.sync_to_position(bv)

    def sync_to_position(self, bv):
        """highlight and scroll to current position"""
        if bv is None or bv != self.current_bv:
            return

        ctx = get_context(bv)
        current_pos = ctx.cursor.current_position

        # only highlight if cursor is positioned
        if current_pos < 0:
            return

        # find and select the current item
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            item_pos = item.data(Qt.UserRole)

            if item_pos == current_pos:
                # clear previous selection
                self.list_widget.clearSelection()
                # select and scroll to current item
                item.setSelected(True)
                self.list_widget.scrollToItem(item, QListWidget.PositionAtCenter)
                break

    def on_item_clicked(self, item):
        """handle click on trace entry - jump to that position"""
        if self.current_bv is None:
            return

        # get the trace index from the item
        trace_index = item.data(Qt.UserRole)
        if trace_index is None:
            return

        # jump to that position
        ctx = get_context(self.current_bv)
        ctx.cursor.set_position(trace_index)
        ctx.update_highlight()
        ctx.navigate_to_current()

        # refresh the view to update highlighting
        self.update_trace_view(self.current_bv)

        # emit signal to update other panels
        self.trace_changed.emit()
