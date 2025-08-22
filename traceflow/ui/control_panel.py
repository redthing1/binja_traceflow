# debugger-like control panel

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QToolBar,
    QToolButton,
    QLabel,
    QHBoxLayout,
)
from PySide6.QtGui import QAction, QIcon
from PySide6.QtCore import Qt, Signal
from binaryninja.interaction import get_open_filename_input

from ..context import get_context
from ..import_task import TraceImportTask


class ControlPanel(QWidget):
    """control panel with debugger-like buttons and position display"""

    # signal emitted when trace navigation changes
    trace_changed = Signal()

    def __init__(self, frame):
        QWidget.__init__(self)
        self.frame = frame

        # create toolbar
        self.toolbar = QToolBar()
        self.toolbar.setStyleSheet("QToolBar{spacing:2px;}")
        max_height = 24

        # run to start button
        self.btn_run = QToolButton()
        self.btn_run.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_run.setMaximumHeight(max_height)
        self.btn_run.setToolTip("Go to start")
        action_run = QAction("Run", self)
        action_run.triggered.connect(self.on_run)
        action_run.setIcon(self._create_text_icon("⏮"))
        self.btn_run.setDefaultAction(action_run)
        self.toolbar.addWidget(self.btn_run)

        # play to end button
        self.btn_play = QToolButton()
        self.btn_play.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_play.setMaximumHeight(max_height)
        self.btn_play.setToolTip("Go to end")
        action_play = QAction("Play", self)
        action_play.triggered.connect(self.on_play)
        action_play.setIcon(self._create_text_icon("⏭"))
        self.btn_play.setDefaultAction(action_play)
        self.toolbar.addWidget(self.btn_play)

        # step forward button
        self.btn_step_forward = QToolButton()
        self.btn_step_forward.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_forward.setMaximumHeight(max_height)
        self.btn_step_forward.setToolTip("Step forward")
        action_step_forward = QAction("Step Forward", self)
        action_step_forward.triggered.connect(self.on_step_forward)
        action_step_forward.setIcon(self._create_text_icon("⏩"))
        self.btn_step_forward.setDefaultAction(action_step_forward)
        self.toolbar.addWidget(self.btn_step_forward)

        # step backward button
        self.btn_step_backward = QToolButton()
        self.btn_step_backward.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_backward.setMaximumHeight(max_height)
        self.btn_step_backward.setToolTip("Step backward")
        action_step_backward = QAction("Step Backward", self)
        action_step_backward.triggered.connect(self.on_step_backward)
        action_step_backward.setIcon(self._create_text_icon("⏪"))
        self.btn_step_backward.setDefaultAction(action_step_backward)
        self.toolbar.addWidget(self.btn_step_backward)

        # separator
        self.toolbar.addSeparator()

        # step in button (placeholder)
        self.btn_step_in = QToolButton()
        self.btn_step_in.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_in.setMaximumHeight(max_height)
        self.btn_step_in.setToolTip("Step in (placeholder)")
        action_step_in = QAction("Step In", self)
        action_step_in.triggered.connect(self.on_step_in)
        action_step_in.setIcon(self._create_text_icon("↓"))
        self.btn_step_in.setDefaultAction(action_step_in)
        self.toolbar.addWidget(self.btn_step_in)

        # step over button (placeholder)
        self.btn_step_over = QToolButton()
        self.btn_step_over.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_over.setMaximumHeight(max_height)
        self.btn_step_over.setToolTip("Step over (placeholder)")
        action_step_over = QAction("Step Over", self)
        action_step_over.triggered.connect(self.on_step_over)
        action_step_over.setIcon(self._create_text_icon("→"))
        self.btn_step_over.setDefaultAction(action_step_over)
        self.toolbar.addWidget(self.btn_step_over)

        # step out button (placeholder)
        self.btn_step_out = QToolButton()
        self.btn_step_out.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_out.setMaximumHeight(max_height)
        self.btn_step_out.setToolTip("Step out (placeholder)")
        action_step_out = QAction("Step Out", self)
        action_step_out.triggered.connect(self.on_step_out)
        action_step_out.setIcon(self._create_text_icon("↑"))
        self.btn_step_out.setDefaultAction(action_step_out)
        self.toolbar.addWidget(self.btn_step_out)

        # step back button (placeholder)
        self.btn_step_back = QToolButton()
        self.btn_step_back.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_back.setMaximumHeight(max_height)
        self.btn_step_back.setToolTip("Step back (placeholder)")
        action_step_back = QAction("Step Back", self)
        action_step_back.triggered.connect(self.on_step_back)
        action_step_back.setIcon(self._create_text_icon("←"))
        self.btn_step_back.setDefaultAction(action_step_back)
        self.toolbar.addWidget(self.btn_step_back)

        # separator
        self.toolbar.addSeparator()

        # load trace button
        self.btn_load = QToolButton()
        self.btn_load.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_load.setMaximumHeight(max_height)
        self.btn_load.setToolTip("Load trace file")
        action_load = QAction("Load Trace", self)
        action_load.triggered.connect(self.on_load_trace)
        action_load.setIcon(self._create_text_icon("📁"))
        self.btn_load.setDefaultAction(action_load)
        self.toolbar.addWidget(self.btn_load)

        # clear trace button
        self.btn_clear = QToolButton()
        self.btn_clear.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_clear.setMaximumHeight(max_height)
        self.btn_clear.setToolTip("Clear trace")
        action_clear = QAction("Clear Trace", self)
        action_clear.triggered.connect(self.on_clear_trace)
        action_clear.setIcon(self._create_text_icon("🗑"))
        self.btn_clear.setDefaultAction(action_clear)
        self.toolbar.addWidget(self.btn_clear)

        # position display
        self.position_label = QLabel("No trace loaded - use Traceflow → Import Trace")
        self.position_label.setAlignment(Qt.AlignCenter)
        self.position_label.setStyleSheet(
            "padding: 4px; border: 1px solid gray; color: gray;"
        )

        # layout
        layout = QVBoxLayout()
        layout.addWidget(self.toolbar)
        layout.addWidget(self.position_label)
        layout.setSpacing(4)
        layout.setContentsMargins(2, 2, 2, 2)
        self.setLayout(layout)

        # disable buttons initially
        self._set_buttons_enabled(False)

    def _create_text_icon(self, text):
        """create simple text-based icon"""
        # for now, just return empty icon - real icons would be created with QPainter
        return QIcon()

    def _set_buttons_enabled(self, enabled):
        """enable/disable control buttons based on trace state"""
        self.btn_run.setEnabled(enabled)
        self.btn_play.setEnabled(enabled)
        self.btn_step_forward.setEnabled(enabled)
        self.btn_step_backward.setEnabled(enabled)
        self.btn_step_in.setEnabled(False)  # placeholder buttons always disabled
        self.btn_step_over.setEnabled(False)
        self.btn_step_out.setEnabled(False)
        self.btn_step_back.setEnabled(False)
        self.btn_clear.setEnabled(enabled)

    def update_controls(self, bv):
        """update control state based on binary view"""
        if bv is None:
            self._set_buttons_enabled(False)
            self.position_label.setText("No active view")
            self.position_label.setStyleSheet(
                "padding: 4px; border: 1px solid gray; color: gray;"
            )
            return

        ctx = get_context(bv)
        has_trace = not ctx.tracedb.is_empty()

        if has_trace:
            self._set_buttons_enabled(True)
            current_pos = ctx.cursor.current_position
            total_entries = ctx.tracedb.get_total_entries()
            if current_pos >= 0:
                self.position_label.setText(
                    f"Position: {current_pos + 1}/{total_entries}"
                )
            else:
                self.position_label.setText(f"Position: not started/{total_entries}")
            # use normal text color when trace is loaded
            self.position_label.setStyleSheet("padding: 4px; border: 1px solid gray;")
        else:
            self._set_buttons_enabled(False)
            self.position_label.setText("No trace loaded. Use Traceflow → Import Trace")
            # use gray text color when no trace
            self.position_label.setStyleSheet(
                "padding: 4px; border: 1px solid gray; color: gray;"
            )

    # button callback methods
    def on_run(self):
        """go to start of trace"""
        bv = self.frame.getCurrentBinaryView()
        if bv:
            ctx = get_context(bv)
            ctx.cursor.go_to_start()
            ctx.update_highlight()
            ctx.navigate_to_current()
            self.update_controls(bv)
            self.trace_changed.emit()

    def on_play(self):
        """go to end of trace"""
        bv = self.frame.getCurrentBinaryView()
        if bv:
            ctx = get_context(bv)
            ctx.cursor.go_to_end()
            ctx.update_highlight()
            ctx.navigate_to_current()
            self.update_controls(bv)
            self.trace_changed.emit()

    def on_step_forward(self):
        """step forward one instruction"""
        bv = self.frame.getCurrentBinaryView()
        if bv:
            ctx = get_context(bv)
            ctx.cursor.step_forward()
            ctx.update_highlight()
            ctx.navigate_to_current()
            self.update_controls(bv)
            self.trace_changed.emit()

    def on_step_backward(self):
        """step backward one instruction"""
        bv = self.frame.getCurrentBinaryView()
        if bv:
            ctx = get_context(bv)
            ctx.cursor.step_backward()
            ctx.update_highlight()
            ctx.navigate_to_current()
            self.update_controls(bv)
            self.trace_changed.emit()

    def on_step_in(self):
        """placeholder: step in functionality"""
        pass

    def on_step_over(self):
        """placeholder: step over functionality"""
        pass

    def on_step_out(self):
        """placeholder: step out functionality"""
        pass

    def on_step_back(self):
        """placeholder: step back functionality"""
        pass

    def on_load_trace(self):
        """load trace file via file dialog"""
        filename = get_open_filename_input("Load Trace File", "*.trace *.txt *.log")
        if filename:
            bv = self.frame.getCurrentBinaryView()
            if bv:
                # start import task
                task = TraceImportTask(bv, filename)
                task.start()

    def on_clear_trace(self):
        """clear current trace"""
        bv = self.frame.getCurrentBinaryView()
        if bv:
            ctx = get_context(bv)
            ctx.clear()
            self.update_controls(bv)
            self.trace_changed.emit()
