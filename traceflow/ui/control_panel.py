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
from .icon_loader import load_icon, create_fallback_icon
from ..import_task import TraceImportTask
from ..constants import get_file_dialog_filter


class ControlPanel(QWidget):
    """control panel with debugger-like buttons and position display"""

    # signal emitted when trace navigation changes
    trace_changed = Signal()

    def __init__(self, frame):
        QWidget.__init__(self)
        self.frame = frame

        # create toolbar
        self.toolbar = QToolBar()
        self.toolbar.setStyleSheet("QToolBar{spacing:2px; border:none;}")
        max_height = 20

        # run to start button
        self.btn_run = QToolButton()
        self.btn_run.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_run.setMaximumHeight(max_height)
        self.btn_run.setToolTip("Go to start")
        action_run = QAction("Run", self)
        action_run.triggered.connect(self.on_run)
        action_run.setIcon(self._create_icon("rotate-ccw", "|<<"))
        self.btn_run.setDefaultAction(action_run)
        self.toolbar.addWidget(self.btn_run)

        # play forward button
        self.btn_play_forward = QToolButton()
        self.btn_play_forward.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_play_forward.setMaximumHeight(max_height)
        self.btn_play_forward.setToolTip("Play forward to end")
        action_play_forward = QAction("Play Forward", self)
        action_play_forward.triggered.connect(self.on_play_forward)
        action_play_forward.setIcon(self._create_icon("play", "|>>"))
        self.btn_play_forward.setDefaultAction(action_play_forward)
        self.toolbar.addWidget(self.btn_play_forward)

        # pause button
        self.btn_pause = QToolButton()
        self.btn_pause.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_pause.setMaximumHeight(max_height)
        self.btn_pause.setToolTip("Pause execution")
        action_pause = QAction("Pause", self)
        action_pause.triggered.connect(self.on_pause)
        action_pause.setIcon(self._create_icon("pause", "||"))
        self.btn_pause.setDefaultAction(action_pause)
        self.toolbar.addWidget(self.btn_pause)

        # step in button (same as step forward)
        self.btn_step_in = QToolButton()
        self.btn_step_in.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_in.setMaximumHeight(max_height)
        self.btn_step_in.setToolTip("Step in")
        action_step_in = QAction("Step In", self)
        action_step_in.triggered.connect(self.on_step_in)
        action_step_in.setIcon(self._create_icon("arrow-down-to-dot", "↓"))
        self.btn_step_in.setDefaultAction(action_step_in)
        self.toolbar.addWidget(self.btn_step_in)

        # step over button
        self.btn_step_over = QToolButton()
        self.btn_step_over.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_over.setMaximumHeight(max_height)
        self.btn_step_over.setToolTip("Step over call")
        action_step_over = QAction("Step Over", self)
        action_step_over.triggered.connect(self.on_step_over)
        action_step_over.setIcon(self._create_icon("redo-dot", "→"))
        self.btn_step_over.setDefaultAction(action_step_over)
        self.toolbar.addWidget(self.btn_step_over)

        # step out button
        self.btn_step_out = QToolButton()
        self.btn_step_out.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_out.setMaximumHeight(max_height)
        self.btn_step_out.setToolTip("Step out of function")
        action_step_out = QAction("Step Out", self)
        action_step_out.triggered.connect(self.on_step_out)
        action_step_out.setIcon(self._create_icon("arrow-up-from-dot", "↑"))
        self.btn_step_out.setDefaultAction(action_step_out)
        self.toolbar.addWidget(self.btn_step_out)

        # step back button
        self.btn_step_back = QToolButton()
        self.btn_step_back.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_step_back.setMaximumHeight(max_height)
        self.btn_step_back.setToolTip("Step back")
        action_step_back = QAction("Step Back", self)
        action_step_back.triggered.connect(self.on_step_back)
        action_step_back.setIcon(self._create_icon("undo-dot", "←"))
        self.btn_step_back.setDefaultAction(action_step_back)
        self.toolbar.addWidget(self.btn_step_back)

        # play backward button
        self.btn_play_backward = QToolButton()
        self.btn_play_backward.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_play_backward.setMaximumHeight(max_height)
        self.btn_play_backward.setToolTip("Play backward to start")
        action_play_backward = QAction("Play Backward", self)
        action_play_backward.triggered.connect(self.on_play_backward)
        action_play_backward.setIcon(self._create_icon("play-back", "<<|"))
        self.btn_play_backward.setDefaultAction(action_play_backward)
        self.toolbar.addWidget(self.btn_play_backward)

        # separator
        self.toolbar.addSeparator()

        # load trace button
        self.btn_load = QToolButton()
        self.btn_load.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_load.setMaximumHeight(max_height)
        self.btn_load.setToolTip("Load trace file")
        action_load = QAction("Load Trace", self)
        action_load.triggered.connect(self.on_load_trace)
        action_load.setIcon(self._create_icon("folder-open", "📁"))
        self.btn_load.setDefaultAction(action_load)
        self.toolbar.addWidget(self.btn_load)

        # clear trace button
        self.btn_clear = QToolButton()
        self.btn_clear.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.btn_clear.setMaximumHeight(max_height)
        self.btn_clear.setToolTip("Clear trace")
        action_clear = QAction("Clear Trace", self)
        action_clear.triggered.connect(self.on_clear_trace)
        action_clear.setIcon(self._create_icon("trash-2", "🗑"))
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

    def update_frame(self, frame):
        """update frame reference when context changes"""
        self.frame = frame

    def _get_binary_view(self):
        """safely get current binary view"""
        if self.frame is None:
            return None
        return self.frame.getCurrentBinaryView()

    def _create_icon(self, icon_name: str, fallback_text: str = "") -> QIcon:
        """create icon from svg file with fallback"""
        icon = load_icon(icon_name, size=24)
        if icon is not None:
            return icon
        return create_fallback_icon(fallback_text, size=24)

    def _set_buttons_enabled(self, enabled):
        """enable/disable control buttons based on trace state"""
        self.btn_run.setEnabled(enabled)
        self.btn_play_forward.setEnabled(enabled)
        self.btn_pause.setEnabled(enabled)
        self.btn_step_in.setEnabled(enabled)
        self.btn_step_over.setEnabled(enabled)
        self.btn_step_out.setEnabled(enabled)
        self.btn_step_back.setEnabled(enabled)
        self.btn_play_backward.setEnabled(enabled)
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
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.run()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot run: no trace loaded or already at start")
        else:
            from ..log import log_warn

            log_warn(None, "cannot run: no binary file is currently open")

    def on_play_forward(self):
        """play forward to end"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.play_forward()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot play forward: no trace loaded")
        else:
            from ..log import log_warn

            log_warn(None, "cannot play forward: no binary file is currently open")

    def on_pause(self):
        """pause execution (currently just a placeholder)"""
        bv = self._get_binary_view()
        if bv:
            # for now, pause is just informational since we don't have async execution
            from ..log import log_info

            log_info(bv, "pause requested (execution is already synchronous)")
        else:
            from ..log import log_warn

            log_warn(None, "cannot pause: no binary file is currently open")

    def on_play_backward(self):
        """play backward to start"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.play_backward()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot play backward: no trace loaded")
        else:
            from ..log import log_warn

            log_warn(None, "cannot play backward: no binary file is currently open")

    def on_step_forward(self):
        """step forward one instruction"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_forward()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step forward: no trace loaded or at end")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step forward: no binary file is currently open")

    def on_step_backward(self):
        """step backward one instruction"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_backward()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step backward: no trace loaded or at start")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step backward: no binary file is currently open")

    def on_step_in(self):
        """step in (same as step forward)"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_in()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step in: at end of trace")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step in: no binary file is currently open")

    def on_step_over(self):
        """step over call"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_over()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step over: at end of trace or error occurred")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step over: no binary file is currently open")

    def on_step_out(self):
        """step out of function"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_out()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step out: not in function or at end of trace")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step out: no binary file is currently open")

    def on_step_back(self):
        """step back (same as step backward)"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            success = ctx.navigator.step_back()
            if success:
                self.update_controls(bv)
                self.trace_changed.emit()
            else:
                from ..log import log_warn

                log_warn(bv, "cannot step back: at start of trace")
        else:
            from ..log import log_warn

            log_warn(None, "cannot step back: no binary file is currently open")

    def on_load_trace(self):
        """load trace file via file dialog"""
        filename = get_open_filename_input("Load Trace File", get_file_dialog_filter())
        if filename:
            bv = self._get_binary_view()
            if bv:
                # start import task
                task = TraceImportTask(bv, filename)
                task.start()
            else:
                from binaryninja.interaction import show_message_box
                from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

                show_message_box(
                    "No Binary View",
                    "Cannot load trace: no binary file is currently open.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon,
                )

    def on_clear_trace(self):
        """clear current trace"""
        bv = self._get_binary_view()
        if bv:
            ctx = get_context(bv)
            ctx.clear()
            self.update_controls(bv)
            self.trace_changed.emit()
        else:
            from ..log import log_warn

            log_warn(None, "cannot clear trace: no binary file is currently open")
