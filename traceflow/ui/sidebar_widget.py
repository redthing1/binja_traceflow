# main tabbed sidebar widget

from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
)
from PySide6.QtWidgets import QVBoxLayout, QTabWidget
from PySide6.QtGui import QImage, QPainter
from PySide6.QtCore import Qt

from .control_panel import ControlPanel
from .trace_view import TraceView
from .stats_view import StatsView


class TraceflowSidebarWidget(SidebarWidget):
    """main sidebar widget with tabbed interface"""

    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)

        self.frame = frame

        # create tab widget
        self.tabs = QTabWidget()

        # create individual panels
        self.control_panel = ControlPanel(frame)
        self.trace_view = TraceView(frame)
        self.stats_view = StatsView(frame)

        # connect signals to refresh other panels
        self.control_panel.trace_changed.connect(self.on_trace_changed)
        self.trace_view.trace_changed.connect(self.on_trace_changed)

        # add tabs
        self.tabs.addTab(self.control_panel, "Controls")
        self.tabs.addTab(self.trace_view, "Trace")
        self.tabs.addTab(self.stats_view, "Stats")

        # set up layout
        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def notifyViewChanged(self, view_frame):
        """handle view changes - update all panels"""
        if view_frame is None:
            return

        # get the binary view from the new frame
        bv = view_frame.getCurrentBinaryView()
        if bv is None:
            return

        # update all panels with new view
        self.control_panel.update_controls(bv)
        self.trace_view.update_trace_view(bv)
        self.stats_view.update_stats(bv)

    def refresh_all_panels(self):
        """refresh all panels for current view"""
        if self.frame is None:
            return

        bv = self.frame.getCurrentBinaryView()
        if bv is None:
            return

        self.control_panel.update_controls(bv)
        self.trace_view.update_trace_view(bv)
        self.stats_view.update_stats(bv)

    def on_trace_changed(self):
        """handle trace navigation changes"""
        # refresh control panel and stats view when position changes
        if self.frame is None:
            return

        bv = self.frame.getCurrentBinaryView()
        if bv is None:
            return

        # identify sender to avoid refreshing the panel that sent the signal
        sender = self.sender()

        if sender != self.control_panel:
            self.control_panel.update_controls(bv)
        if sender != self.trace_view:
            self.trace_view.update_trace_view(bv)

        # always refresh stats
        self.stats_view.update_stats(bv)


class TraceflowSidebarWidgetType(SidebarWidgetType):
    """widget type for registering with binary ninja"""

    name = "Traceflow"

    def __init__(self):
        # create simple placeholder icon (56x56)
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(0x80808080)  # gray background

        # draw simple "T" for traceflow
        painter = QPainter(icon)
        painter.setPen(0xFFFFFFFF)  # white text

        # set larger font for better visibility
        font = painter.font()
        font.setPointSize(32)
        font.setBold(True)
        painter.setFont(font)

        painter.drawText(icon.rect(), Qt.AlignCenter, "T")
        painter.end()

        SidebarWidgetType.__init__(self, icon, TraceflowSidebarWidgetType.name)

    def createWidget(self, frame, data):
        """create widget instance for given context"""
        return TraceflowSidebarWidget(TraceflowSidebarWidgetType.name, frame, data)

    def defaultLocation(self):
        """default location in sidebar"""
        return SidebarWidgetLocation.LeftContent

    def contextSensitivity(self):
        """use single instance that manages view changes"""
        return SidebarContextSensitivity.SelfManagedSidebarContext
