# ui registration

from binaryninjaui import Sidebar
from .sidebar_widget import TraceflowSidebarWidgetType

# register the sidebar widget type
Sidebar.addSidebarWidgetType(TraceflowSidebarWidgetType())
