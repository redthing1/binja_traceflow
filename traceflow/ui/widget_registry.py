# global registry of sidebar widgets indexed by binaryview

from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView
    from .sidebar_widget import TraceflowSidebarWidget

# global registry to map binaryview -> sidebar widget instance
_widget_registry: Dict["BinaryView", "TraceflowSidebarWidget"] = {}


def register_widget(bv: "BinaryView", widget: "TraceflowSidebarWidget") -> None:
    """register a sidebar widget for a binary view"""
    _widget_registry[bv] = widget


def unregister_widget(bv: "BinaryView") -> None:
    """unregister a sidebar widget for a binary view"""
    if bv in _widget_registry:
        del _widget_registry[bv]


def get_widget(bv: "BinaryView") -> Optional["TraceflowSidebarWidget"]:
    """get the sidebar widget for a binary view"""
    return _widget_registry.get(bv)


def clear_registry() -> None:
    """clear all widget registrations (for cleanup)"""
    _widget_registry.clear()
