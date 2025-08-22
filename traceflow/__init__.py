# plugin package

from binaryninja import PluginCommand
from .settings import my_settings

# import ui module to register sidebar widget
from . import ui

# import plugin module and register menu commands
from .plugin import (
    import_trace_command,
    clear_trace_command,
    is_valid_for_import,
    is_valid_for_clear,
)

# register menu commands
PluginCommand.register(
    "Traceflow\\Import Trace",
    "Import execution trace file",
    import_trace_command,
    is_valid_for_import,
)

PluginCommand.register(
    "Traceflow\\Clear Trace",
    "Clear current trace",
    clear_trace_command,
    is_valid_for_clear,
)
