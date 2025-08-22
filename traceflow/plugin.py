# main plugin logic and menu command handlers

import time
from binaryninja import BinaryView
from binaryninja.interaction import get_open_filename_input
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

from .import_task import TraceImportTask
from .context import clear_context, has_trace
from .log import log_info, log_error


def import_trace_command(bv: BinaryView):
    """Import trace file command handler"""

    # get file path using file dialog
    file_extensions = "Trace Files (*.trace *.txt *.log *.jsonl);;All Files (*.*)"
    filepath = get_open_filename_input("Select trace file to import:", file_extensions)

    if not filepath:
        # user cancelled
        return

    log_info(bv, f"importing trace from: {filepath}")

    # create and start import task
    # the task handles its own completion logging and error/success dialogs
    task = TraceImportTask(bv, filepath)
    task.start()


def clear_trace_command(bv: BinaryView):
    """Clear current trace command handler"""

    # confirm with user
    result = show_message_box(
        "Clear Trace",
        "Are you sure you want to clear the current trace?\n\nThis action cannot be undone.",
        MessageBoxButtonSet.YesNoButtonSet,
        MessageBoxIcon.QuestionIcon,
    )

    if result == 1:  # Yes button
        start_time = time.time()

        # clear the trace context
        clear_context(bv)

        elapsed = time.time() - start_time
        log_info(bv, f"trace cleared (took {elapsed:.2f}s)")

        # show confirmation message
        show_message_box(
            "Trace Cleared",
            "The trace has been cleared successfully.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )


def is_valid_for_import(bv: BinaryView) -> bool:
    """Check if import command is valid for this binary view"""
    # any binary view can have traces imported
    return True


def is_valid_for_clear(bv: BinaryView) -> bool:
    """Check if clear command is valid for this binary view"""
    # only valid if we have a trace loaded
    return has_trace(bv)
