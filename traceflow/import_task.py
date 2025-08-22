import os
from binaryninja import BackgroundTaskThread
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

from .context import get_context
from .parsers import detect_and_parse
from .settings import my_settings
from .log import log_info, log_error
from .trace_cursor import TraceCursor


class TraceImportTask(BackgroundTaskThread):
    """background task for importing trace files"""

    def __init__(self, bv, filepath):
        super().__init__("Importing trace...", can_cancel=True)
        self.bv = bv
        self.filepath = filepath
        self.error = None

    def run(self):
        """run the import task"""

        try:
            # phase 1: parse trace file
            filename = os.path.basename(self.filepath)
            self.progress = f"Parsing {filename}..."
            if self.cancelled:
                return

            parsed_tracedb = detect_and_parse(self.bv, self.filepath)
            if self.cancelled:
                return

            # get initial stats
            total_entries = parsed_tracedb.get_total_entries()
            unique_addresses = parsed_tracedb.get_unique_address_count()
            self.progress = f"Parsed {total_entries:,} entries with {unique_addresses:,} unique addresses"

            # phase 2: load into context
            self.progress = "Loading into context..."
            ctx = get_context(self.bv)

            # clear any existing trace data
            ctx.clear()

            # copy parsed trace data
            ctx.tracedb = parsed_tracedb

            # recreate cursor
            ctx.cursor = TraceCursor(ctx.tracedb)

            if self.cancelled:
                ctx.clear()  # rollback on cancel
                return

            # phase 3: final setup
            self.progress = f"Trace imported: {total_entries:,} entries loaded"

            # log success message with stats if enabled in settings
            try:
                if my_settings.get_bool("traceflow.showStatsInLog", False):
                    msg = f"loaded trace: {total_entries:,} entries with {unique_addresses:,} unique addresses"
                    if parsed_tracedb.get_thread_count() > 1:
                        msg += f" ({parsed_tracedb.get_thread_count()} threads)"
                    log_info(self.bv, msg)
            except:
                # ignore settings errors, not critical
                pass

            # show completion dialog if enabled
            try:
                if my_settings.get_bool("traceflow.showCompletionDialog", True):
                    show_message_box(
                        "Import Complete",
                        f"Trace file imported successfully.\n\n{total_entries:,} entries loaded.\n\nUse the Traceflow sidebar to navigate the trace.",
                        MessageBoxButtonSet.OKButtonSet,
                        MessageBoxIcon.InformationIcon,
                    )
            except:
                # ignore settings errors, not critical
                pass

            log_info(self.bv, f"trace import complete: {self.filepath}")

            # mark task as finished
            self.finish()

        except Exception as e:
            self.error = str(e)
            log_error(self.bv, f"trace import failed: {e}")
            self._show_error_dialog()
            self.cancel()

    def _show_error_dialog(self):
        """show user-friendly error dialog"""
        error_lower = self.error.lower()

        if "no such file" in error_lower or "file not found" in error_lower:
            # file not found error
            title = "File Not Found"
            icon = MessageBoxIcon.ErrorIcon
            show_message_box(
                title,
                f"Trace Import Failed\n\nThe specified file could not be found:\n{self.filepath}",
                MessageBoxButtonSet.OKButtonSet,
                icon,
            )
        elif "no parser found" in error_lower:
            # unsupported file format
            title = "Unsupported File Format"
            icon = MessageBoxIcon.ErrorIcon
            show_message_box(
                title,
                f"Trace Import Failed\n\nNo parser found for this file format.",
                MessageBoxButtonSet.OKButtonSet,
                icon,
            )
        elif "permission" in error_lower or "access" in error_lower:
            # permission error
            title = "Access Denied"
            icon = MessageBoxIcon.ErrorIcon
            show_message_box(
                title,
                f"Trace Import Failed\n\nPermission denied accessing file:\n{self.filepath}",
                MessageBoxButtonSet.OKButtonSet,
                icon,
            )
        else:
            # generic error
            show_message_box(
                "Trace Import Error",
                f"Failed to import trace: {self.error}",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )
