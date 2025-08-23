import os
from binaryninja import BackgroundTaskThread
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

from .context import get_context, ExecutionState
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

            # phase 3: final setup and initial navigation
            self.progress = f"Trace imported: {total_entries:,} entries loaded"

            # go to first instruction and set up initial state
            ctx.cursor.go_to_start()
            ctx.set_execution_state(ExecutionState.STOPPED)

            # debug logging
            current_addr = ctx.cursor.get_current_address()
            log_info(
                self.bv,
                f"initial position set to address: {hex(current_addr) if current_addr else 'None'}",
            )

            ctx.update_highlight()
            ctx.navigate_to_current()

            # log success message with statistics
            msg = f"loaded trace: {total_entries:,} entries with {unique_addresses:,} unique addresses"
            if parsed_tracedb.get_thread_count() > 1:
                msg += f" ({parsed_tracedb.get_thread_count()} threads)"
            log_info(self.bv, msg)

            # show completion dialog if enabled
            try:
                if my_settings.get_bool("traceflow.showCompletionDialog", True):
                    show_message_box(
                        "Import Complete",
                        f"Trace file imported successfully.\n\n{total_entries:,} entries loaded.\n\nUse the Traceflow sidebar to navigate the trace.",
                        MessageBoxButtonSet.OKButtonSet,
                        MessageBoxIcon.InformationIcon,
                    )
            except (AttributeError, TypeError):
                # ignore settings/dialog errors, not critical for functionality
                pass

            log_info(self.bv, f"trace import complete: {self.filepath}")

            # notify ui that trace import is complete
            self._notify_ui_refresh()

            # mark task as finished
            self.finish()

        except Exception as e:
            self.error = str(e)
            log_error(self.bv, f"trace import failed: {e}")
            self._show_error_dialog()
            self.cancel()

    def _notify_ui_refresh(self):
        """notify ui to refresh after import completes"""
        try:
            from .ui.widget_registry import get_widget
            from .log import log_info

            widget = get_widget(self.bv)
            if widget:
                # emit signal on main thread to refresh ui
                from PySide6.QtCore import QMetaObject, Qt

                log_info(self.bv, "notifying ui to refresh after trace import")
                QMetaObject.invokeMethod(
                    widget, "on_trace_imported", Qt.QueuedConnection
                )
            else:
                log_info(self.bv, "warning: no widget found in registry for ui refresh")
        except Exception as e:
            # ui refresh failure is not critical - log but don't crash
            from .log import log_warn

            log_warn(self.bv, f"failed to refresh ui after import: {e}")

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
