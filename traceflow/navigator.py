# navigation logic for trace stepping operations

from .context import TraceContext
from .log import log_info, log_error, log_warn


class TraceNavigator:
    """handles all stepping operations for trace navigation"""

    def __init__(self, context: TraceContext):
        self.context = context

    def run(self) -> bool:
        """go to beginning of trace"""
        if self.context.tracedb.is_empty():
            log_warn(self.context.bv, "cannot run: no trace loaded")
            return False

        self.context.execution_state = "running"

        # use cursor method to go to start
        success = self.context.cursor.go_to_start()
        if success:
            self.context.execution_state = "stopped"
            self.update_ui()
            log_info(self.context.bv, "moved to beginning of trace")
        else:
            self.context.execution_state = "stopped"
            log_error(self.context.bv, "failed to move to beginning of trace")

        return success

    def play(self) -> bool:
        """go to end of trace"""
        if self.context.tracedb.is_empty():
            log_warn(self.context.bv, "cannot play: no trace loaded")
            return False

        self.context.execution_state = "running"

        # use cursor method to go to end
        success = self.context.cursor.go_to_end()
        if success:
            self.context.execution_state = "at_end"
            self.update_ui()
            log_info(self.context.bv, "moved to end of trace")
        else:
            self.context.execution_state = "stopped"
            log_error(self.context.bv, "failed to move to end of trace")

        return success

    def step_forward(self) -> bool:
        """move to next instruction"""
        if not self.can_step_forward():
            log_warn(self.context.bv, "cannot step forward: at end of trace")
            return False

        self.context.execution_state = "running"

        # if not started, go to beginning first
        if not self.context.cursor.is_started():
            success = self.context.cursor.go_to_start()
        else:
            # use cursor method to step forward
            success = self.context.cursor.step_forward()

        if success:
            # check if we reached the end
            if self.is_at_end():
                self.context.execution_state = "at_end"
            else:
                self.context.execution_state = "stopped"
            self.update_ui()
        else:
            self.context.execution_state = "stopped"
            log_error(self.context.bv, "failed to step forward")

        return success

    def step_backward(self) -> bool:
        """move to previous instruction"""
        if not self.can_step_backward():
            log_warn(self.context.bv, "cannot step backward: at beginning of trace")
            return False

        self.context.execution_state = "running"

        # use cursor method to step backward
        success = self.context.cursor.step_backward()
        if success:
            self.context.execution_state = "stopped"
            self.update_ui()
        else:
            self.context.execution_state = "stopped"
            log_error(self.context.bv, "failed to step backward")

        return success

    def step_in(self) -> bool:
        """follow call into function (placeholder: just step_forward for now)"""
        return self.step_forward()

    def step_over(self) -> bool:
        """skip over call (placeholder: just step_forward for now)"""
        return self.step_forward()

    def step_out(self) -> bool:
        """continue until function return (placeholder: just step_forward for now)"""
        return self.step_forward()

    def step_back(self) -> bool:
        """reverse of step_in (placeholder: just step_backward for now)"""
        return self.step_backward()

    def update_ui(self):
        """update highlights and navigate binary view"""
        # update instruction highlight for current position
        self.context.update_highlight()
        # sync binary view to current position
        self.context.navigate_to_current()

    def can_step_forward(self) -> bool:
        """check if forward step is possible"""
        if self.context.tracedb.is_empty():
            return False
        # if not started, we can always step forward to position 0
        if not self.context.cursor.is_started():
            return True
        # otherwise check if we're not at the end
        return not self.is_at_end()

    def can_step_backward(self) -> bool:
        """check if backward step is possible"""
        if self.context.tracedb.is_empty():
            return False
        # must be started and not at beginning
        return self.context.cursor.is_started() and not self.is_at_start()

    def is_at_start(self) -> bool:
        """check if at beginning of trace"""
        return self.context.cursor.is_at_start()

    def is_at_end(self) -> bool:
        """check if at end of trace"""
        return self.context.cursor.is_at_end()
