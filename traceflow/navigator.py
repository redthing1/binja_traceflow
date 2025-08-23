# navigation logic for trace stepping operations

from typing import Optional, Set
from binaryninja.enums import LowLevelILOperation
from .context import TraceContext, ExecutionState
from .log import log_info, log_error, log_warn

try:
    from binaryninja.debugger import DebuggerController

    DEBUGGER_AVAILABLE = True
except ImportError:
    DEBUGGER_AVAILABLE = False


class TraceNavigator:
    """handles all stepping operations for trace navigation"""

    def __init__(self, context: TraceContext):
        self.context = context
        self._breakpoint_addresses: Set[int] = set()
        self._dbg_controller: Optional[DebuggerController] = None

    def _init_debugger(self):
        """initialize debugger controller if not already done"""
        if self._dbg_controller is None and DEBUGGER_AVAILABLE:
            try:
                self._dbg_controller = DebuggerController(self.context.bv)
            except Exception:
                # debugger may not be available or accessible
                pass

    def _refresh_breakpoints(self):
        """refresh breakpoint set from debugger controller"""
        self._init_debugger()
        if self._dbg_controller:
            try:
                self._breakpoint_addresses = {
                    bp.address for bp in self._dbg_controller.breakpoints
                }
            except Exception:
                # breakpoints may not be accessible
                self._breakpoint_addresses = set()
        else:
            self._breakpoint_addresses = set()

    def _check_breakpoint(self, address: int) -> bool:
        """check if address has a breakpoint"""
        return address in self._breakpoint_addresses

    def run(self) -> bool:
        """go to beginning of trace"""
        if self.context.tracedb.is_empty():
            log_warn(self.context.bv, "cannot run: no trace loaded")
            return False

        self.context.set_execution_state(ExecutionState.RUNNING)

        # go to start
        success = self.context.cursor.go_to_start()
        if success:
            self.context.set_execution_state(ExecutionState.STOPPED)
            self.update_ui()
            log_info(self.context.bv, "moved to beginning of trace")
        else:
            self.context.set_execution_state(ExecutionState.STOPPED)
            log_error(self.context.bv, "failed to move to beginning of trace")

        return success

    def play(self) -> bool:
        """play forward to end OR backward to start based on current position"""
        if self.context.tracedb.is_empty():
            log_warn(self.context.bv, "cannot play: no trace loaded")
            return False

        # determine direction based on current position
        if self.context.cursor.is_at_end():
            return self.play_backward()  # at end, play backward
        else:
            return self.play_forward()  # otherwise play forward

    def play_forward(self) -> bool:
        """fast forward to end without highlighting until stopped"""
        self.context.set_execution_state(ExecutionState.RUNNING)

        # refresh breakpoints before tight loop
        self._refresh_breakpoints()

        # if not started, go to beginning first
        if not self.context.cursor.is_started():
            if not self.context.cursor.go_to_start():
                self.context.set_execution_state(ExecutionState.STOPPED)
                return False

        # fast execution without painting
        while not self.context.cursor.is_at_end():
            if not self.context.cursor.step_forward():
                break

            # check for breakpoint at current address
            current_addr = self.context.cursor.get_current_address()
            if current_addr and self._check_breakpoint(current_addr):
                self.context.set_execution_state(ExecutionState.STOPPED)
                self.update_ui()
                log_info(self.context.bv, f"stopped at breakpoint: {hex(current_addr)}")
                return True

        # stop and paint final position
        self.context.set_execution_state(ExecutionState.STOPPED)
        self.update_ui()
        log_info(self.context.bv, "played forward to end of trace")
        return True

    def play_backward(self) -> bool:
        """rewind to start without highlighting until stopped"""
        self.context.set_execution_state(ExecutionState.RUNNING)

        # refresh breakpoints before tight loop
        self._refresh_breakpoints()

        # fast execution without painting
        while not self.context.cursor.is_at_start():
            if not self.context.cursor.step_backward():
                break

            # check for breakpoint at current address
            current_addr = self.context.cursor.get_current_address()
            if current_addr and self._check_breakpoint(current_addr):
                self.context.set_execution_state(ExecutionState.STOPPED)
                self.update_ui()
                log_info(self.context.bv, f"stopped at breakpoint: {hex(current_addr)}")
                return True

        # stop and paint final position
        self.context.set_execution_state(ExecutionState.STOPPED)
        self.update_ui()
        log_info(self.context.bv, "played backward to start of trace")
        return True

    def step_forward(self) -> bool:
        """move to next instruction"""
        if not self.can_step_forward():
            log_warn(self.context.bv, "cannot step forward: at end of trace")
            return False

        self.context.set_execution_state(ExecutionState.RUNNING)

        # if not started, go to beginning first
        if not self.context.cursor.is_started():
            success = self.context.cursor.go_to_start()
        else:
            success = self.context.cursor.step_forward()

        if success:
            self.context.set_execution_state(ExecutionState.STOPPED)
            self.update_ui()
        else:
            self.context.set_execution_state(ExecutionState.STOPPED)
            log_error(self.context.bv, "failed to step forward")

        return success

    def step_backward(self) -> bool:
        """move to previous instruction"""
        if not self.can_step_backward():
            log_warn(self.context.bv, "cannot step backward: at beginning of trace")
            return False

        self.context.set_execution_state(ExecutionState.RUNNING)

        success = self.context.cursor.step_backward()
        if success:
            self.context.set_execution_state(ExecutionState.STOPPED)
            self.update_ui()
        else:
            self.context.set_execution_state(ExecutionState.STOPPED)
            log_error(self.context.bv, "failed to step backward")

        return success

    def _is_call_instruction(self, address: int) -> bool:
        """check if instruction at address is a call"""
        funcs = self.context.bv.get_functions_containing(address)

        for func in funcs:
            try:
                llil = func.get_llil_at(address)
                if llil and llil.operation == LowLevelILOperation.LLIL_CALL:
                    return True
            except (AttributeError, RuntimeError):
                # function may not have llil or address not valid
                continue
        return False

    def _get_current_function(self):
        """get function containing current address"""
        current_addr = self.context.cursor.get_current_address()
        if not current_addr:
            return None

        funcs = self.context.bv.get_functions_containing(current_addr)
        return funcs[0] if funcs else None

    def step_in(self) -> bool:
        """step in (same as step forward for trace replay)"""
        return self.step_forward()

    def step_over(self) -> bool:
        """step over call - if at call, continue until after it returns"""
        if not self.can_step_forward():
            log_warn(self.context.bv, "cannot step over: at end of trace")
            return False

        current_addr = self.context.cursor.get_current_address()
        if not current_addr:
            return self.step_forward()

        # check if current instruction is a call
        if not self._is_call_instruction(current_addr):
            # not a call, just step forward
            return self.step_forward()

        # it's a call - step forward once to enter the call
        self.context.set_execution_state(ExecutionState.RUNNING)

        # refresh breakpoints before tight loop
        self._refresh_breakpoints()

        if not self.context.cursor.step_forward():
            self.context.set_execution_state(ExecutionState.STOPPED)
            return False

        # get the function we just entered
        called_func = self._get_current_function()
        if not called_func:
            # couldn't determine function, just stop here
            self.context.set_execution_state(ExecutionState.STOPPED)
            self.update_ui()
            log_info(self.context.bv, "stepped over call (function not identified)")
            return True

        # continue until we exit this function
        while not self.context.cursor.is_at_end():
            if not self.context.cursor.step_forward():
                break

            # check for breakpoint at current address
            current_addr = self.context.cursor.get_current_address()
            if current_addr and self._check_breakpoint(current_addr):
                self.context.set_execution_state(ExecutionState.STOPPED)
                self.update_ui()
                log_info(
                    self.context.bv,
                    f"stopped at breakpoint during step over: {hex(current_addr)}",
                )
                return True

            current_func = self._get_current_function()
            if current_func != called_func:
                # we've exited the called function
                break

        self.context.set_execution_state(ExecutionState.STOPPED)
        self.update_ui()
        log_info(
            self.context.bv,
            f"stepped over call to {called_func.name if called_func else 'unknown'}",
        )
        return True

    def step_out(self) -> bool:
        """continue until we exit current function"""
        if not self.can_step_forward():
            log_warn(self.context.bv, "cannot step out: at end of trace")
            return False

        # get current function
        current_func = self._get_current_function()
        if not current_func:
            # no function context, just step forward
            log_warn(self.context.bv, "cannot step out: not in a function")
            return self.step_forward()

        self.context.set_execution_state(ExecutionState.RUNNING)

        # refresh breakpoints before tight loop
        self._refresh_breakpoints()

        # continue until we exit this function
        while not self.context.cursor.is_at_end():
            if not self.context.cursor.step_forward():
                break

            # check for breakpoint at current address
            current_addr = self.context.cursor.get_current_address()
            if current_addr and self._check_breakpoint(current_addr):
                self.context.set_execution_state(ExecutionState.STOPPED)
                self.update_ui()
                log_info(
                    self.context.bv,
                    f"stopped at breakpoint during step out: {hex(current_addr)}",
                )
                return True

            new_func = self._get_current_function()
            if new_func != current_func:
                # we've exited the function
                break

        self.context.set_execution_state(ExecutionState.STOPPED)
        self.update_ui()
        log_info(self.context.bv, f"stepped out of {current_func.name}")
        return True

    def step_back(self) -> bool:
        """reverse of step_in (placeholder: just step_backward for now)"""
        return self.step_backward()

    def update_ui(self):
        """navigate binary view to current position"""
        # painting is now handled by state transitions in set_execution_state()
        # only navigation is needed here
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
