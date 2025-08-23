# aslr address translation utility

import os
from typing import List, Optional, TYPE_CHECKING
from .module_info import ModuleInfo
from .log import log_info, log_warn, log_debug

if TYPE_CHECKING:
    from binaryninja import BinaryView


class AddressTranslator:
    """translates runtime aslr addresses to binaryview virtual addresses"""

    def __init__(self, bv: "BinaryView", runtime_modules: List[ModuleInfo]):
        self.bv = bv
        self.runtime_modules = runtime_modules
        self.target_module: Optional[ModuleInfo] = None
        self.bv_base: Optional[int] = None
        self.offset: Optional[int] = None

        self._find_target_module()
        self._calculate_translation_offset()

    def _find_target_module(self):
        """find module matching binaryview filename"""
        target_filename = os.path.basename(self.bv.file.original_filename)
        log_debug(self.bv, f"looking for module matching '{target_filename}'")

        # first pass: exact name matches
        for module in self.runtime_modules:
            if module.name == target_filename:
                self.target_module = module
                log_info(
                    self.bv,
                    f"found exact module match: {module.name} at runtime base 0x{module.runtime_base:x}",
                )
                return

        # second pass: partial matches
        for module in self.runtime_modules:
            if target_filename in module.name or module.name in target_filename:
                self.target_module = module
                log_info(
                    self.bv,
                    f"found partial module match: {module.name} at runtime base 0x{module.runtime_base:x}",
                )
                return

        # log available modules for debugging
        available = [f"{m.name} (0x{m.runtime_base:x})" for m in self.runtime_modules]
        log_warn(
            self.bv,
            f"no matching module found for '{target_filename}'. available: {', '.join(available)}",
        )

    def _calculate_translation_offset(self):
        """calculate offset between runtime base and binaryview base"""
        if not self.target_module:
            return

        # find binaryview base address from segments
        if not self.bv.segments:
            log_warn(self.bv, "no segments found in binaryview")
            return

        self.bv_base = min(seg.start for seg in self.bv.segments)

        # calculate translation offset
        self.offset = self.bv_base - self.target_module.runtime_base

        log_info(
            self.bv,
            f"translation setup: runtime_base=0x{self.target_module.runtime_base:x} -> bv_base=0x{self.bv_base:x} (offset=0x{self.offset:x})",
        )

    def translate(self, runtime_addr: int) -> Optional[int]:
        """convert runtime address to binaryview virtual address"""
        if not self._can_translate():
            return None

        # check if address belongs to our target module
        if not self.target_module.contains_address(runtime_addr):
            return None

        # translate to binaryview address
        bv_addr = runtime_addr + self.offset

        # verify the translated address makes sense
        if not any(seg.start <= bv_addr < seg.end for seg in self.bv.segments):
            log_warn(
                self.bv,
                f"translated address 0x{bv_addr:x} not in any binaryview segment",
            )
            return None

        return bv_addr

    def is_target_address(self, runtime_addr: int) -> bool:
        """check if address belongs to target module"""
        if not self.target_module:
            return False
        return self.target_module.contains_address(runtime_addr)

    def _can_translate(self) -> bool:
        """check if translator is properly initialized"""
        return (
            self.target_module is not None
            and self.bv_base is not None
            and self.offset is not None
        )

    def get_stats(self) -> dict:
        """get translation statistics"""
        return {
            "has_target_module": self.target_module is not None,
            "target_module_name": (
                self.target_module.name if self.target_module else None
            ),
            "target_runtime_base": (
                f"0x{self.target_module.runtime_base:x}" if self.target_module else None
            ),
            "bv_base": f"0x{self.bv_base:x}" if self.bv_base else None,
            "translation_offset": f"0x{self.offset:x}" if self.offset else None,
            "can_translate": self._can_translate(),
        }
