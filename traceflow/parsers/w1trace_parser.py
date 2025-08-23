# w1trace jsonl format parser

import json
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from binaryninja import BinaryView

from .base import BaseParser
from ..tracedb import TraceDB, TraceEntry
from ..module_info import ModuleInfo
from ..address_translator import AddressTranslator
from ..log import log_info, log_warn, log_debug


class W1TraceParser(BaseParser):
    """parser for w1trace jsonl format"""

    @classmethod
    def get_file_extensions(cls) -> list[str]:
        """get list of file extensions this parser supports"""
        return ["jsonl"]

    @staticmethod
    def can_parse(filepath: str) -> bool:
        """check if file can be parsed by this parser"""
        try:
            with open(filepath, "r") as f:
                # check first line for w1trace metadata
                first_line = f.readline().strip()
                if not first_line:
                    return False

                data = json.loads(first_line)
                return (
                    data.get("type") == "metadata" and data.get("tracer") == "w1trace"
                )
        except (json.JSONDecodeError, FileNotFoundError, KeyError):
            return False

    def parse(self, bv: "BinaryView", filepath: str) -> TraceDB:
        """parse w1trace jsonl file and return trace database"""
        trace_db = TraceDB()
        modules: List[ModuleInfo] = []
        translator: Optional[AddressTranslator] = None

        log_debug(bv, f"parsing w1trace file: {filepath}")

        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    record_type = data.get("type")

                    if record_type == "metadata":
                        # parse module information from metadata
                        modules_data = data.get("modules", [])
                        modules = [ModuleInfo.from_dict(m) for m in modules_data]

                        log_info(bv, f"parsed {len(modules)} modules from metadata")
                        for module in modules:
                            log_debug(
                                bv,
                                f"module: {module.name} at 0x{module.runtime_base:x} size={module.size}",
                            )

                        # create address translator
                        translator = AddressTranslator(bv, modules)
                        stats = translator.get_stats()
                        log_info(bv, f"address translator: {stats}")

                        continue

                    elif record_type == "insn":
                        # instruction execution record
                        runtime_address = data.get("address")
                        step = data.get("step")

                        if runtime_address is None or step is None:
                            continue

                        # skip if no translator (no metadata yet)
                        if translator is None:
                            log_warn(
                                bv,
                                f"skipping instruction at line {line_num}: no metadata/translator available",
                            )
                            continue

                        # translate runtime address to binaryview address
                        bv_address = translator.translate(runtime_address)

                        if bv_address is not None:
                            # add trace entry with translated address
                            trace_db.add_entry(
                                address=bv_address,
                                thread_id=0,  # w1trace doesn't specify thread in this format
                                metadata={
                                    "step": step,
                                    "runtime_address": runtime_address,  # keep original for debugging
                                },
                            )
                        # else: address not in target module, skip silently

                except json.JSONDecodeError as e:
                    log_warn(bv, f"skipping malformed json at line {line_num}: {e}")
                    continue
                except Exception as e:
                    log_warn(bv, f"error processing line {line_num}: {e}")
                    continue

        # log final statistics
        total_entries = trace_db.get_total_entries()
        unique_addrs = trace_db.get_unique_address_count()

        if translator:
            stats = translator.get_stats()
            log_info(
                bv,
                f"parsing complete: {total_entries} entries, {unique_addrs} unique addresses. translator: {stats['can_translate']}",
            )
        else:
            log_warn(
                bv,
                f"parsing complete but no translator available: {total_entries} entries",
            )

        return trace_db
