# w1trace jsonl format parser

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView

from .base import BaseParser
from ..tracedb import TraceDB, TraceEntry


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

        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    record_type = data.get("type")

                    if record_type == "metadata":
                        # store metadata for potential future use
                        # could extract module info, version, etc.
                        continue

                    elif record_type == "insn":
                        # instruction execution record
                        address = data.get("address")
                        step = data.get("step")

                        if address is None or step is None:
                            continue

                        # add trace entry
                        trace_db.add_entry(
                            address=address,
                            thread_id=0,  # w1trace doesn't specify thread in this format
                            metadata={"step": step},
                        )

                except json.JSONDecodeError as e:
                    from ..log import log_warn

                    log_warn(bv, f"skipping malformed json at line {line_num}: {e}")
                    continue
                except Exception as e:
                    from ..log import log_warn

                    log_warn(bv, f"error processing line {line_num}: {e}")
                    continue

        return trace_db
