# parser for hex address trace files

import os
import re
from typing import TYPE_CHECKING

from .base import BaseParser
from ..tracedb import TraceDB

if TYPE_CHECKING:
    from binaryninja import BinaryView


class HexParser(BaseParser):
    """parser for trace files containing hex addresses on newlines"""

    def can_parse(self, filepath: str) -> bool:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                # check first 100 lines for hex pattern
                for i, line in enumerate(f):
                    if i >= 100:
                        break

                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # look for hex pattern (0x prefix or plain hex)
                    if line.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", line):
                        return True

            return False

        except (IOError, UnicodeDecodeError):
            return False

    def parse(self, bv: "BinaryView", filepath: str) -> TraceDB:
        trace_db = TraceDB()
        filename = os.path.basename(filepath)

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                line_count = 0
                valid_addresses = 0
                invalid_addresses = 0

                for line_num, line in enumerate(f, 1):
                    line_count += 1

                    # progress tracking every 1000 lines
                    if line_count % 1000 == 0:
                        from ..log import log_info

                        log_info(
                            bv, f"parsing {filename}: processed {line_count:,} lines"
                        )

                    line = line.strip()

                    # skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    try:
                        # parse hex address
                        if line.startswith("0x"):
                            address = int(line, 16)
                        elif re.match(r"^[0-9a-fA-F]+$", line):
                            address = int(line, 16)
                        else:
                            from ..log import log_warn

                            log_warn(
                                bv, f"invalid hex format at line {line_num}: {line}"
                            )
                            invalid_addresses += 1
                            continue

                        # validate address exists in binary view
                        if not bv.is_valid_offset(address):
                            from ..log import log_warn

                            log_warn(
                                bv,
                                f"address 0x{address:x} not found in binary (line {line_num})",
                            )
                            invalid_addresses += 1
                            continue

                        # add to trace database (default thread_id=0)
                        trace_db.add_entry(address, thread_id=0)
                        valid_addresses += 1

                    except ValueError as e:
                        from ..log import log_warn

                        log_warn(
                            bv, f"failed to parse hex at line {line_num}: {line} ({e})"
                        )
                        invalid_addresses += 1
                        continue

                # final progress and stats
                from ..log import log_info, log_warn

                log_info(
                    bv,
                    f"parsed {filename}: {valid_addresses:,} valid addresses from {line_count:,} lines",
                )

                if invalid_addresses > 0:
                    log_warn(bv, f"skipped {invalid_addresses:,} invalid addresses")

                if trace_db.is_empty():
                    raise Exception(f"no valid addresses found in {filename}")

                return trace_db

        except IOError as e:
            raise Exception(f"failed to read file {filename}: {e}")
        except Exception as e:
            from ..log import log_error

            log_error(bv, f"parsing failed for {filename}: {e}")
            raise
