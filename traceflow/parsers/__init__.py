# parser factory for detecting and parsing trace files

from typing import TYPE_CHECKING, List

from .base import BaseParser
from .hex_parser import HexParser
from .w1trace_parser import W1TraceParser

if TYPE_CHECKING:
    from binaryninja import BinaryView
    from ..tracedb import TraceDB


# list of available parsers in order of preference
_PARSERS: List[BaseParser] = [
    W1TraceParser(),  # try w1trace first since it has specific format detection
    HexParser(),  # fallback to hex parser for simple address lists
]


def detect_and_parse(bv: "BinaryView", filepath: str) -> "TraceDB":
    """
    detect file format and parse using appropriate parser

    args:
        bv: binary view for address validation
        filepath: path to the trace file

    returns:
        TraceDB containing parsed trace entries

    raises:
        Exception: if no parser can handle the file or parsing fails
    """
    # try each parser in order
    for parser in _PARSERS:
        try:
            if parser.can_parse(filepath):
                return parser.parse(bv, filepath)
        except Exception as e:
            from ..log import log_error

            log_error(bv, f"parser {parser.__class__.__name__} failed: {e}")
            continue

    # no parser could handle the file
    raise Exception(f"no parser found for file format: {filepath}")
