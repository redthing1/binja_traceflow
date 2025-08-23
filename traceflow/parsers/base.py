# base parser class for trace file formats

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView
    from ..tracedb import TraceDB


class BaseParser(ABC):
    """abstract base class for trace file parsers"""

    @classmethod
    def get_file_extensions(cls) -> list[str]:
        """get list of file extensions this parser supports"""
        return []

    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        pass

    @abstractmethod
    def parse(self, bv: "BinaryView", filepath: str) -> "TraceDB":
        pass
