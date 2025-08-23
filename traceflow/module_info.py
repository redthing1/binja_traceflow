# module information for trace parsing

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class ModuleInfo:
    """information about a module from trace metadata"""

    id: int
    name: str
    path: str
    runtime_base: int  # runtime base address with aslr
    size: int
    type: str  # main, library, etc.
    is_system: bool

    @property
    def runtime_end(self) -> int:
        """end address of module at runtime"""
        return self.runtime_base + self.size

    def contains_address(self, address: int) -> bool:
        """check if address falls within this module's runtime range"""
        return self.runtime_base <= address < self.runtime_end

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleInfo":
        """create moduleinfo from dictionary (e.g., from json)"""
        return cls(
            id=data["id"],
            name=data["name"],
            path=data["path"],
            runtime_base=data["base"],
            size=data["size"],
            type=data.get("type", "unknown"),
            is_system=data.get("is_system", False),
        )
