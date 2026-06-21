from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanResult:
    engine: str
    sarif_document: dict[str, object]
    raw_output: str = ""
    errors: list[str] = field(default_factory=list)


class Scanner(ABC):
    engine: str

    @abstractmethod
    def scan(self, target_path: Path) -> ScanResult: ...

    @abstractmethod
    def is_available(self) -> bool: ...
