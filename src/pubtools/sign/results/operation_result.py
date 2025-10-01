from __future__ import annotations

from abc import ABC, abstractmethod
import dataclasses
from typing import Any, Dict, List


@dataclasses.dataclass()
class OperationResult(ABC):
    """OperationResult abstract class."""

    signing_keys: List[str]

    @abstractmethod
    def to_dict(self: OperationResult) -> Dict[Any, Any]:
        """Return dict representation of OperationResult."""
        ...  # pragma: no cover
