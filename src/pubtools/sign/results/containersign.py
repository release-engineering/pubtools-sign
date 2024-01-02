from __future__ import annotations
import dataclasses

from typing import List, ClassVar
from typing_extensions import Self

from ..results.operation_result import OperationResult


@dataclasses.dataclass
class ContainerSignResult(OperationResult):
    """ContainerOperationResult model."""

    ResultType: ClassVar[OperationResult]
    results: List[str]
    signing_key: str
    failed: bool

    def to_dict(self: Self):
        """Return dict representation of ContainerOperationResult."""
        return {"results": self.results, "signing_key": self.signing_key, "failed": self.failed}
