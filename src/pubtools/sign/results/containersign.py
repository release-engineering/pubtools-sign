from __future__ import annotations
import dataclasses

from typing import List, ClassVar, Any, Dict
from typing_extensions import Self

from ..results.operation_result import OperationResult


@dataclasses.dataclass
class ContainerSignResult(OperationResult):
    """ContainerOperationResult model.

    Attributes:
        results (List[str]): List of signing result outputs.
        signing_keys (List[str]): The signing keys used during signing.
        failed (bool): Indicates if the operation failed.
    """

    ResultType: ClassVar[OperationResult]
    results: List[str]
    signing_keys: List[str]
    failed: bool

    def to_dict(self: Self) -> Dict[Any, Any]:
        """Return dict representation of ContainerOperationResult."""
        return {"results": self.results, "signing_keys": self.signing_keys, "failed": self.failed}
