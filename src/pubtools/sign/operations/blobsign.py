from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar, Any

from ..results.operation_result import OperationResult

from .base import SignOperation


@dataclass
class BlobSignOperation(SignOperation):
    """BlobSignOperation model class."""

    ResultType: ClassVar[OperationResult]
    blobs: List[str] = field(
        metadata={"description": "list of string data to be signed"}, default_factory=list
    )
    task_id: str = field(
        metadata={
            "description": "Usually pub task id, serves as identifier for in signing request"
        },
        default="",
    )
    requester: str = field(
        metadata={"description": "Requester of the signing operation"}, default=""
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a dict representation of the object."""
        return dict(
            blobs=self.blobs,
            signing_key_names=self.signing_key_names,
            signing_keys=self.signing_keys,
            task_id=self.task_id,
            requester=self.requester,
        )
