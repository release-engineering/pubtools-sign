from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar, Any

from ..results.operation_result import OperationResult

from .base import SignOperation


@dataclass
class ContainerSignOperation(SignOperation):
    """ContainersSignOperation model class."""

    ResultType: ClassVar[OperationResult]
    digests: List[str] = field(metadata={"description": "List of digest to sign"})
    references: List[str] = field(metadata={"description": "List of references to sign"})
    signing_key: str = field(
        metadata={"description": "Signing key short id which should be used for signing"}
    )
    task_id: str = field(
        metadata={"description": "Usually pub task id, serves as identifier for in signing request"}
    )
    identity_references: List[str] = field(
        metadata={"description": "List of references to sign"}, default_factory=list
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a dict representation of the object."""
        return dict(
            digests=self.digests,
            references=self.references,
            signing_key=self.signing_key,
            task_id=self.task_id,
        )
