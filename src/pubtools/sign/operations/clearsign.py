from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar, Any

from ..results.operation_result import OperationResult

from .base import SignOperation


@dataclass
class ClearSignOperation(SignOperation):
    """ClearsSignOperation model class."""

    ResultType: ClassVar[OperationResult]
    inputs: List[str] = field(
        metadata={
            "type": "list",
            "description": "Signing data",
            "required": "true",
            "sample": ["input1", "input2"],
        },
        default_factory=list,
    )
    task_id: str = field(
        metadata={
            "type": "str",
            "description": "Usually pub task id, serves as identifier for in signing request",
            "required": "true",
            "sample": "1",
        },
        default="",
    )
    repo: str = field(
        metadata={
            "type": "str",
            "description": "Repository name",
            "required": "true",
            "sample": "repo",
        },
        default="",
    )
    requester: str = field(
        metadata={"description": "Requester of the signing operation"}, default=""
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a dict representation of the object."""
        return dict(
            inputs=self.inputs,
            signing_keys=self.signing_keys,
            task_id=self.task_id,
            repo=self.repo,
            requester=self.requester,
        )
