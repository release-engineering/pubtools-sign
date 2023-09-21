from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar

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
    repo: str = field(
        metadata={
            "type": "str",
            "description": "Repository name",
            "required": "true",
            "sample": "repo",
        }
    )
