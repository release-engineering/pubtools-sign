from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar

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
        }
    )
    signing_key: str = field(
        metadata={
            "type": "str",
            "description": "Signing key short id which should be used for signing",
            "required": "true",
            "sample": "123",
        }
    )
    task_id: str = field(
        metadata={
            "type": "str",
            "description": "Usually pub task id, serves as identifier for in signing request",
            "required": "true",
            "sample": "1",
        }
    )
    repo: str = field(
        metadata={
            "type": "str",
            "description": "Repository name",
            "required": "true",
            "sample": "repo",
        }
    )
