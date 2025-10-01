from typing import List, Dict, Any, Type
from typing_extensions import Self

from .operation_result import OperationResult

import dataclasses


@dataclasses.dataclass()
class ClearSignResult(OperationResult):
    """ClearOperationResult model.

    Attributes:
        outputs (List[str]): List of signing result outputs.
        signing_keys (List[str]): List of signing keys used during signing.
    """

    outputs: List[str]
    signing_keys: List[str]

    def to_dict(self: Self) -> Dict[Any, Any]:
        """Return dict representation of ClearOperationResult."""
        return {"outputs": self.outputs, "signing_keys": self.signing_keys}

    @classmethod
    def doc_arguments(cls: Type[Self]) -> Dict[str, Any]:
        """Return dictionary with arguments description of the operation."""
        doc_arguments = {
            "operation_results": {
                "type": "list",
                "description": "Signing result output",
                "returned": "always",
                "sample": ["signed:'hello world'"],
            },
            "signing_keys": {
                "type": "list",
                "description": "The signing keys which is used during signing.",
                "returned": "always",
                "sample": ["123"],
            },
        }

        return doc_arguments
