from __future__ import annotations

from abc import ABC, abstractmethod
import dataclasses
from typing import Any, Dict

from .clearsign import ClearSignResult  # noqa: F401
from .containersign import ContainerSignResult  # noqa: F401
from .blobsign import BlobSignResult  # noqa: F401

__all__ = ["ClearSignResult", "ContainerSignResult", "BlobSignResult"]


@dataclasses.dataclass()
class SignerResults(ABC):
    """SignerResults abstract class."""

    status: str
    error_message: str

    @abstractmethod
    def to_dict(self: SignerResults) -> Dict[Any, Any]:
        """Return dict representation of SignerResults."""
        ...  # pragma: no cover
