"""Kafka message and error models for pubtools-sign."""

import dataclasses
from typing import Dict, Any, Optional


@dataclasses.dataclass
class KafkaMessage:
    """Kafka message model.

    Attributes:
        headers (Dict[str, Any]): Headers of the message.
        topic (str): Topic to which the message is sent.
        body (Dict[str, Any]): Body of the message.
        ttl (Optional[int]): Time To Live of the message (not directly used in Kafka).
    """

    headers: Dict[str, Any]
    topic: str
    body: Dict[str, Any]
    ttl: Optional[int] = 0


@dataclasses.dataclass
class KafkaError:
    """Kafka error model.

    Attributes:
        name (str): Name of the error.
        description (Optional[str]): Description of the error.
        source (Any): Source of the error.
    """

    name: str
    description: Optional[str]
    source: Any
