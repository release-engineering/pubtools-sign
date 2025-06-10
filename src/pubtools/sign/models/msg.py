import dataclasses
from typing import Dict, Any, Optional


@dataclasses.dataclass
class MsgMessage:
    """Messaging message model.

    Attributes:
        headers (Dict[str, Any]): Headers of the message.
        address (str): Address to which the message is sent.
        body (Dict[str, Any]): Body of the message.
    """

    headers: Dict[str, Any]
    address: str
    body: Dict[str, Any]


@dataclasses.dataclass
class MsgError:
    """Messaging error model.

    Attributes:
        name (str): Name of the error.
        description (Optional[str]): Description of the error.
        source (Any): Source of the error, can be a link, session, connection, or transport.
    """

    name: str
    description: Optional[str]
    source: Any
