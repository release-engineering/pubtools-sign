from typing import Any, List, Optional

from ..models.msg import MsgError

from proton.handlers import MessagingHandler
import proton

IGNORED_ERRORS = ["amqp:connection:framing-error"]

LOG_HDR_EVT_FMT = "[EVNT: {}]"


class _MsgClient(MessagingHandler):
    def __init__(self, errors: List[MsgError]) -> None:
        super().__init__()
        self.errors = errors

    def _format_log_msg(self, msg: str, event: Optional[proton.Event] = None) -> str:
        if event:
            hdr = LOG_HDR_EVT_FMT.format(event.type)
        else:
            hdr = ""
        return hdr + " " + msg

    def on_error(self, event: proton.Event, source: Any = None) -> bool:
        description = source.condition or source.remote_condition
        if description.name in IGNORED_ERRORS:
            return False
        self.errors.append(
            MsgError(
                name=event,
                description=source.condition or source.remote_condition,
                source=source,
            )
        )
        event.container.stop()
        return True

    def on_link_error(self, event: proton.Event) -> None:
        self.on_error(event, event.link)

    def on_session_error(self, event: proton.Event) -> None:
        self.on_error(event, event.session)

    def on_connection_error(self, event: proton.Event) -> None:
        self.on_error(event, event.connection)

    def on_transport_error(self, event: proton.Event) -> None:
        self.on_error(event, event.transport)
