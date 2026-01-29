import datetime
import json
import logging
import threading
from typing import Any, List, Dict, Union, cast

from ..models.msg import MsgError

from .msg import _MsgClient

import proton
import proton.utils
from proton.reactor import Container

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.sign.client.msg_recv_client")


class _RecvClient(_MsgClient):

    def __init__(
        self,
        uid: str,
        topic: str,
        message_ids: List[str],
        id_key: str,
        broker_urls: List[str],
        cert: str,
        ca_cert: str,
        timeout: int,
        recv: Dict[Any, Any],
        errors: List[MsgError],
    ) -> None:
        super().__init__(errors=errors)
        self.uid = uid
        self.broker_urls = broker_urls
        self.topic = topic
        self.id_key = id_key
        self.ssl_domain = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)
        if cert:
            LOG.info(self._format_log_msg(f"RECEIVER: Using {cert} as SSL certificate"))
            self.ssl_domain.set_credentials(cert, cert, None)
        if ca_cert:
            LOG.info(self._format_log_msg(f"RECEIVER: Using {ca_cert} as SSL CA certificate"))
            self.ssl_domain.set_trusted_ca_db(ca_cert)
        self.ssl_domain.set_peer_authentication(proton.SSLDomain.ANONYMOUS_PEER)
        self.recv_ids = {x: False for x in message_ids}
        self.confirmed = 0
        self.recv = recv
        self.timeout = timeout
        self.recv_in_time = False
        self.last_message_received = datetime.datetime.now()
        LOG.info(self._format_log_msg(f"RECEIVER: Listening to topic {topic}"))
        LOG.info(self._format_log_msg(f"RECEIVER: Expected to receive {len(message_ids)} messages"))

    def on_start(self, event: proton.Event) -> None:
        LOG.debug(self._format_log_msg("RECEIVER: On start", event=event))
        self.conn = event.container.connect(
            urls=self.broker_urls, ssl_domain=self.ssl_domain, sasl_enabled=False
        )
        self.receiver = event.container.create_receiver(self.conn, self.topic)
        self.timer_task = event.container.schedule(self.timeout / 2, self)

    def on_error(self, event: proton.Event, source: Any = None) -> bool:
        not_ignored = super().on_error(event, event.transport)
        if not not_ignored:
            LOG.warning(
                self._format_log_msg(
                    f"RECEIVER Error: {source.condition or source.remote_condition} ignored",
                    event=event,
                )
            )
        else:
            LOG.error(
                self._format_log_msg(
                    f"RECEIVER Error: {source.condition or source.remote_condition}", event=event
                )
            )
        return not_ignored

    @tw.instrument_func()
    def on_message(self, event: proton.Event) -> None:
        LOG.debug(self._format_log_msg(f"RECEIVER: On message {event.message.body}", event=event))
        outer_message = json.loads(event.message.body)
        headers = event.message.properties
        msg_id = outer_message["msg"][self.id_key]
        if event.delivery:
            self.accept(event.delivery)

        if msg_id in self.recv_ids:
            self.recv_ids[msg_id] = True
            self.recv[msg_id] = (outer_message, headers)
            self.recv_in_time = True
            self.last_message_received = datetime.datetime.now()
        else:
            LOG.debug(self._format_log_msg(f"RECEIVER: Ignored message {msg_id}", event=event))

        if self.recv_ids.values() and all(self.recv_ids.values()):
            self.timer_task.cancel()
            if event.receiver:
                event.receiver.close()
            if event.connection:
                event.connection.close()
            LOG.info(self._format_log_msg("RECEIVER:All messages received", event=event))

    def on_timer_task(self, event: proton.Event) -> None:
        if self.recv_in_time:
            LOG.info(
                self._format_log_msg(
                    f"RECEIVER: On timeout but messages was received - "
                    f"continue, received: {len([x for x in self.recv_ids.values() if x])}"
                    f"/{len([x for x in self.recv_ids.values() if x])}",
                    event=event,
                )
            )
            self.recv_in_time = False
            self.timer_task = event.reactor.schedule(self.timeout / 2, self)
            return
        if (datetime.datetime.now() - self.last_message_received).total_seconds() < self.timeout:
            self.timer_task = event.reactor.schedule(self.timeout / 2, self)
            return
        LOG.warning(
            self._format_log_msg(
                "RECEIVER: On timeout, received messages: "
                f"{len([x for x in self.recv_ids.values() if x])}/"
                f"{len(self.recv_ids)}",
                event=event,
            )
        )
        self.timer_task.cancel()
        if event.connection:
            event.connection.close()  # pragma: no cover
        if event.receiver:
            event.receiver.close()  # pragma: no cover
        event.container.stop()

        if not all(self.recv_ids.values()):
            self.errors.append(
                MsgError(
                    source=event,
                    name="MessagingTimeout",
                    description=self._format_log_msg(
                        "Out of time when receiving messages "
                        f"({len([x for x in self.recv_ids.values() if x])}"
                        f"/{len(self.recv_ids)})",
                        event=event,
                    ),
                )
            )

    def close(self) -> None:
        if hasattr(self, "timer_task"):
            self.timer_task.cancel()
        if hasattr(self, "receiver"):
            self.receiver.close()
        if hasattr(self, "conn"):
            self.conn.close()


class RecvClient(Container):
    """Messaging receiver."""

    def __init__(
        self,
        uid: str,
        topic: str,
        message_ids: List[str],
        id_key: str,
        broker_urls: List[str],
        cert: str,
        ca_cert: str,
        timeout: int,
        retries: int,
        errors: List[MsgError],
        received: Dict[Any, Any],
    ) -> None:
        """Recv Client Initializer.

        Args:
            topic (str): Topic where to listen for incoming messages
            message_ids (List[str]): List of awaited message ids
            id_key (str): Attribute name in message body which is considered as id
            broker_urls (List[str]): List of broker urls
            cert (str): Messaging client certificate
            ca_cert (str): Messaging ca certificate
            timeout (int): Timeout for the messaging receiver
            retries (int): How many attempts to retry receiving messages
            errors (List[MsgError]): List of errors which occured during the process
            received (Dict[Any, Any]): Mapping of received messages
            uid (str): Unique identifier for the receiver
        """
        self.message_ids = message_ids
        self.recv: Dict[Any, Any] = received
        self._errors: List[MsgError] = errors
        self.topic = topic
        self.message_ids = message_ids
        self.id_key = id_key
        self.broker_urls = broker_urls
        self.cert = cert
        self.ca_cert = ca_cert
        self.timeout = timeout
        self.uid = uid
        self._retries = retries
        handler = _RecvClient(
            uid=uid,
            topic=topic,
            message_ids=message_ids,
            id_key=id_key,
            broker_urls=broker_urls,
            cert=cert,
            ca_cert=ca_cert,
            timeout=timeout,
            recv=self.recv,
            errors=self._errors,
        )
        super().__init__(handler)
        self._handler = handler

    def get_errors(self) -> List[MsgError]:
        """Get errors from receiver.

        This method doesn't have any meaningfull usecase, it's only used for testing

        Returns:
            List[MsgError]: List of errors which occured during the process
        """
        return self._errors  # pragma: no cover

    def get_received(self) -> Dict[Any, Any]:
        """Get received messages.

        This method doesn't have any meaningfull usecase, it's only used for testing

        Returns:
            Dict[Any, Any]: Dictionary of received messages
        """
        return self.recv  # pragma: no cover

    def run(self) -> Union[Dict[Any, Any], List[MsgError]]:  # type: ignore[override]
        """Run the receiver.

        This method starts the receiver and waits for messages to be received.

        Returns:
            Union[Dict[Any, Any], List[MsgError]]: Dictionary of received messages if successful,
            or a list of errors if any occurred.
        """
        LOG.info("Running messaging receiver")
        if not len(self.message_ids):
            LOG.warning("No messages to receive")
            return []
        super().run()
        if self._errors:
            return self._errors
        return self.recv

    def close(self) -> None:
        """Close receiver."""
        LOG.info("Closing messaging receiver")
        if self._handler:
            cast(_RecvClient, self._handler).close()


class RecvThread(threading.Thread):
    """Receiver wrapper allows to stop receiver on demand."""

    def __init__(self, recv: RecvClient):
        """Recv Thread Initializer.

        Args:
            recv (RecvClient): RecvClient instance
        """
        super().__init__()
        self.recv = recv

    def stop(self) -> None:
        """Stop receiver."""
        self.recv.close()

    def run(self) -> None:
        """Run receiver."""
        self.recv.run()
