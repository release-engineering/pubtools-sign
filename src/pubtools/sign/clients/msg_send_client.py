import json
import logging
from typing import List, Dict, Any

from ..models.msg import MsgMessage, MsgError

from .msg import _MsgClient

import proton
import proton.utils
from proton.reactor import Container

from pubtools.tracing import get_trace_wrapper

from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

tw = get_trace_wrapper()
propagator = TraceContextTextMapPropagator()
LOG = logging.getLogger("pubtools.sign.signers.msg_send_client")


class _SendClient(_MsgClient):
    def __init__(
        self,
        messages: List[MsgMessage],
        broker_urls: List[str],
        cert: str,
        ca_cert: str,
        errors: List[MsgError],
        **kwargs: Dict[str, Any],
    ) -> None:
        super().__init__(errors=errors, **kwargs)
        self.broker_urls = broker_urls
        self.messages = messages
        self.ssl_domain = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)
        if cert:
            LOG.info(self._format_log_msg(f"SENDER: Using {cert} as SSL certificate"))
            self.ssl_domain.set_credentials(cert, cert, None)
        if ca_cert:
            LOG.info(self._format_log_msg(f"SENDER: Using {ca_cert} as SSL CA certificate"))
            self.ssl_domain.set_trusted_ca_db(ca_cert)
        self.ssl_domain.set_peer_authentication(proton.SSLDomain.ANONYMOUS_PEER)
        self.sent = 0
        self.confirmed = 0
        self.total = len(messages)

    def on_start(self, event: proton.Event) -> None:
        event.container.connect(
            urls=self.broker_urls, ssl_domain=self.ssl_domain, sasl_enabled=False
        )

    def on_connection_opened(self, event: proton.Event) -> None:
        if event.connection:
            self.sender = event.container.create_sender(event.connection)

    @tw.instrument_func()
    def on_sendable(self, event: proton.Event) -> None:
        if event.sender and event.sender.credit and self.sent < self.total:
            message = self.messages[self.sent]
            # Inject trace context to message properties
            propagator.inject(carrier=message.headers)
            LOG.debug(
                self._format_log_msg(
                    f"SENDER: Sending message: {json.dumps(message.body)}"
                    f"{message.address}"
                    f"{json.dumps(message.headers)}",
                )
            )
            if event.sender:
                event.sender.send(
                    proton.Message(
                        properties=message.headers,
                        address=message.address,
                        body=json.dumps(message.body),
                    )
                )
            self.sent += 1

    def on_accepted(self, event: proton.Event) -> None:
        # LOG.info("Sender accepted")
        self.confirmed += 1
        if self.confirmed == self.total:
            LOG.info("SENDER: closing")
            if event.connection:
                event.connection.close()
            self.sender.close()

    def on_disconnected(self, event: proton.Event) -> None:  # pragma: no cover
        self.sent = self.confirmed  # pragma: no cover

    def on_error(self, event: proton.Event, source: Any = None) -> bool:
        not_ignored = super().on_error(event, source)
        if not not_ignored:
            LOG.warning(
                self._format_log_msg(
                    f"SENDER Error: {source.condition or source.remote_condition} ignored",
                    event=event,
                )
            )
        else:
            LOG.error(
                self._format_log_msg(
                    f"SENDER Error: {source.condition or source.remote_condition}", event=event
                )
            )
        return not_ignored


class SendClient(Container):
    """SendClient wrapper class."""

    def __init__(
        self,
        messages: List[MsgMessage],
        broker_urls: List[str],
        cert: str,
        ca_cert: str,
        retries: int,
        errors: List[MsgError],
        **kwargs: Dict[str, Any],
    ) -> None:
        """Send Client Initializer.

        Args:
            messages (List[MsgMessage]): List of messages to send.
            broker_urls (List[str]): List of addresses of messaging broker.
            cert (str): Path to messaging client key and certificate in PEM format.
            ca_cert (str): Path to messaging CA certificate.
            retries (int): Number of retries for sending messages.
            errors (List[MsgError]): List of errors which occurred during the process.
        """
        self.messages = messages
        self.handler = _SendClient(
            messages=messages, broker_urls=broker_urls, cert=cert, ca_cert=ca_cert, errors=errors
        )
        self._retries = retries
        self._errors = errors
        super().__init__(self.handler, **kwargs)

    def run(self) -> List[MsgError]:  # type: ignore[override]
        """Run the SendClient.

        Returns:
            List[MsgError]: List of errors that occurred during sending messages.
        """
        errors_len = 0
        if not len(self.messages):
            LOG.warning("No messages to send")
            return []
        for x in range(self._retries):
            super().run()
            if len(self._errors) == errors_len:
                break
            errors_len = len(self._errors)
        else:
            return self._errors
        return []
