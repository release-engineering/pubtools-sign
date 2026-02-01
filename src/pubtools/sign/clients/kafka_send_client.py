"""Kafka send client for pubtools-sign - mirrors msg_send_client.py functionality."""

import json
import logging
import time
from typing import List, Dict, Any, Optional

from confluent_kafka import Producer, KafkaException

from ..models.kafka import KafkaMessage, KafkaError

from pubtools.tracing import get_trace_wrapper
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

tw = get_trace_wrapper()
propagator = TraceContextTextMapPropagator()
LOG = logging.getLogger("pubtools.sign.clients.kafka_send_client")


# Default Kafka producer settings for SASL_SSL authentication
DEFAULT_PRODUCER_SETTINGS = {
    "sasl.mechanisms": "SCRAM-SHA-512",
    "security.protocol": "SASL_SSL",
}


class KafkaSendClient:
    """Kafka send client wrapper class - mirrors SendClient for UMB."""

    def __init__(
        self,
        messages: List[KafkaMessage],
        bootstrap_servers: List[str],
        username: str,
        password: str,
        retries: int,
        errors: List[KafkaError],
        additional_settings: Optional[Dict[str, Any]] = None,
        fallback_base: float = 1.0,
        fallback_factor: float = 2.0,
    ) -> None:
        """Kafka Send Client Initializer.

        Args:
            messages: List of messages to send.
            bootstrap_servers: List of Kafka broker URLs.
            username: Kafka username for SASL authentication.
            password: Kafka password for SASL authentication.
            retries: Number of retries for sending messages.
            errors: List of errors which occurred during the process.
            additional_settings: Additional Kafka producer settings.
            fallback_base: Base time for exponential backoff.
            fallback_factor: Multiplier for exponential backoff.
        """
        self.messages = messages
        self._errors = errors
        self._retries = retries
        self._additional_settings = additional_settings or {}
        self._fallback_base = fallback_base
        self._fallback_factor = fallback_factor
        self._bootstrap_servers = bootstrap_servers
        self._username = username
        self._password = password

        self._producer: Optional[Producer] = None
        self.sent = 0
        self.confirmed = 0
        self._delivery_errors: Dict[str, Exception] = {}

    def _get_producer(self) -> Producer:
        """Create and cache the Kafka producer."""
        if not self._producer:
            config_dict = {
                "bootstrap.servers": ",".join(self._bootstrap_servers),
                "sasl.username": self._username,
                "sasl.password": self._password,
                **DEFAULT_PRODUCER_SETTINGS,
            }
            config_dict.update(self._additional_settings)
            self._producer = Producer(config_dict)
            LOG.info("KAFKA SENDER: Created producer for %s", self._bootstrap_servers)
        return self._producer

    def _delivery_callback(self, err: Any, msg: Any) -> None:
        """Callback for message delivery confirmation."""
        if err:
            LOG.error("KAFKA SENDER: Delivery failed for message: %s", err)
            self._delivery_errors[msg.topic()] = err
        else:
            self.confirmed += 1
            LOG.debug(
                "KAFKA SENDER: Message delivered to %s [%s] at offset %s",
                msg.topic(),
                msg.partition(),
                msg.offset(),
            )

    def _calculate_backoff(self, attempt_idx: int) -> float:
        """Calculate exponential backoff time for a given attempt."""
        return self._fallback_base * self._fallback_factor ** attempt_idx

    @tw.instrument_func()
    def _send_message(self, message: KafkaMessage) -> bool:
        """Send a single message with retry logic.

        Args:
            message: The message to send.

        Returns:
            True if message was sent successfully, False otherwise.
        """
        producer = self._get_producer()

        # Inject trace context to message headers
        headers_copy = dict(message.headers)
        propagator.inject(carrier=headers_copy)

        # Convert headers to Kafka format (list of tuples with bytes values)
        kafka_headers = [
            (k, v.encode("utf-8") if isinstance(v, str) else str(v).encode("utf-8"))
            for k, v in headers_copy.items()
        ]

        body_bytes = json.dumps(message.body).encode("utf-8")
        timestamp = int(time.time() * 1000)

        LOG.debug(
            "KAFKA SENDER: Sending message to %s: %s",
            message.topic,
            json.dumps(message.body),
        )

        for attempt_idx in range(self._retries + 1):
            try:
                producer.produce(
                    topic=message.topic,
                    value=body_bytes,
                    headers=kafka_headers,
                    timestamp=timestamp,
                    callback=self._delivery_callback,
                )
                # Flush to ensure delivery
                producer.flush(timeout=30)

                if message.topic in self._delivery_errors:
                    raise self._delivery_errors.pop(message.topic)

                self.sent += 1
                return True

            except (BufferError, KafkaException) as err:
                if attempt_idx < self._retries:
                    backoff_time = self._calculate_backoff(attempt_idx)
                    LOG.warning(
                        "KAFKA SENDER: Send failed, retrying in %.1f seconds "
                        "(attempt %d/%d): %s",
                        backoff_time,
                        attempt_idx + 1,
                        self._retries,
                        err,
                    )
                    time.sleep(backoff_time)
                else:
                    LOG.error(
                        "KAFKA SENDER: Failed to send message after %d attempts: %s",
                        self._retries + 1,
                        err,
                    )
                    self._errors.append(
                        KafkaError(
                            name="KafkaSendError",
                            description=str(err),
                            source=err,
                        )
                    )
                    return False

        return False

    def run(self) -> List[KafkaError]:
        """Send all messages.

        Returns:
            List of errors that occurred during sending messages.
        """
        if not self.messages:
            LOG.warning("KAFKA SENDER: No messages to send")
            return []

        LOG.info("KAFKA SENDER: Sending %d messages", len(self.messages))

        for message in self.messages:
            self._send_message(message)

        # Final flush
        if self._producer:
            remaining = self._producer.flush(timeout=30)
            if remaining > 0:
                LOG.warning(
                    "KAFKA SENDER: %d messages still in queue after flush", remaining
                )

        LOG.info(
            "KAFKA SENDER: Completed. Sent: %d, Confirmed: %d, Errors: %d",
            self.sent,
            self.confirmed,
            len(self._errors),
        )

        return self._errors

    def close(self) -> None:
        """Close the producer."""
        if self._producer:
            self._producer.flush()
            LOG.info("KAFKA SENDER: Producer closed")
