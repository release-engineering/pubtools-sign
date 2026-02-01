"""Kafka receive client for pubtools-sign.

Implements a request-response pattern for signing operations using confluent-kafka.
The client waits for specific response message IDs that match sent requests.
"""

import datetime
import json
import logging
import threading
from typing import Any, List, Dict, Union, Optional

from confluent_kafka import Consumer, KafkaException

from ..models.kafka import KafkaError

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.sign.clients.kafka_recv_client")


# Default Kafka consumer settings for SASL_SSL authentication
DEFAULT_CONSUMER_SETTINGS = {
    "sasl.mechanisms": "SCRAM-SHA-512",
    "security.protocol": "SASL_SSL",
    "enable.auto.commit": False,
    "auto.offset.reset": "earliest",
    "partition.assignment.strategy": "cooperative-sticky",
}


class _KafkaRecvClient:
    """Internal Kafka receive client for request-response pattern."""

    def __init__(
        self,
        uid: str,
        topic: str,
        message_ids: List[str],
        id_key: str,
        bootstrap_servers: List[str],
        username: str,
        password: str,
        group_id: str,
        timeout: int,
        recv: Dict[Any, Any],
        errors: List[KafkaError],
        additional_settings: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize Kafka receive client.

        Args:
            uid: Unique identifier for the receiver.
            topic: Topic to listen for incoming messages.
            message_ids: List of awaited message IDs.
            id_key: Attribute name in message body which is considered as ID.
            bootstrap_servers: List of Kafka broker URLs.
            username: Kafka username for SASL authentication.
            password: Kafka password for SASL authentication.
            group_id: Consumer group ID.
            timeout: Timeout for receiving messages.
            recv: Dictionary to store received messages.
            errors: List to collect errors.
            additional_settings: Additional Kafka consumer settings.
        """
        self.uid = uid
        self.topic = topic
        self.message_ids = message_ids
        self.id_key = id_key
        self.bootstrap_servers = bootstrap_servers
        self.username = username
        self.password = password
        self.group_id = group_id
        self.timeout = timeout
        self.recv = recv
        self.errors = errors
        self.additional_settings = additional_settings or {}

        self._consumer: Optional[Consumer] = None
        self._stop_flag = False
        self.recv_ids = {x: False for x in message_ids}
        self.recv_in_time = False
        self.last_message_received = datetime.datetime.now()

        LOG.info("KAFKA RECEIVER [%s]: Listening to topic %s", uid, topic)
        LOG.info(
            "KAFKA RECEIVER [%s]: Expected to receive %d messages",
            uid,
            len(message_ids),
        )

    def _get_consumer(self) -> Consumer:
        """Create and cache the Kafka consumer."""
        if not self._consumer:
            # Build consumer config
            config_dict = {
                "bootstrap.servers": ",".join(self.bootstrap_servers),
                "sasl.username": self.username,
                "sasl.password": self.password,
                "group.id": self.group_id,
                **DEFAULT_CONSUMER_SETTINGS,
            }
            config_dict.update(self.additional_settings)
            self._consumer = Consumer(config_dict)
            LOG.info(
                "KAFKA RECEIVER [%s]: Created consumer for %s with group %s",
                self.uid,
                self.bootstrap_servers,
                self.group_id,
            )
        return self._consumer

    def _parse_headers(self, headers: Optional[List[tuple]]) -> Dict[str, Any]:
        """Parse Kafka headers into a dictionary."""
        if not headers:
            return {}
        result = {}
        for key, value in headers:
            if value is not None:
                try:
                    result[key] = value.decode("utf-8")
                except (UnicodeDecodeError, AttributeError):
                    result[key] = value
        return result

    @tw.instrument_func()
    def _process_message(self, msg: Any) -> bool:
        """Process a received message.

        Args:
            msg: The Kafka message.

        Returns:
            True if all expected messages have been received.
        """
        try:
            value = msg.value()
            if not value:
                return False

            outer_message = json.loads(value.decode("utf-8"))
            headers = self._parse_headers(msg.headers())

            # Extract message ID from the nested structure
            msg_content = outer_message.get("msg", outer_message)
            msg_id = msg_content.get(self.id_key)

            if msg_id is None:
                LOG.debug(
                    "KAFKA RECEIVER [%s]: Message has no %s field, skipping",
                    self.uid,
                    self.id_key,
                )
                return False

            if msg_id in self.recv_ids:
                self.recv_ids[msg_id] = True
                self.recv[msg_id] = (outer_message, headers)
                self.recv_in_time = True
                self.last_message_received = datetime.datetime.now()
                LOG.debug(
                    "KAFKA RECEIVER [%s]: Received expected message %s",
                    self.uid,
                    msg_id,
                )
            else:
                LOG.debug(
                    "KAFKA RECEIVER [%s]: Ignored message %s (not in expected list)",
                    self.uid,
                    msg_id,
                )

            # Check if all messages received
            if self.recv_ids.values() and all(self.recv_ids.values()):
                LOG.info(
                    "KAFKA RECEIVER [%s]: All messages received",
                    self.uid,
                )
                return True

        except json.JSONDecodeError as e:
            LOG.warning(
                "KAFKA RECEIVER [%s]: Failed to decode message: %s",
                self.uid,
                e,
            )
        except Exception as e:
            LOG.error(
                "KAFKA RECEIVER [%s]: Error processing message: %s",
                self.uid,
                e,
            )

        return False

    def _check_timeout(self) -> bool:
        """Check if timeout has been exceeded.

        Returns:
            True if timeout exceeded and should stop.
        """
        elapsed = (datetime.datetime.now() - self.last_message_received).total_seconds()

        if self.recv_in_time:
            # Reset if we received a message recently
            self.recv_in_time = False
            return False

        if elapsed >= self.timeout:
            received_count = len([x for x in self.recv_ids.values() if x])
            total_count = len(self.recv_ids)

            LOG.warning(
                "KAFKA RECEIVER [%s]: Timeout after %.1f seconds. "
                "Received %d/%d messages",
                self.uid,
                elapsed,
                received_count,
                total_count,
            )

            if not all(self.recv_ids.values()):
                self.errors.append(
                    KafkaError(
                        source=None,
                        name="MessagingTimeout",
                        description=(
                            f"Out of time when receiving messages "
                            f"({received_count}/{total_count})"
                        ),
                    )
                )
            return True

        return False

    def run(self) -> Union[Dict[Any, Any], List[KafkaError]]:
        """Run the receiver.

        Returns:
            Dictionary of received messages if successful,
            or list of errors if any occurred.
        """
        if not self.message_ids:
            LOG.warning("KAFKA RECEIVER [%s]: No messages to receive", self.uid)
            return {}

        consumer = self._get_consumer()
        consumer.subscribe([self.topic])

        LOG.info("KAFKA RECEIVER [%s]: Starting to poll for messages", self.uid)

        try:
            while not self._stop_flag:
                # Check timeout
                if self._check_timeout():
                    break

                # Poll for messages
                msg = consumer.poll(timeout=1.0)

                if msg is None:
                    continue

                if msg.error():
                    LOG.debug(
                        "KAFKA RECEIVER [%s]: Consumer error: %s",
                        self.uid,
                        msg.error(),
                    )
                    continue

                # Process the message
                all_received = self._process_message(msg)

                # Commit the offset
                consumer.commit(msg)

                if all_received:
                    break

        except KafkaException as e:
            LOG.error("KAFKA RECEIVER [%s]: Kafka error: %s", self.uid, e)
            self.errors.append(
                KafkaError(
                    name="KafkaError",
                    description=str(e),
                    source=e,
                )
            )

        if self.errors:
            return self.errors

        return self.recv

    def stop(self) -> None:
        """Stop the receiver."""
        self._stop_flag = True

    def close(self) -> None:
        """Close the consumer."""
        self._stop_flag = True
        if self._consumer:
            try:
                self._consumer.close()
                LOG.info("KAFKA RECEIVER [%s]: Consumer closed", self.uid)
            except (RuntimeError, KafkaException):
                LOG.debug("KAFKA RECEIVER [%s]: Consumer already closed", self.uid)

    def get_errors(self) -> List[KafkaError]:
        """Get errors from receiver."""
        return self.errors

    def get_received(self) -> Dict[Any, Any]:
        """Get received messages."""
        return self.recv


class KafkaRecvClient:
    """Kafka receive client wrapper class."""

    def __init__(
        self,
        uid: str,
        topic: str,
        message_ids: List[str],
        id_key: str,
        bootstrap_servers: List[str],
        username: str,
        password: str,
        group_id: str,
        timeout: int,
        retries: int,
        errors: List[KafkaError],
        received: Dict[Any, Any],
        additional_settings: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Kafka Recv Client Initializer.

        Args:
            uid: Unique identifier for the receiver.
            topic: Topic where to listen for incoming messages.
            message_ids: List of awaited message IDs.
            id_key: Attribute name in message body which is considered as ID.
            bootstrap_servers: List of Kafka broker URLs.
            username: Kafka username for SASL authentication.
            password: Kafka password for SASL authentication.
            group_id: Consumer group ID.
            timeout: Timeout for the messaging receiver.
            retries: How many attempts to retry receiving messages.
            errors: List of errors which occurred during the process.
            received: Mapping of received messages.
            additional_settings: Additional Kafka consumer settings.
        """
        self.message_ids = message_ids
        self.recv: Dict[Any, Any] = received
        self._errors: List[KafkaError] = errors
        self.topic = topic
        self.id_key = id_key
        self.bootstrap_servers = bootstrap_servers
        self.username = username
        self.password = password
        self.group_id = group_id
        self.timeout = timeout
        self.uid = uid
        self._retries = retries
        self.additional_settings = additional_settings

        self._handler = _KafkaRecvClient(
            uid=uid,
            topic=topic,
            message_ids=message_ids,
            id_key=id_key,
            bootstrap_servers=bootstrap_servers,
            username=username,
            password=password,
            group_id=group_id,
            timeout=timeout,
            recv=self.recv,
            errors=self._errors,
            additional_settings=additional_settings,
        )

    def get_errors(self) -> List[KafkaError]:
        """Get errors from receiver.

        Returns:
            List of errors which occurred during the process.
        """
        return self._errors

    def get_received(self) -> Dict[Any, Any]:
        """Get received messages.

        Returns:
            Dictionary of received messages.
        """
        return self.recv

    def run(self) -> Union[Dict[Any, Any], List[KafkaError]]:
        """Run the receiver.

        Returns:
            Dictionary of received messages if successful,
            or a list of errors if any occurred.
        """
        LOG.info("Running Kafka messaging receiver")
        if not len(self.message_ids):
            LOG.warning("No messages to receive")
            return {}

        return self._handler.run()

    def close(self) -> None:
        """Close receiver."""
        LOG.info("Closing Kafka messaging receiver")
        self._handler.close()


class KafkaRecvThread(threading.Thread):
    """Receiver wrapper allows to stop receiver on demand."""

    def __init__(self, recv: KafkaRecvClient):
        """Kafka Recv Thread Initializer.

        Args:
            recv: KafkaRecvClient instance.
        """
        super().__init__()
        self.recv = recv
        self._result: Union[Dict[Any, Any], List[KafkaError]] = {}

    def stop(self) -> None:
        """Stop receiver."""
        self.recv.close()

    def run(self) -> None:
        """Run receiver."""
        self._result = self.recv.run()

    def get_result(self) -> Union[Dict[Any, Any], List[KafkaError]]:
        """Get the result from the receiver thread."""
        return self._result
