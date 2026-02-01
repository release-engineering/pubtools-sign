"""Tests for Kafka receive client."""

import json
import threading
from unittest.mock import Mock, patch, MagicMock

import pytest

from pubtools.sign.models.kafka import KafkaError
from pubtools.sign.clients.kafka_recv_client import (
    _KafkaRecvClient,
    KafkaRecvClient,
    KafkaRecvThread,
)


class TestKafkaRecvClient:
    """Tests for KafkaRecvClient."""

    def test_recv_zero_messages(self):
        """Test receiving when no messages are expected."""
        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=[],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=10,
            retries=3,
            errors=errors,
            received=received,
        )
        result = client.run()
        assert result == {}

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_single_message(self, mock_consumer_class):
        """Test receiving a single expected message."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        # Create a mock message
        mock_msg = Mock()
        mock_msg.error.return_value = None
        mock_msg.value.return_value = json.dumps({
            "msg": {"request_id": "123", "signed_data": "test-signature"}
        }).encode("utf-8")
        mock_msg.headers.return_value = [("mtype", b"test")]

        # First poll returns message, subsequent polls return None
        poll_count = 0

        def mock_poll(timeout):
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                return mock_msg
            return None

        mock_consumer.poll.side_effect = mock_poll

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=1,
            retries=3,
            errors=errors,
            received=received,
        )

        result = client.run()

        assert "123" in received
        mock_consumer.subscribe.assert_called_once_with(["test-topic"])
        mock_consumer.commit.assert_called()

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_multiple_messages(self, mock_consumer_class):
        """Test receiving multiple expected messages."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        messages = []
        for i in range(3):
            mock_msg = Mock()
            mock_msg.error.return_value = None
            mock_msg.value.return_value = json.dumps({
                "msg": {"request_id": f"id-{i}", "data": f"data-{i}"}
            }).encode("utf-8")
            mock_msg.headers.return_value = []
            messages.append(mock_msg)

        poll_idx = 0

        def mock_poll(timeout):
            nonlocal poll_idx
            if poll_idx < len(messages):
                msg = messages[poll_idx]
                poll_idx += 1
                return msg
            return None

        mock_consumer.poll.side_effect = mock_poll

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["id-0", "id-1", "id-2"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=5,
            retries=3,
            errors=errors,
            received=received,
        )

        result = client.run()

        assert len(received) == 3
        assert "id-0" in received
        assert "id-1" in received
        assert "id-2" in received

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_timeout(self, mock_consumer_class):
        """Test timeout when message not received."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        # Always return None (no messages)
        mock_consumer.poll.return_value = None

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=1,  # 1 second timeout
            retries=3,
            errors=errors,
            received=received,
        )

        result = client.run()

        # Should have timeout error
        assert len(errors) == 1
        assert errors[0].name == "MessagingTimeout"

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_ignore_unexpected_message(self, mock_consumer_class):
        """Test ignoring messages with unexpected IDs."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        # Create unexpected message
        mock_msg = Mock()
        mock_msg.error.return_value = None
        mock_msg.value.return_value = json.dumps({
            "msg": {"request_id": "unexpected-id", "data": "test"}
        }).encode("utf-8")
        mock_msg.headers.return_value = []

        poll_count = 0

        def mock_poll(timeout):
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                return mock_msg
            return None

        mock_consumer.poll.side_effect = mock_poll

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["expected-id"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=1,
            retries=3,
            errors=errors,
            received=received,
        )

        result = client.run()

        # Should not have received the unexpected message
        assert "unexpected-id" not in received
        # Should have timeout error since expected message never arrived
        assert len(errors) == 1

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_close(self, mock_consumer_class):
        """Test closing the receiver."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=10,
            retries=3,
            errors=errors,
            received=received,
        )

        # Need to initialize the consumer first by accessing the handler
        client._handler._get_consumer()
        client.close()
        mock_consumer.close.assert_called_once()

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_consumer_error(self, mock_consumer_class):
        """Test handling consumer poll errors."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        mock_msg = Mock()
        mock_msg.error.return_value = Mock(str=lambda: "Consumer error")

        poll_count = 0

        def mock_poll(timeout):
            nonlocal poll_count
            poll_count += 1
            if poll_count <= 2:
                return mock_msg
            return None

        mock_consumer.poll.side_effect = mock_poll

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=1,
            retries=3,
            errors=errors,
            received=received,
        )

        result = client.run()

        # Should handle errors gracefully and eventually timeout
        assert len(errors) >= 1


class TestKafkaRecvThread:
    """Tests for KafkaRecvThread."""

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_thread(self, mock_consumer_class):
        """Test receiver thread."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer

        mock_msg = Mock()
        mock_msg.error.return_value = None
        mock_msg.value.return_value = json.dumps({
            "msg": {"request_id": "123", "data": "test"}
        }).encode("utf-8")
        mock_msg.headers.return_value = []

        poll_count = 0

        def mock_poll(timeout):
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                return mock_msg
            return None

        mock_consumer.poll.side_effect = mock_poll

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=5,
            retries=3,
            errors=errors,
            received=received,
        )

        thread = KafkaRecvThread(client)
        thread.start()
        thread.join(timeout=10)

        assert "123" in received

    @patch("pubtools.sign.clients.kafka_recv_client.Consumer")
    def test_recv_thread_stop(self, mock_consumer_class):
        """Test stopping receiver thread."""
        mock_consumer = MagicMock()
        mock_consumer_class.return_value = mock_consumer
        mock_consumer.poll.return_value = None

        errors = []
        received = {}
        client = KafkaRecvClient(
            uid="test-1",
            topic="test-topic",
            message_ids=["123"],
            id_key="request_id",
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            group_id="test-group",
            timeout=30,
            retries=3,
            errors=errors,
            received=received,
        )

        thread = KafkaRecvThread(client)
        thread.start()

        # Stop the thread
        thread.stop()
        thread.join(timeout=5)

        assert not thread.is_alive()
