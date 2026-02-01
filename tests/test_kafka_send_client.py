"""Tests for Kafka send client."""

import json
from unittest.mock import Mock, patch, MagicMock

import pytest

from pubtools.sign.models.kafka import KafkaMessage, KafkaError
from pubtools.sign.clients.kafka_send_client import KafkaSendClient


class TestKafkaSendClient:
    """Tests for KafkaSendClient."""

    def test_send_zero_messages(self):
        """Test sending zero messages returns empty errors."""
        errors = []
        client = KafkaSendClient(
            messages=[],
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=3,
            errors=errors,
        )
        result = client.run()
        assert result == []
        assert len(errors) == 0

    @patch("pubtools.sign.clients.kafka_send_client.Producer")
    def test_send_single_message(self, mock_producer_class):
        """Test sending a single message successfully."""
        mock_producer = MagicMock()
        mock_producer_class.return_value = mock_producer

        # Simulate successful delivery callback
        def mock_produce(topic, value, headers, timestamp, callback):
            mock_msg = Mock()
            mock_msg.topic.return_value = topic
            mock_msg.partition.return_value = 0
            mock_msg.offset.return_value = 1
            callback(None, mock_msg)

        mock_producer.produce.side_effect = mock_produce
        mock_producer.flush.return_value = 0

        message = KafkaMessage(
            headers={"mtype": "test"},
            topic="test-topic",
            body={"msg": {"request_id": "123", "data": "test"}},
        )

        errors = []
        client = KafkaSendClient(
            messages=[message],
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=3,
            errors=errors,
        )

        result = client.run()

        assert result == []
        assert client.sent == 1
        assert client.confirmed == 1
        mock_producer.produce.assert_called_once()

    @patch("pubtools.sign.clients.kafka_send_client.Producer")
    def test_send_multiple_messages(self, mock_producer_class):
        """Test sending multiple messages."""
        mock_producer = MagicMock()
        mock_producer_class.return_value = mock_producer

        call_count = 0

        def mock_produce(topic, value, headers, timestamp, callback):
            nonlocal call_count
            call_count += 1
            mock_msg = Mock()
            mock_msg.topic.return_value = topic
            mock_msg.partition.return_value = 0
            mock_msg.offset.return_value = call_count
            callback(None, mock_msg)

        mock_producer.produce.side_effect = mock_produce
        mock_producer.flush.return_value = 0

        messages = [
            KafkaMessage(
                headers={"mtype": "test"},
                topic="test-topic",
                body={"msg": {"request_id": f"id-{i}", "data": f"test-{i}"}},
            )
            for i in range(3)
        ]

        errors = []
        client = KafkaSendClient(
            messages=messages,
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=3,
            errors=errors,
        )

        result = client.run()

        assert result == []
        assert client.sent == 3
        assert client.confirmed == 3
        assert mock_producer.produce.call_count == 3

    @patch("pubtools.sign.clients.kafka_send_client.Producer")
    def test_send_with_delivery_error(self, mock_producer_class):
        """Test handling delivery errors."""
        from confluent_kafka import KafkaException

        mock_producer = MagicMock()
        mock_producer_class.return_value = mock_producer

        # Simulate a KafkaException on produce
        mock_producer.produce.side_effect = KafkaException(
            Mock(str=lambda: "Delivery failed")
        )
        mock_producer.flush.return_value = 0

        message = KafkaMessage(
            headers={"mtype": "test"},
            topic="test-topic",
            body={"msg": {"request_id": "123"}},
        )

        errors = []
        client = KafkaSendClient(
            messages=[message],
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=0,  # No retries
            errors=errors,
        )

        result = client.run()

        # Should have an error
        assert len(errors) == 1
        assert errors[0].name == "KafkaSendError"

    @patch("pubtools.sign.clients.kafka_send_client.Producer")
    @patch("pubtools.sign.clients.kafka_send_client.time.sleep")
    def test_send_with_retry(self, mock_sleep, mock_producer_class):
        """Test retry logic on transient failures."""
        from confluent_kafka import KafkaException

        mock_producer = MagicMock()
        mock_producer_class.return_value = mock_producer

        attempt = 0

        def mock_produce(topic, value, headers, timestamp, callback):
            nonlocal attempt
            attempt += 1
            if attempt < 2:
                raise KafkaException(Mock(str=lambda: "Transient error"))
            mock_msg = Mock()
            mock_msg.topic.return_value = topic
            mock_msg.partition.return_value = 0
            mock_msg.offset.return_value = 1
            callback(None, mock_msg)

        mock_producer.produce.side_effect = mock_produce
        mock_producer.flush.return_value = 0

        message = KafkaMessage(
            headers={"mtype": "test"},
            topic="test-topic",
            body={"msg": {"request_id": "123"}},
        )

        errors = []
        client = KafkaSendClient(
            messages=[message],
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=3,
            errors=errors,
            fallback_base=0.1,
            fallback_factor=2.0,
        )

        result = client.run()

        assert result == []
        assert client.sent == 1
        mock_sleep.assert_called()  # Should have slept during retry

    @patch("pubtools.sign.clients.kafka_send_client.Producer")
    def test_close(self, mock_producer_class):
        """Test closing the client."""
        mock_producer = MagicMock()
        mock_producer_class.return_value = mock_producer

        client = KafkaSendClient(
            messages=[],
            bootstrap_servers=["localhost:9092"],
            username="user",
            password="pass",
            retries=3,
            errors=[],
        )

        # Create producer
        client._get_producer()
        client.close()

        mock_producer.flush.assert_called()
