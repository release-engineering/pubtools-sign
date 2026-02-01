"""Tests for MsgSigner with Kafka enabled."""

from unittest.mock import Mock, patch, MagicMock

import pytest

from pubtools.sign.conf.conf import load_config
from pubtools.sign.signers.msgsigner import MsgSigner


class TestMsgSignerKafkaConfig:
    """Tests for Kafka configuration loading."""

    def test_kafka_config_loading(self, f_config_msg_signer_with_kafka):
        """Test that Kafka config is properly loaded from Kafka-only config file."""
        signer = MsgSigner()
        signer.load_config(load_config(f_config_msg_signer_with_kafka))

        assert signer.kafka_enabled is True
        assert signer.kafka_bootstrap_servers == ["localhost:9092"]
        assert signer.kafka_username == "test-user"
        assert signer.kafka_password == "test-password"
        assert signer.kafka_topic_send_to == "test-signing-requests"
        assert signer.kafka_topic_listen_to == "test-signing-responses"
        assert signer.kafka_group_id == "pubtools-sign-test-group"
        assert signer.kafka_retries == 3
        # UMB should be disabled when using Kafka config
        assert signer.messaging_brokers == []

    def test_kafka_config_standalone_format(self, f_config_kafka_standalone):
        """Test that Kafka config is properly loaded from standalone Kafka config file."""
        signer = MsgSigner()
        config_data = load_config(f_config_kafka_standalone)
        signer.load_config(config_data)

        # Verify Kafka config is loaded with standalone format values
        assert signer.kafka_enabled is True
        assert signer.kafka_bootstrap_servers == ["localhost:9092"]
        assert signer.kafka_username == "test-user"
        assert signer.kafka_password == "test-password"
        assert signer.kafka_topic_send_to == "test-signing-requests"
        assert signer.kafka_topic_listen_to == "test-signing-responses"
        assert signer.kafka_group_id == "pubtools-sign-standalone-group"
        assert signer.kafka_retries == 5
        assert signer.kafka_fallback_base == 0.5
        assert signer.kafka_fallback_factor == 1.5
        # UMB should be disabled
        assert signer.messaging_brokers == []

    def test_kafka_config_umb_only(self, f_config_umb_only):
        """Test that UMB-only config works without Kafka."""
        signer = MsgSigner()
        signer.load_config(load_config(f_config_umb_only))

        # Verify UMB config is loaded
        assert signer.messaging_brokers == ["amqps://broker-01:5671", "amqps://broker-02:5671"]
        
        # Verify Kafka is not enabled
        assert signer.kafka_enabled is False

    def test_kafka_config_defaults(self, f_config_msg_signer_ok):
        """Test that Kafka config defaults are correct when not configured."""
        signer = MsgSigner()
        signer.load_config(load_config(f_config_msg_signer_ok))

        assert signer.kafka_enabled is False
        # When disabled, other fields should be empty/default
        assert signer.kafka_bootstrap_servers == []
        assert signer.kafka_username == ""
        assert signer.kafka_password == ""

    def test_kafka_doc_arguments(self):
        """Test that Kafka options are in doc_arguments."""
        doc_args = MsgSigner.doc_arguments()

        assert "kafka_enabled" in doc_args["options"]
        assert "kafka_bootstrap_servers" in doc_args["options"]
        assert "kafka_username" in doc_args["options"]
        assert "kafka_password" in doc_args["options"]
        assert "kafka_topic_send_to" in doc_args["options"]
        assert "kafka_topic_listen_to" in doc_args["options"]
        assert "kafka_group_id" in doc_args["options"]
        assert "kafka_retries" in doc_args["options"]


class TestMsgSignerKafkaMessaging:
    """Tests for Kafka messaging integration."""

    def test_kafka_disabled_no_send(self, f_config_msg_signer_ok):
        """Test that Kafka is not called when disabled."""
        signer = MsgSigner()
        signer.load_config(load_config(f_config_msg_signer_ok))

        # Kafka should be disabled
        assert signer.kafka_enabled is False

    def test_kafka_enabled_attributes(self, f_config_msg_signer_with_kafka):
        """Test that Kafka attributes are properly set when enabled."""
        signer = MsgSigner()
        signer.load_config(load_config(f_config_msg_signer_with_kafka))

        # Kafka should be enabled with all attributes set
        assert signer.kafka_enabled is True
        assert signer.kafka_bootstrap_servers == ["localhost:9092"]
        assert signer.kafka_topic_send_to == "test-signing-requests"
        assert signer.kafka_topic_listen_to == "test-signing-responses"
        assert signer.kafka_group_id == "pubtools-sign-test-group"
        # UMB should be disabled
        assert signer.messaging_brokers == []
