import pytest
import piny

from pubtools.sign.conf.conf import load_config


def test_load_config_radas_ok(f_config_msg_signer_ok, f_client_certificate, f_ca_certificate):
    assert load_config(f_config_msg_signer_ok) == {
        "msg_signer": {
            "messaging_brokers": ["amqps://broker-01:5671", "amqps://broker-02:5671"],
            "messaging_cert_key": f_client_certificate,
            "messaging_ca_cert": f_ca_certificate,
            "topic_send_to": "topic://Topic.sign",
            "topic_listen_to": "queue://Consumer.{creator}.{task_id}.Topic.sign.{task_id}",
            "environment": "prod",
            "service": "pubtools-sign",
            "timeout": 1,
            "retries": 3,
            "send_retries": 2,
            "message_id_key": "request_id",
            "log_level": "debug",
        }
    }


def test_load_config_missing(f_config_msg_signer_missing):
    with pytest.raises(piny.errors.ValidationError):
        assert load_config(f_config_msg_signer_missing)
