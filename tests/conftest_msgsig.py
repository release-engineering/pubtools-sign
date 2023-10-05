from unittest.mock import patch

from pytest import fixture
import tempfile


@fixture
def f_msg_signer(f_config_msg_signer_ok):
    with patch("pubtools.sign.signers.msgsigner.MsgSigner") as msgsigner:
        yield msgsigner


@fixture
def f_config_msg_signer_ok(f_client_certificate):
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            f"""
msg_signer:
  messaging_brokers:
    - amqps://broker-01:5671
    - amqps://broker-02:5671
  messaging_cert_key: {f_client_certificate}
  messaging_ca_cert: ~/messaging/ca-cert.crt
  topic_send_to: topic://Topic.sign
  topic_listen_to: queue://Consumer.{{creator}}.{{task_id}}.Topic.sign.{{task_id}}
  environment: prod
  service: pubtools-sign
  timeout: 1
  retries: 3
  message_id_key: request_id
  log_level: debug
        """.encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name
