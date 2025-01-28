from dataclasses import dataclass
from unittest.mock import patch, Mock

from pubtools.sign.clients.msg_send_client import SendClient, _SendClient
from pubtools.sign.models.msg import MsgMessage, MsgError

import json


def test_send_client_zero_messages(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_fake_msgsigner,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    sc = SendClient([], [f"localhost:{port}"], f_client_certificate, f_ca_certificate, 10, [])
    sc.run()
    msgsigner, _, received_messages = f_fake_msgsigner
    assert [x.body for x in msgsigner.received_messages] == []


def test_send_client_send_message(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={}, address=f_msgsigner_listen_to_topic, body={"message": "test_message"}
    )
    sc = SendClient(
        [message], [f"localhost:{port}"], f_client_certificate, f_ca_certificate, 10, []
    )
    assert sc.run() == []
    msgsigner, _, received_messages = f_fake_msgsigner
    assert len(received_messages) == 1
    assert [x.body for x in received_messages] == [json.dumps(message.body)]


def test_send_client_errors(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    message1 = MsgMessage(
        headers={}, address=f_msgsigner_listen_to_topic, body={"message": "test_message1"}
    )

    on_start_original = _SendClient.on_start
    with patch(
        "pubtools.sign.clients.msg_send_client._SendClient.on_start", autospec=True
    ) as patched_on_accepted:
        errors = ["errors"]
        patched_on_accepted.side_effect = lambda self, event: [
            self.errors.append("1"),
            on_start_original(self, event),
        ]
        sc = SendClient(
            [message1], [f"localhost:{port}"], f_client_certificate, f_ca_certificate, 1, errors
        )
        assert sc.run() == ["errors", "1"]


@dataclass
class FakeDescription:
    """Fake error description."""

    name: str


def test_ingore_error(
    f_msgsigner_listen_to_topic,
    f_qpid_broker,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    message1 = MsgMessage(
        headers={}, address=f_msgsigner_listen_to_topic, body={"message": "test_message1"}
    )
    mock_error = Mock(
        transport=Mock(condition=FakeDescription(name="amqp:connection:framing-error"))
    )
    errors = []
    msgsc = _SendClient(
        [message1], [f"localhost:{port}"], f_client_certificate, f_ca_certificate, errors
    )
    msgsc.on_transport_error(mock_error)
    assert errors == []


def test_non_ingored_error(
    f_msgsigner_listen_to_topic,
    f_qpid_broker,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    message1 = MsgMessage(
        headers={}, address=f_msgsigner_listen_to_topic, body={"message": "test_message1"}
    )
    mock_error = Mock(transport=Mock(condition=FakeDescription(name="amqp:simulated-error")))
    errors = []
    msgsc = _SendClient(
        [message1], [f"localhost:{port}"], f_client_certificate, f_ca_certificate, errors
    )
    msgsc.on_transport_error(mock_error)
    assert errors == [
        MsgError(
            name=mock_error, description=mock_error.transport.condition, source=mock_error.transport
        )
    ]
