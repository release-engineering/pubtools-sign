from unittest.mock import patch, Mock
import time
from threading import Thread

from pubtools.sign.clients.msg_send_client import SendClient, _SendClient
from pubtools.sign.clients.msg_recv_client import RecvClient, _RecvClient, RecvThread
from pubtools.sign.models.msg import MsgMessage


def test_recv_client_zero_messages(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
    f_client_certificate,
    f_ca_certificate,
):
    qpid_broker, port = f_qpid_broker
    errors = []
    received = {}
    rc = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue,
        [],
        [f"localhost:{port}"],
        "request_id",
        f_client_certificate,
        f_ca_certificate,
        1.0,
        1,
        errors,
        received,
    )
    rc.run()
    msgsigner, _, received_messages = f_fake_msgsigner
    assert [x.body for x in msgsigner.received_messages] == []


def test_recv_client_recv_message(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )

    sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
    errors = []
    received = {}
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue,
        ["1"],
        "request_id",
        [f"localhost:{port}"],
        "",
        "",
        60.0,
        2,
        errors,
        received,
    )

    tsc = Thread(target=sender.run, args=())
    trc = Thread(target=receiver.run, args=())

    trc.start()
    tsc.start()

    time.sleep(1)

    assert receiver.recv == {
        "1": ({"msg": {"message": "test_message", "request_id": "1"}}, {"mtype": "test"})
    }

    receiver.stop()
    sender.stop()
    tsc.join()
    trc.join()


def test_recv_client_timeout(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )
    errors = []
    received = {}
    sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue + "_wrong",
        ["1"],
        "request_id",
        [f"localhost:{port}"],
        "",
        "",
        10.0,
        1,
        errors,
        received,
    )

    tsc = Thread(target=sender.run, args=())
    trc = Thread(target=receiver.run, args=())

    trc.start()
    tsc.start()

    time.sleep(1)

    assert receiver.recv == {}


def test_recv_client_transport_error(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    errors = []
    received = {}
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue,
        ["1"],
        "request_id",
        [f"localhost:{port+1}"],
        "",
        "",
        10.0,
        1,
        errors,
        received,
    )

    trc = Thread(target=receiver.run, args=())

    trc.start()

    time.sleep(1)
    assert len(errors) == 1


def test_recv_client_link_error(
    f_cleanup_msgsigner_messages,
    f_broken_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_broken_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )
    sender = SendClient([message], [f"localhostx:{port}"], "", "", 10, [])
    errors = []
    received = {}
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue,
        ["1"],
        "request_id",
        [f"localhost:{port}"],
        "",
        "",
        10.0,
        1,
        errors,
        received,
    )

    tsc = Thread(target=sender.run, args=())
    trc = Thread(target=receiver.run, args=())

    trc.start()
    tsc.start()
    time.sleep(1)
    assert len(errors) == 1


def test_recv_client_errors(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )
    sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
    errors = []
    received = {}

    print(id(errors))
    on_message_original = _RecvClient.on_message
    with patch(
        "pubtools.sign.clients.msg_recv_client._RecvClient.on_message", autospec=True
    ) as patched_on_message:
        patched_on_message.side_effect = lambda self, event: [
            self.errors.append("1"),
            on_message_original(self, event),
        ]

        receiver = RecvClient(
            "uid-1",
            f_msgsigner_send_to_queue,
            ["1"],
            "request_id",
            [f"localhost:{port}"],
            "",
            "",
            10.0,
            1,
            errors,
            received,
        )

        tsc = Thread(target=sender.run, args=())
        trc = Thread(target=receiver.run, args=())

        trc.start()
        tsc.start()
        # time.sleep(1)
        trc.join()
        assert len(errors) == 1


def test_recv_client_timeout_recv_in_time(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )
    message2 = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "2"}},
    )
    sender = SendClient([message, message2], [f"localhost:{port}"], "", "", 10, [], prefetch=1)
    errors = []
    received = {}

    # on_message_original = _RecvClient.on_message
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue,
        ["1", "2"],
        "request_id",
        [f"localhost:{port}"],
        "",
        "",
        8,
        1,
        errors,
        received,
    )

    sender.handler.handlers[0].on_start(Mock())
    receiver._handler.on_start(Mock())
    sender.handler.handlers[0].on_sendable(Mock())
    receiver._handler.on_message(
        Mock(message=Mock(body='{"msg":{"message":"test_message","request_id":"2"}}'))
    )
    receiver._handler.on_timer_task(Mock())
    receiver._handler.on_message(
        Mock(message=Mock(body='{"msg":{"message":"test_message","request_id":"2"}}'))
    )
    assert receiver.errors == []


def test_recv_client_recv_message_stray(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic_stray,
    f_msgsigner_send_to_queue_stray,
    f_fake_msgsigner_stray,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic_stray,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )

    sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
    errors = []
    received = {}
    receiver = RecvClient(
        "uid-1",
        f_msgsigner_send_to_queue_stray,
        ["1"],
        "request_id",
        [f"localhost:{port}"],
        "",
        "",
        60.0,
        2,
        errors,
        received,
    )

    tsc = Thread(target=sender.run, args=())
    trc = Thread(target=receiver.run, args=())

    trc.start()
    tsc.start()

    time.sleep(1)

    assert receiver.recv == {}

    receiver.stop()
    sender.stop()
    tsc.join()
    trc.join()


def test_recv_client_recv_message_timeout(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )

    on_sendable_original = _SendClient.on_sendable
    with patch(
        "pubtools.sign.clients.msg_send_client._SendClient.on_sendable", autospec=True
    ) as patched_on_sendable:
        patched_on_sendable.side_effect = lambda self, event: [
            on_sendable_original(self, event),
            time.sleep(10),
        ]

        sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
        errors = []
        received = {}
        receiver = RecvClient(
            "uid-1",
            f_msgsigner_send_to_queue,
            ["1"],
            "request_id",
            [f"localhost:{port}"],
            "",
            "",
            1.0,
            2,
            errors,
            received,
        )

        tsc = Thread(target=sender.run, args=())
        trc = Thread(target=receiver.run, args=())

        trc.start()
        tsc.start()

        time.sleep(5)

        receiver.stop()
        sender.stop()
        tsc.join()
        trc.join()


class MockRecv:
    """Mock receiver class."""

    def __init__(self) -> None:
        """Initialize mock receiver."""
        self.closed = False
        self.timeout = 10
        handler = Mock()
        handler.close = self.close
        self.handler = Mock()
        self.handler.handlers = [handler]

    def close(self) -> None:
        """Close receiver handler."""
        self.closed = True

    def run(self) -> None:
        """Run interruptible endless loop."""
        while not self.closed:
            time.sleep(1)
            self.timeout -= 1
            if self.timeout < 1:
                break


def test_recv_thread() -> None:
    mock_recv = MockRecv()
    recvt = RecvThread(recv=mock_recv)
    recvt.start()
    recvt.stop()
    assert mock_recv.closed
    assert mock_recv.timeout > 0


def test_recv_client_close(
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_msgsigner_send_to_queue,
):
    qpid_broker, port = f_qpid_broker
    message = MsgMessage(
        headers={"mtype": "test"},
        address=f_msgsigner_listen_to_topic,
        body={"msg": {"message": "test_message", "request_id": "1"}},
    )

    with patch(
        "pubtools.sign.clients.msg_recv_client._RecvClient.on_start", autospec=True
    ) as patched_on_start:
        patched_on_start.side_effect = lambda self, event: [
            setattr(self, "timer_task", Mock()),
            setattr(self, "conn", Mock()),
            setattr(self, "receiver", Mock()),
            time.sleep(1),
        ]

        sender = SendClient([message], [f"localhost:{port}"], "", "", 10, [])
        errors = []
        received = {}
        receiver = RecvClient(
            "uid-1",
            f_msgsigner_send_to_queue,
            ["1"],
            "request_id",
            [f"localhost:{port}"],
            "",
            "",
            1.0,
            2,
            errors,
            received,
        )

        tsc = Thread(target=sender.run, args=())
        rcvt = RecvThread(recv=receiver)

        rcvt.start()
        tsc.start()
        sender.stop()
        rcvt.stop()
        time.sleep(1)

        tsc.join()
        rcvt.join()


def test_recv_client_close_method(f_msgsigner_send_to_queue, f_qpid_broker):
    qpid_broker, port = f_qpid_broker
    errors = []
    received = {}
    with patch(
        "pubtools.sign.clients.msg_recv_client._RecvClient.on_start", autospec=True
    ) as patched_on_start:
        patched_on_start.side_effect = lambda self, event: [
            setattr(self, "timer_task", Mock()),
            setattr(self, "conn", Mock()),
            setattr(self, "receiver", Mock()),
            time.sleep(1),
        ]
        receiver = RecvClient(
            "uid-1",
            f_msgsigner_send_to_queue,
            ["1"],
            "request_id",
            [f"localhost:{port}"],
            "",
            "",
            1.0,
            2,
            errors,
            received,
        )
        receiver.handler.on_start(Mock())
        receiver.close()
        receiver.handler.timer_task.cancel.assert_called_once()
        receiver.handler.receiver.close.assert_called_once()
        receiver.handler.conn.close.assert_called_once()
