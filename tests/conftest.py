import collections
import json
import socket
import logging
from multiprocessing import Process
import threading
import tempfile
import uuid
import os
import sys

from unittest.mock import patch

from .conftest_msgsig import (  # noqa: F401
    f_msg_signer,  # noqa: F401
    f_config_msg_signer_ok,  # noqa: F401
    f_config_msg_signer_ok2,  # noqa: F401
    f_config_msg_signer_aliases,  # noqa: F401
)  # noqa: F401
from .conftest_cosignsig import (  # noqa: F401
    f_cosign_signer,  # noqa: F401
    f_config_cosign_signer_ok,  # noqa: F401
    f_config_cosign_signer_aliases,  # noqa: F401
    f_config_cosign_signer_no_auth,
)  # noqa: F401


from proton import Endpoint
from proton.reactor import Container
import proton
from proton import Message

from pytest import fixture

from pubtools.sign.clients.msg import _MsgClient


LOG = logging.getLogger("pubtools.sign.signers.radas")
LOG.addHandler(logging.StreamHandler(sys.stdout))


class _Queue(object):
    def __init__(self, address, dynamic=False):
        self.address = address
        self.dynamic = dynamic
        self.queue = collections.deque()
        self.consumers = []

    def subscribe(self, consumer):
        LOG.debug("QUEUE SUBSCRIBED: %s %s", self.address, consumer)
        self.consumers.append(consumer)

    def unsubscribe(self, consumer):
        LOG.debug("QUEUE UNSUBSCRIBED: %s %s", self.address, consumer)
        if consumer in self.consumers:
            self.consumers.remove(consumer)
        return len(self.consumers) == 0 and (self.dynamic or len(self.queue) == 0)

    def publish(self, message):
        self.queue.append(message)
        self.dispatch()

    def dispatch(self, consumer=None):
        if consumer:
            c = [consumer]
        else:
            c = self.consumers
        LOG.debug("QUEUE DISPATCH TO %s %s", self.address, c)
        while self._deliver_to(c):
            pass

    def _deliver_to(self, consumers):
        try:
            result = False
            for c in consumers:
                if c.credit:
                    message = self.queue.popleft()
                    LOG.debug("QUEUE DELIVER TO %s %s", self.address, c, message)
                    c.send(message)
                    result = True
            return result
        except IndexError:  # no more messages
            LOG.debug("QUEUE NOTHING TO DELIVER %s", self.address)
            return False


class _Broker(_MsgClient):
    def __init__(self, url):
        super().__init__(errors=[])
        self.url = url
        self.queues = {}

    def on_start(self, event):
        print("BROKER on start", self.url)
        LOG.info("BROKER on start", self.url)
        self.acceptor = event.container.listen(self.url)

    def _queue(self, address):
        if address not in self.queues:
            self.queues[address] = _Queue(address)
        return self.queues[address]

    def on_link_opening(self, event):
        LOG.info(
            "BROKER on_link_opening event",
            event.link,
            "source addr:",
            event.link.source.address,
            "remote source addr",
            event.link.remote_source.address,
            "target addr:",
            event.link.target.address,
            "remote target addr",
            event.link.remote_target.address,
        )
        print(
            "BROKER on_link_opening event",
            event.link,
            "source addr:",
            event.link.source.address,
            "remote source addr",
            event.link.remote_source.address,
            "target addr:",
            event.link.target.address,
            "remote target addr",
            event.link.remote_target.address,
        )
        if event.link.is_sender:
            if event.link.remote_source.dynamic:
                address = str(uuid.uuid4())
                event.link.source.address = address
                q = _Queue(address, True)
                self.queues[address] = q
                q.subscribe(event.link)
            elif event.link.remote_source.address:
                event.link.source.address = event.link.remote_source.address
                self._queue(event.link.source.address).subscribe(event.link)
        elif event.link.remote_target.address:
            event.link.target.address = event.link.remote_target.address

    def _unsubscribe(self, link):
        if link.source.address in self.queues and self.queues[link.source.address].unsubscribe(
            link
        ):
            del self.queues[link.source.address]

    def on_link_closing(self, event):
        LOG.info(">> BROKER On link closing", event)
        if event.link.is_sender:
            self._unsubscribe(event.link)

    def on_disconnected(self, event):
        LOG.info(">> BROKER On disconnected", event)
        self.remove_stale_consumers(event.connection)

    def remove_stale_consumers(self, connection):
        link = connection.link_head(Endpoint.REMOTE_ACTIVE)
        LOG.info("BROKER removing stale consumer", link)
        while link:
            if link.is_sender:
                self._unsubscribe(link)
            link = link.next(Endpoint.REMOTE_ACTIVE)

    def on_sendable(self, event):
        LOG.info("BROKER on_sendable", event.link.source.address)
        self._queue(event.link.source.address).dispatch(event.link)

    def on_message(self, event):
        LOG.info("BROKER ON MESSAGE", event.message)
        address = event.link.target.address
        if address is None:
            address = event.message.address
        LOG.debug("BROKER publish", address)
        self._queue(address).publish(event.message)


class _BrokenBroker(_Broker):
    def on_sendable(self, event):
        LOG.info("BROKER on_sendable", event.link.source.address)
        self._queue(event.link.source.address).dispatch(event.link)
        raise ValueError("Simulated broker error")
        event.on_link_error(event)


class _FakeMsgSigner(proton.handlers.MessagingHandler):
    def __init__(self, broker_urls, listen_to, send_to, cert, ca_cert, received_messages):
        self.broker_urls = broker_urls
        self.listen_to = listen_to
        self.send_to = send_to
        self.ssl_domain = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)
        self.ssl_domain.set_peer_authentication(proton.SSLDomain.ANONYMOUS_PEER)
        self.received_messages = received_messages
        super().__init__()
        self.to_send = []

    def on_start(self, event):
        conn = event.container.connect(
            urls=self.broker_urls, ssl_domain=self.ssl_domain, sasl_enabled=False
        )
        self.receiver = event.container.create_receiver(conn, self.listen_to)

    def on_message(self, event):
        LOG.debug("RADAS on message", event.message)
        headers = event.message.properties
        self.received_messages.append(event.message)

        if headers.get("mtype") == "container_signature":
            reply_message = ""
        if headers.get("mtype") == "clearsig_signature":
            reply_message = ""
        else:
            reply_message = event.message.body

        reply = Message()
        reply.address = self.send_to
        LOG.debug("Send to", self.send_to)
        reply.body = reply_message
        reply.properties = event.message.properties

        sender = event.container.create_sender(event.connection)
        LOG.debug("RADAS Sending", reply)
        sender.send(reply)
        LOG.debug("RADAS Sent")

    def on_sendable(self, event):
        LOG.debug("RADAS on sendable")
        if not self.to_send:
            LOG.debug("RADAS Nothing to send")
            return
        message_to_send = self.to_send.pop(0)
        event.sender.send(message_to_send)


class _StrayFakeMsgSigner(_FakeMsgSigner):
    def on_message(self, event):
        headers = event.message.properties
        self.received_messages.append(event.message)

        if headers.get("mtype") == "container_signature":
            reply_message = ""
        if headers.get("mtype") == "clearsig_signature":
            reply_message = ""
        else:
            reply_message = json.loads(event.message.body)

        reply = Message()
        reply.address = self.send_to
        reply_message["msg"]["request_id"] += "1"
        reply.body = json.dumps(reply_message)

        reply.properties = event.message.properties

        sender = event.container.create_sender(event.connection)
        sender.send(reply)


def run_broker(broker, stdout):
    sys.stdout = stdout
    broker.run()


@fixture(scope="session")
def f_msgsigner_listen_to_topic():
    return "topic://Topic.pubtools.sign"


@fixture(scope="session")
def f_msgsigner_send_to_queue():
    return "topic://Topic.signatory.sign"


@fixture(scope="session")
def f_msgsigner_listen_to_topic_stray():
    return "topic://Topic.pubtools.sign.stray"


@fixture(scope="session")
def f_msgsigner_send_to_queue_stray():
    return "topic://Topic.signatory.sign.stray"


@fixture(scope="session")
def f_received_messages():
    return []


@fixture
def f_cleanup_msgsigner_messages(f_received_messages):
    return f_received_messages.clear()


@fixture(scope="session")
def f_find_available_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@fixture(scope="session")
def f_find_available_port_for_broken():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@fixture(scope="session")
def f_qpid_broker(f_find_available_port):
    LOG.info("starting broker", f"localhost:{f_find_available_port}")
    broker = Container(_Broker(f"localhost:{f_find_available_port}"))
    p = Process(target=run_broker, args=(broker, sys.stdout))
    p.start()
    yield (broker, f_find_available_port)
    LOG.info("destroying qpid broker")
    p.terminate()


@fixture(scope="session")
def f_broken_qpid_broker(f_find_available_port_for_broken):
    LOG.debug("starting broker", f"localhost:{f_find_available_port_for_broken}")
    broker = Container(_BrokenBroker(f"localhost:{f_find_available_port_for_broken}"))
    p = Process(target=broker.run, args=())
    p.start()
    yield (broker, f_find_available_port_for_broken)
    LOG.debug("destroying qpid broker")
    p.terminate()


@fixture(scope="session")
def f_fake_msgsigner(
    f_find_available_port,
    f_msgsigner_listen_to_topic,
    f_msgsigner_send_to_queue,
    f_received_messages,
):
    fr = _FakeMsgSigner(
        [f"localhost:{f_find_available_port}"],
        f_msgsigner_listen_to_topic,
        f_msgsigner_send_to_queue,
        "",
        "",
        f_received_messages,
    )
    frc = Container(fr)
    t = threading.Thread(target=frc.run, args=())
    t.start()
    yield fr, frc, f_received_messages
    frc.stop()


@fixture(scope="session")
def f_fake_msgsigner_stray(
    f_find_available_port,
    f_msgsigner_listen_to_topic_stray,
    f_msgsigner_send_to_queue_stray,
    f_received_messages,
):
    fr = _StrayFakeMsgSigner(
        [f"localhost:{f_find_available_port}"],
        f_msgsigner_listen_to_topic_stray,
        f_msgsigner_send_to_queue_stray,
        "",
        "",
        f_received_messages,
    )
    frc = Container(fr)
    t = threading.Thread(target=frc.run, args=())
    t.start()
    yield fr, frc, f_received_messages
    frc.stop()


@fixture
def f_client_certificate():
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1y5rshMkYqfP2
k7z2IJXto3AvLCAYDN9WX5mUUFgPFAFur38bDopqj5dSkXlR5f3MwZeRCNsxRXKD
USjv1T9HjD2t2D7eOAQhhx7dtgMPEYRJes02/ejzGojqrXEoG3TsCf8wBmb5ALDc
VrgEWShRRGi3qzsDXijMtzns+30+/rOfR68+353iLXTJ3g/MkVRLks6xwq35ZbH4
Ichu/6ISRU7Lk3tOq811a/SFuHdSLrOzU13VDK+6nQiWMUPbHy6OHK88dC+6mRws
RJuqHg0cKSIA5aiE7T7o9S3v10P0wJnn8B7d+bsHZJPxqLxFdbQ5Ogjrc195TEmf
kAd4kB8BAgMBAAECggEABwvEdhfuK58cLBWVKoCwMOr/jEuAdbAriI9pXlvIEvMI
fG3PvkinrZpBwB7wad/BMMo8za+vP6tQdTWcQaHlK0ispBAUXTRkeBhypj8Rgqgw
FXE9kozgJkp0LazR3L8mLqcTSX0pCOv5ftu7U3tRZkdxi9NWlOKFkCwmkghcBgjE
M2LZx4mCNbtD0WQYqMr0HdGJsedCNRrmCAZ5eoTM+HIh8C2eCRT4mBirNLIHsg/d
TqLI9TN0JvDkpTHt7W94Cxi7th5uLrXfE+D5cbHT0OV4L/kwQj3JjZDekUTCqljX
OcC8X0l8+SYo6+qlc0mmd324LzGmD+fuP9LXnHkc8QKBgQDwUABdZKZWRWMdypj4
jgzSBZa1k6cDt39373MFwhk+c5nYUm7ijsRncz85Vb8n0vwY6K0DWuP3yNfuKyVe
BDXZHfgncz3hc+pBa3B/NIxDmI16D2SEomhe+/JyHh1wnOI5DPJFSrWhYtuMvKpv
QBpQ0rNP8Xq+6c/Gg06g1SFRkQKBgQDBqbCpPOt6+dlR/7aRzbWBe9hUqYegRKw+
Is+Ap9hcup7zstsKOdjBGt89wV7BV9KQQnE69uOqBx6CdqEUId47C3F661hT/npR
B9bBdwW7m8FKbu5i86d1V3ddvdNbIkAeqwjSpnkrLzITPJ74w9yhxAxqO/7wMAs1
PBTpNHo+cQKBgE/f128zYBI2t+4UA+pBlMNN9jzeGdojaKvdm9ajIC7gz5bWN2L4
XxGffbk55fJ/ryk8VR1TXYhjaloQXzgzoA5NZsj+Behk1czuwBKXzbM+BnA2o4tu
S9CeX4RMvC5NBug9hF1BqsM8j4rkvqWBof2ROuZsdgb0wgnSZRUSIiPxAoGAHMUg
wYOTWAmWB2B9tttgg4Pqd2lYBK8vB2wUd4B33A69XmbLs5E0ajubvojjksWBOn0k
ZSYYXEICfk8xTtRZN1xT13bvAEtl0HPhq4wLBfv1kyE3uOuJjR0ZVovEwl0sOWIf
RWwFxCyWu9TdqQcv17hQP9f536TDhX0PfjWVk4ECgYEAp5ze8TFxH8PyTqGOGikn
aKhWL4DD3dNoXCYOrcEmTKOXftlvlrR+6VjCT0DFro9QxQM9S7BEhugmbm/kQoD3
0jxXWkX9wkN2thOrUwJBHBtj/PUqA+s5bbi//V8pSmdSfXn3HgKaXD40sAoX8HWn
8n8nYo3EMM6kk5gbZToN33k=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUSd6+UGxdN+U6W7tYnZwrY1Tn5NYwDQYJKoZIhvcNAQEL
BQAwSjFIMAkGA1UEBhMCVVMwGQYDVQQDDBJwdWJ0b29scy1zaWduLXRlc3QwIAYK
CZImiZPyLGQBAQwScHVidG9vbHMtc2lnbi10ZXN0MB4XDTI0MDMwNjEyMzY0MloX
DTI0MDQwNTEyMzY0MlowSjFIMAkGA1UEBhMCVVMwGQYDVQQDDBJwdWJ0b29scy1z
aWduLXRlc3QwIAYKCZImiZPyLGQBAQwScHVidG9vbHMtc2lnbi10ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtcua7ITJGKnz9pO89iCV7aNwLywg
GAzfVl+ZlFBYDxQBbq9/Gw6Kao+XUpF5UeX9zMGXkQjbMUVyg1Eo79U/R4w9rdg+
3jgEIYce3bYDDxGESXrNNv3o8xqI6q1xKBt07An/MAZm+QCw3Fa4BFkoUURot6s7
A14ozLc57Pt9Pv6zn0evPt+d4i10yd4PzJFUS5LOscKt+WWx+CHIbv+iEkVOy5N7
TqvNdWv0hbh3Ui6zs1Nd1Qyvup0IljFD2x8ujhyvPHQvupkcLESbqh4NHCkiAOWo
hO0+6PUt79dD9MCZ5/Ae3fm7B2ST8ai8RXW0OToI63NfeUxJn5AHeJAfAQIDAQAB
o1MwUTAdBgNVHQ4EFgQU8A73Ay/YOz2vLvTPwfptk48pndQwHwYDVR0jBBgwFoAU
8A73Ay/YOz2vLvTPwfptk48pndQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAnOmCHWw5UAxJJwxzEW0KRx56qmVawJ6QJCEvBLMXqZuR+kR6Sw7b
WysDTqsD091GVSpvu76RXJLSH/BiP+HbmjPLtb5qb55XM+i7dcz9pIB505jovvC4
t+OA/JZtx/8OmtIhhF1Se2n6gj8dG1H0tuaKbW3E95K7pC59yyW0zKP08ensy2QD
MfggkSRenn4VoA91+jRMylnawn4jIUlWyvUsvturSVz2WP7NmlYTnlCcifyBuYqq
IQ1XIX6F1jjody+3I+8b2tBpaPuNXDAtfoEoUWZW0ToTfAi+6Li7IMjXRZ6wPVxU
aoKJ9jBURYeYzd/Zi2RPLpjt8TYPir8vKQ==
-----END CERTIFICATE-----

""".encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name


@fixture
def f_ca_certificate():
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            """
-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIUATUd1WliG6ETZqKP8EZyijG9xUIwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCdVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEQMA4GA1UE
CgwHUmVkIEhhdDEbMBkGA1UECwwSQ2xvdWQgRGlzdHJpYnV0aW9uMRYwFAYDVQQD
DA1wdWJ0b29scy1zaWduMB4XDTIzMDUyNTEyNDQwMloXDTI4MDUyMzEyNDQwMlow
azELMAkGA1UEBhMCdVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEQMA4GA1UECgwH
UmVkIEhhdDEbMBkGA1UECwwSQ2xvdWQgRGlzdHJpYnV0aW9uMRYwFAYDVQQDDA1w
dWJ0b29scy1zaWduMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2e8m
tgCPFummVobuc+IHdTHfdDVYnMYyp3+ZRrzc5yCYjRpeIoABzcI/aZza2kljHNKZ
yan6LnsdD45xuyhDVmgMHij7Luq0p8ibQAQvmf6kh1pMgFy3Mtsm+lwT99Bt8gNN
YUiahSkN+vZa3eswZTzu5z5RkztzZt4O9qzsdUR7tKPjB5OlvsZFyFnvgtnAByqh
bLpe/YHR/A79TWgzZFBt67/f4ghGHUtN+CPB6e+TLKQ9QRsOqZLhuMwlNsJSBc8k
duvaXYDU3w+GXMci7pWIk3HM2Z9m0AxizZe8ygz/wworSxC8CS2WwPil3W9ft4iT
LTxBoEtN2MQUTMyo9QIDAQABo1MwUTAdBgNVHQ4EFgQUD+IG9eOMO65c5BCgycdw
60t7z3owHwYDVR0jBBgwFoAUD+IG9eOMO65c5BCgycdw60t7z3owDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAsX9O5pnlmmXfm6Vx98bOp8o79g40
KTfi1KZg8M3wfWYGDhSpDqdJC/1IPdEWp8VWF68zymTVa5unXRPewwQ07SP5yn19
YFlQF7l9vSnVVt4/JRPB+ydBgSXoxK6b5zbEK8+3iqBuRGvp8u0rrn4ohEkserd+
tcKssr4IEdgeVNco+UStQrrIrf+KoPN147fKzwkaUZKj3ybVExHnilr4D+HB94jL
pH404Fud+v2NWjl7RSQnsMw+gCz6Sm3eU/aWC5L5ZOecawj01Qr60nv97eqc8tdG
TrXd8yRh0cI5wL5KnO4hL/kYwOOaKsMwEkNlmL2Io7DrhVgJUAWycqfHfA==
-----END CERTIFICATE-----""".encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name


@fixture
def f_config_msg_signer_missing():
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            f"""
msg_signer:
  messaging_brokers:
    - amqps://broker-01:5671
    - amqps://broker-02:5671
  messaging_cert_key: {f_client_certificate}
  messaging_ca_cert: ~/messaging/ca-cert.crt
  topic_listen_to: queue://Consumer.{{creator}}.{{task_id}}.Topic.sign.{{task_id}}
  environment: prod
  service: pubtools-sign
  timeout: 1
  retries: 3
  message_id_key: request_id
  log_level: debug""".encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name


@fixture
def f_environ():
    with patch.dict(os.environ, {}, clear=True) as patched:
        yield patched
