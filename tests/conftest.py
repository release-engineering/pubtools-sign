import collections
import json
import socket
import logging
from multiprocessing import Process
import threading
import tempfile
import uuid

from .conftest_msgsig import f_msg_signer  # noqa: F401


from proton import Endpoint
from proton.reactor import Container
import proton
from proton import Message

from pytest import fixture

from pubtools.sign.clients.msg import _MsgClient


LOG = logging.getLogger("pubtools.sign.signers.radas")


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
        LOG.debug("BROKER on start", self.url)
        self.acceptor = event.container.listen(self.url)

    def _queue(self, address):
        if address not in self.queues:
            self.queues[address] = _Queue(address)
        return self.queues[address]

    def on_link_opening(self, event):
        LOG.debug(
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
        LOG.debug(">> BROKER On link closing", event)
        if event.link.is_sender:
            self._unsubscribe(event.link)

    def on_disconnected(self, event):
        LOG.debug(">> BROKER On disconnected", event)
        self.remove_stale_consumers(event.connection)

    def remove_stale_consumers(self, connection):
        link = connection.link_head(Endpoint.REMOTE_ACTIVE)
        LOG.debug("BROKER removing stale consumer", link)
        while link:
            if link.is_sender:
                self._unsubscribe(link)
            link = link.next(Endpoint.REMOTE_ACTIVE)

    def on_sendable(self, event):
        LOG.debug("BROKER on_sendable", event.link.source.address)
        self._queue(event.link.source.address).dispatch(event.link)

    def on_message(self, event):
        LOG.debug("BROKER ON MESSAGE", event.message)
        address = event.link.target.address
        if address is None:
            address = event.message.address
        LOG.debug("BROKER publish", address)
        self._queue(address).publish(event.message)


class _BrokenBroker(_Broker):
    def on_sendable(self, event):
        LOG.debug("BROKER on_sendable", event.link.source.address)
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
    LOG.debug("starting broker", f"localhost:{f_find_available_port}")
    broker = Container(_Broker(f"localhost:{f_find_available_port}"))
    p = Process(target=broker.run, args=())
    p.start()
    yield (broker, f_find_available_port)
    LOG.debug("destroying qpid broker")
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
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxcdD7r4IdRBrylZnLNmHMu4AHnt1ReE7LhvIJj9XF+akW9pa
Nc7rY+dHGZVd45VUsS37MuGRzkl4gUs/wAh+4PQK+dDGqDY5nJL7QNgw96s1129d
O09inhUBFp7tMfc+xAuNvDSrxRHthwnDIU2Jrbl6fzube07g0qx7geCqxti/g5cg
xuQBQpHSpaRgZ7cyNuiyww1vssbqqAG8UZHb4SpwaqjXnPp6Vd/yrU3bRKAtD5s5
+ZxCa/dUJfsqS3jxQMlfH0lbvxZ5yR+4pLRAISKLfdTDcN56XJ6IstNyusNhr/76
C/CfWUN+oe5yCWbRx4L5Q6lcpDq5DcbMNswEoQIDAQABAoIBAQCUDQWCW0jzcNZv
wdw8S54Udusp5ls0c1Ucv/lFAFdO8f2JMNwkuX+l6oRj11dQPQIIHBaV0RuXo5IM
n2racsGf3a+1sB513xmjZreko/GMBOMqIRhWhKebFLga2d9PbvjSQp/YCkmnHTOE
yb8DWAq/PEBBrDpIxRQxQKK355mPfW/OT2ds/C9Qeg/JtqX8N+OyPLzXNV1Ga1OE
GSMm0sv4TTyq5MrQDxx3C/MkjEwnDWkjV5kQhQHGJ+ehlXbkQqIAyfOLvWLIhu7t
e9mWRykqoBJUU1/eks9QohHtrgFHdbwwI1bsxxZCTirRXPpen0/SEWZ4jUkPB6MV
vdqGxJoRAoGBAP92liL2yMP/27Bi/hBjTpKMCZsH7Hl04RSrJZ6AzxPlglh2deCG
bpmffItcvUymLKMbIixo2mdQ0M3tqIFtA7k7M/ZGRNkYRI17J4kXoFa0qvX4zULl
csLDau0DMVTrCoXRlWmozp9Ony4kAp5xh7ygIFyE+rw2G48pxNkotOkNAoGBAMYx
pnZQn1eD4TLERy+s679LWupFLjlasaYhHM4mOZR36ABIjzbUSTe5qG8qXs2V0UXF
G8vaGp8LLIwWg304WWTcErJru6qrp08OlHHPqytuDrQcpqwMkAgA4/xezGJW9ljJ
wYWTEonWMlfKFP04kVg+CqATBnjVMCii5SjAmrzlAoGBANF8f1WgpbYEZDTamJj7
tnz6FQ5qiwJ2U/TM/AZkfmtEc4Tzb2p1EtErNchafmkSg9wk7fsY6LB8Vx3nW5z2
tmz5HX1A1khoXB7g9OS42SUA9ojKRBgta9RGx7IgQh3uuCxQV4PTh8yffm0p3nPr
iXGmpaL48VvRyvu1NtUVSnUpAoGAeyWEigVkTItsFRAyLyRhwxW+YswjgY2hzljK
viiwJFkwtWRgYDAdYluglZodF96cDp7/u3VEj0fxIQYoI1ks6md30pbwH4bSyWOE
xwbDE5Qp3K3kvgh8QgzTnA8HLZ9dKCQMc8PDhBOsajHtQr2wScUa8wV/QvssFkPI
4b5zJyUCgYEAra20VWtCDvtgVkEYEV3Taqp9lx8g4sW+E3O0/q5hUKjmyC1+xjwS
i4CYcqbOwSpEBJ6SInJ8qO9mr5H34IrNVMDqQFtQeUs14BubD5SL789jPzzYlPuf
WtgtGGUuxENK+DcU7zn6px9PqS0Rd8paC7CWrVZpn9fLusC8DAYNyG8=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUTTW9wgsEcsPa+nC9LNIY2NQHs/gwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCdVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEQMA4GA1UE
CgwHUmVkIEhhdDEbMBkGA1UECwwSQ2xvdWQgRGlzdHJpYnV0aW9uMRYwFAYDVQQD
DA1wdWJ0b29scy1zaWduMB4XDTIzMDUyNTEyNDQwNVoXDTI1MDgyNzEyNDQwNVow
cDELMAkGA1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEQMA4GA1UECgwH
UmVkIEhhdDEbMBkGA1UECwwSQ2xvdWQgRGlzdHJpYnV0aW9uMRswGQYDVQQDDBJw
dWJ0b29scy1zaWduLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDFx0Puvgh1EGvKVmcs2Ycy7gAee3VF4TsuG8gmP1cX5qRb2lo1zutj50cZlV3j
lVSxLfsy4ZHOSXiBSz/ACH7g9Ar50MaoNjmckvtA2DD3qzXXb107T2KeFQEWnu0x
9z7EC428NKvFEe2HCcMhTYmtuXp/O5t7TuDSrHuB4KrG2L+DlyDG5AFCkdKlpGBn
tzI26LLDDW+yxuqoAbxRkdvhKnBqqNec+npV3/KtTdtEoC0Pmzn5nEJr91Ql+ypL
ePFAyV8fSVu/FnnJH7iktEAhIot91MNw3npcnoiy03K6w2Gv/voL8J9ZQ36h7nIJ
ZtHHgvlDqVykOrkNxsw2zAShAgMBAAGjVTBTMB8GA1UdIwQYMBaAFA/iBvXjjDuu
XOQQoMnHcOtLe896MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMBgGA1UdEQQRMA+C
DWhlbGxmaXNoLnRlc3QwDQYJKoZIhvcNAQELBQADggEBAMpT7zdPkO4gb3tn74Nb
aFIhRDr4sQorpMlxRYQZSKV5qjvZ364bHaig380iQMwVs2H09z6IpO/8eXbrtlaD
z3QH2bt+yofk+JbWjQky7fKB1ZXvpugcNMTgr2OuupqPIkHaE4N+lZmaasMDY3+i
+1F5U/0EaNYuFt7Tv6uS9cqkbUuvm9Elm71arkDSrdOycTXGmm+DB8XnAGnQpNWQ
L3WmvVmWzvgjYOxvef2nNE3SeM3+/ZDCNYIJGC3KS/pOdshF95Xy00mkXv+Z0wAL
iuT88ZskJ2WDrduvxxKPSFUZ1ncZMsRAcNp8B0+JeR9Q30TGJCMNqJ3jg4u8Pvod
lq4=
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
