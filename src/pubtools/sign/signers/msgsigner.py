from __future__ import annotations

import base64
from dataclasses import field, dataclass, asdict
import enum
import json
import logging
from typing import cast, Dict, List, ClassVar, Any, Optional, Type, Tuple
from typing_extensions import Self
import uuid
import os
import sys

from OpenSSL import crypto
import click

from . import Signer
from ..operations.base import SignOperation
from ..operations import ClearSignOperation, ContainerSignOperation, BlobSignOperation
from ..results.signing_results import SigningResults
from ..results import ClearSignResult, ContainerSignResult, BlobSignResult
from ..results import SignerResults
from ..exceptions import UnsupportedOperation
from ..clients.msg_send_client import SendClient
from ..clients.msg_recv_client import RecvClient, RecvThread
from ..models.msg import MsgMessage, MsgError
from ..conf.conf import load_config, CONFIG_PATHS
from ..utils import (
    set_log_level,
    sanitize_log_level,
    isodate_now,
    _get_config_file,
    run_in_parallel,
    FData,
)

from ..clients.kafka_send_client import KafkaSendClient
from ..clients.kafka_recv_client import KafkaRecvClient, KafkaRecvThread
from ..models.kafka import KafkaMessage, KafkaError


LOG = logging.getLogger("pubtools.sign.signers.msgsigner")
LOG.setLevel(logging.INFO)


class SignRequestType(str, enum.Enum):
    """Sign request type enum."""

    CONTAINER = "container_signature"
    CLEARSIGN = "clearsign_signature"
    GPGSIGN = "gpg_signature"
    BATCH = "batch"


@dataclass()
class MsgSignerResults(SignerResults):
    """MsgSignerResults model."""

    status: str
    error_message: str

    def to_dict(self: SignerResults) -> Dict[Any, Any]:
        """Return dict representation of MsgSignerResults model."""
        return {"status": self.status, "error_message": self.error_message}

    @classmethod
    def doc_arguments(cls: Type[Self]) -> Dict[str, Any]:
        """Return dictionary with result description of SignerResults."""
        doc_arguments = {
            "signer_result": {
                "type": "dict",
                "description": "Signing result status.",
                "returned": "always",
                "sample": {"status": "ok", "error_message": ""},
            }
        }

        return doc_arguments


@dataclass()
class MsgSigner(Signer):
    """Messaging signer class."""

    messaging_brokers: List[str] = field(
        init=False,
        metadata={
            "description": "List of brokers URLS",
            "sample": [
                "amqps://broker-01:5671",
                "amqps://broker-02:5671",
            ],
        },
    )
    messaging_cert_key: str = field(
        init=False,
        metadata={
            "description": "Client certificate + key for messaging authorization",
            "sample": "~/messaging/cert.pem",
        },
    )
    messaging_ca_cert: str = field(
        init=False,
        metadata={"description": "Messaging CA certificate", "sample": "~/messaging/ca_cert.crt"},
    )
    topic_send_to: str = field(
        init=False,
        metadata={
            "description": "Topic where to send the messages",
            "sample": "topic://Topic.sign",
        },
    )
    topic_listen_to: str = field(
        init=False,
        metadata={
            "description": "Topic where to listen for replies",
            "sample": "queue://Consumer.{{creator}}.{{task_id}}.Topic.sign.{{task_id}}",
        },
    )
    creator: str = field(
        init=False,
        metadata={
            "description": "Identification of creator of signing request",
            "sample": "pubtools-sign",
        },
    )
    environment: str = field(
        init=False,
        metadata={"description": "Environment indetification in sent messages", "sample": "prod"},
    )
    service: str = field(
        init=False, metadata={"description": "Service identificator", "sample": "pubtools-sign"}
    )
    timeout: int = field(
        init=False,
        default=60,
        metadata={"description": "Timeout for messaging receive", "sample": 1},
    )
    retries: int = field(
        init=False,
        default=3,
        metadata={"description": "Retries for messaging receive", "sample": 3},
    )
    send_retries: int = field(
        init=False,
        default=2,
        metadata={"description": "Retries for messaging send+receive", "sample": 2},
    )
    message_id_key: str = field(
        init=False,
        metadata={
            "description": "Attribute name in message body which should be used as message id",
            "sample": "123",
        },
    )
    key_aliases: Dict[str, str] = field(
        init=False,
        metadata={
            "description": "Aliases for signing keys",
            "sample": "{'production':'abcde1245'}",
        },
        default_factory=dict,
    )

    log_level: str = field(init=False, metadata={"description": "Log level", "sample": "debug"})
    task_id_attribute: str = field(
        init=False,
        default="pub_task_id",
        metadata={
            "description": "Attribute used to custom identification of signing request",
            "sample": "task_id",
        },
    )

    kafka_enabled: bool = field(
        init=False,
        default=False,
        metadata={
            "description": "Kafka messaging enabled (auto-set when kafka config is present)",
            "sample": False,
        },
    )
    kafka_bootstrap_servers: List[str] = field(
        init=False,
        default_factory=list,
        metadata={
            "description": "List of Kafka broker URLs",
            "sample": ["kafka-01:9092", "kafka-02:9092"],
        },
    )
    kafka_username: str = field(
        init=False,
        default="",
        metadata={
            "description": "Kafka username for SASL authentication",
            "sample": "kafka-user",
        },
    )
    kafka_password: str = field(
        init=False,
        default="",
        metadata={
            "description": "Kafka password for SASL authentication",
            "sample": "kafka-password",
        },
    )
    kafka_topic_send_to: str = field(
        init=False,
        default="",
        metadata={
            "description": "Kafka topic where to send the messages",
            "sample": "signing-requests",
        },
    )
    kafka_topic_listen_to: str = field(
        init=False,
        default="",
        metadata={
            "description": "Kafka topic where to listen for replies",
            "sample": "signing-responses",
        },
    )
    kafka_group_id: str = field(
        init=False,
        default="pubtools-sign",
        metadata={
            "description": "Kafka consumer group ID",
            "sample": "pubtools-sign-group",
        },
    )
    kafka_retries: int = field(
        init=False,
        default=3,
        metadata={
            "description": "Number of retries for Kafka operations",
            "sample": 3,
        },
    )
    kafka_fallback_base: float = field(
        init=False,
        default=1.0,
        metadata={
            "description": "Base time for exponential backoff in Kafka retries",
            "sample": 1.0,
        },
    )
    kafka_fallback_factor: float = field(
        init=False,
        default=2.0,
        metadata={
            "description": "Multiplier for exponential backoff in Kafka retries",
            "sample": 2.0,
        },
    )

    SUPPORTED_OPERATIONS: ClassVar[List[Type[SignOperation]]] = [
        ContainerSignOperation,
        ClearSignOperation,
        BlobSignOperation,
    ]

    _signer_config_key: str = "msg_signer"

    def _construct_signing_message(
        self: MsgSigner,
        claim: str,
        signing_key: str,
        repo: str,
        signing_key_name: str = "",
        extra_attrs: Optional[Dict[str, Any]] = None,
        sig_type: SignRequestType = SignRequestType.CONTAINER,
    ) -> dict[str, Any]:
        if sig_type == SignRequestType.CONTAINER:
            data_attr = "claim_file"
        elif sig_type == SignRequestType.GPGSIGN:
            data_attr = "artifact"
        else:
            data_attr = "data"
        _extra_attrs = extra_attrs or {}
        message = {
            "sig_key_id": signing_key[-8:],
            data_attr: claim,
            "request_id": str(uuid.uuid4()),
            "created": isodate_now(),
            "requested_by": self.creator,
            "repo": repo,
        }
        if signing_key_name:
            message["sig_keyname"] = signing_key_name
        message.update(_extra_attrs)
        return message

    def _construct_headers(
        self: MsgSigner, sig_type: SignRequestType, extra_attrs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        headers = {
            "service": self.service,
            "environment": self.environment,
            "owner_id": self.creator,
            "mtype": sig_type.value,
            "source": "metadata",
        }
        if extra_attrs:
            headers.update(extra_attrs)
        return headers

    def _create_msg_messages(
        self: MsgSigner,
        data: str,
        repo: str,
        operation: SignOperation,
        sig_type: SignRequestType,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> List[MsgMessage]:
        messages = []
        for _signing_key, _signing_key_name in zip(
            operation.signing_keys,
            operation.signing_key_names or [""] * len(operation.signing_keys),
        ):
            if _signing_key in self.key_aliases:
                signing_key = self.key_aliases[_signing_key]
                LOG.info(f"Using signing key alias {signing_key} for {_signing_key}")
            else:
                signing_key = _signing_key
            ret = MsgMessage(
                headers=self._construct_headers(sig_type, extra_attrs=extra_attrs),
                body=self._construct_signing_message(
                    data,
                    signing_key,
                    repo,
                    signing_key_name=_signing_key_name,
                    extra_attrs=extra_attrs,
                    sig_type=sig_type,
                ),
                address=self.topic_send_to.format(
                    **dict(list(asdict(self).items()) + list(asdict(operation).items()))
                ),
                ttl=self.timeout * self.retries,
            )
            LOG.debug(f"Construted message with request_id {ret.body['request_id']}")
            messages.append(ret)
        return messages

    def load_config(self: MsgSigner, config_data: Dict[str, Any]) -> None:
        """Load configuration of messaging signer.

        Arguments:
            config_data (dict): configuration data to load

        The config file determines which transport to use based on which section is present.
        Only one transport can be configured per config file.
        """
        umb_config = config_data.get("msg_signer")
        kafka_config = config_data.get("kafka_signer")

        if umb_config and kafka_config:
            raise ValueError("Config file cannot have both msg_signer and kafka_signer. Choose one.")

        if not umb_config and not kafka_config:
            raise ValueError("Config file must have either msg_signer or kafka_signer")

        if umb_config:
            self.messaging_brokers = umb_config["messaging_brokers"]
            self.messaging_cert_key = os.path.expanduser(umb_config["messaging_cert_key"])
            self.messaging_ca_cert = os.path.expanduser(umb_config["messaging_ca_cert"])
            self.topic_send_to = umb_config["topic_send_to"]
            self.topic_listen_to = umb_config["topic_listen_to"]
            self.environment = umb_config["environment"]
            self.service = umb_config["service"]
            self.message_id_key = umb_config["message_id_key"]
            self.retries = umb_config["retries"]
            self.send_retries = umb_config["send_retries"]
            self.log_level = umb_config["log_level"]
            self.timeout = umb_config["timeout"]
            self.creator = self._get_cert_subject_cn()
            self.key_aliases = umb_config.get("key_aliases", {})
            self.task_id_attribute = umb_config.get("task_id_attribute", "pub_task_id")
            self.kafka_enabled = False
        else:
            self.messaging_brokers = []
            self.messaging_cert_key = ""
            self.messaging_ca_cert = ""
            self.topic_send_to = ""
            self.topic_listen_to = ""
            self.environment = kafka_config.get("environment", "prod")
            self.service = kafka_config.get("service", "pubtools-sign")
            self.message_id_key = "request_id"
            self.retries = kafka_config.get("retries", 3)
            self.send_retries = kafka_config.get("send_retries", 2)
            self.log_level = "INFO"
            self.timeout = kafka_config.get("timeout", 600)
            self.creator = kafka_config.get("creator", "pubtools-sign")
            self.key_aliases = {}
            self.task_id_attribute = "pub_task_id"
            self._load_kafka_config(config_data)

    def _load_kafka_config(self: MsgSigner, config_data: Dict[str, Any]) -> None:
        """Load Kafka configuration from config data.

        Kafka is automatically enabled when kafka_signer section is present
        with required fields: bootstrap_servers, topic_send_to, topic_listen_to.

        Arguments:
            config_data (dict): configuration data to load
        """
        kafka_config = config_data.get("kafka_signer")

        if not kafka_config:
            self.kafka_enabled = False
            return

        self.kafka_bootstrap_servers = kafka_config.get("bootstrap_servers", [])
        self.kafka_username = kafka_config.get("username", "")
        self.kafka_password = kafka_config.get("password", "")
        self.kafka_topic_send_to = kafka_config.get("topic_send_to", "")
        self.kafka_topic_listen_to = kafka_config.get("topic_listen_to", "")
        self.kafka_group_id = kafka_config.get("group_id", "pubtools-sign")
        self.kafka_retries = kafka_config.get("retries", 3)
        self.kafka_fallback_base = kafka_config.get("fallback_base", 1.0)
        self.kafka_fallback_factor = kafka_config.get("fallback_factor", 2.0)

        missing = []
        if not self.kafka_bootstrap_servers:
            missing.append("bootstrap_servers")
        if not self.kafka_topic_send_to:
            missing.append("topic_send_to")
        if not self.kafka_topic_listen_to:
            missing.append("topic_listen_to")

        if missing:
            LOG.debug(
                "Kafka config section present but missing required fields: %s. "
                "Kafka messaging will not be enabled.",
                ", ".join(missing),
            )
            self.kafka_enabled = False
        else:
            self.kafka_enabled = True
            LOG.info(
                "Kafka messaging enabled. Brokers: %s, Send topic: %s, Recv topic: %s",
                self.kafka_bootstrap_servers,
                self.kafka_topic_send_to,
                self.kafka_topic_listen_to,
            )

    def _get_cert_subject_cn(self) -> str:
        x509 = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(os.path.expanduser(self.messaging_cert_key)).read().encode()
        )
        return x509.get_subject().CN or x509.get_subject().UID  # type: ignore[attr-defined]

    def operations(self: MsgSigner) -> List[Type[SignOperation]]:
        """Return list of supported signing operation classes.

        Returns:
            List[Type[SignOperation]]: list of supported operations
        """
        return self.SUPPORTED_OPERATIONS

    def sign(self: MsgSigner, operation: SignOperation) -> SigningResults:
        """Run signing operation.

        Args:
            operation (SignOperation): signing operation

        Returns:
            SigningResults: results of the signing operation
        """
        if isinstance(operation, ClearSignOperation):
            return self.clear_sign(operation)
        elif isinstance(operation, ContainerSignOperation):
            return self.container_sign(operation)
        elif isinstance(operation, BlobSignOperation):
            return self.blob_sign(operation)
        else:
            raise UnsupportedOperation(operation)

    def _convert_to_kafka_messages(
        self, messages: List[MsgMessage], operation: SignOperation
    ) -> List["KafkaMessage"]:
        """Convert MsgMessage objects to KafkaMessage objects.

        Args:
            messages: List of MsgMessage objects.
            operation: The signing operation (for topic formatting).

        Returns:
            List of KafkaMessage objects.
        """
        kafka_messages = []
        topic = self.kafka_topic_send_to.format(
            **dict(list(asdict(self).items()) + list(asdict(operation).items()))
        )
        for msg in messages:
            kafka_msg = KafkaMessage(
                headers=dict(msg.headers),
                topic=topic,
                body=dict(msg.body),
                ttl=msg.ttl,
            )
            kafka_messages.append(kafka_msg)
        return kafka_messages

    def _kafka_send_and_receive(
        self, messages: List[MsgMessage], operation: SignOperation
    ) -> Tuple[Dict[Any, Any], List["KafkaError"], int]:
        """Send messages to Kafka and receive responses.

        This method handles Kafka messaging when Kafka transport is configured.

        Args:
            messages: List of messages to send.
            operation: The signing operation.

        Returns:
            Tuple of (received messages dict, errors list, return code).
        """
        if not self.kafka_enabled:
            return {}, [], 0

        kafka_messages = self._convert_to_kafka_messages(messages, operation)
        received: Dict[Any, Any] = {}
        errors: List[KafkaError] = []

        for i in range(self.send_retries):
            message_ids = [msg.body["request_id"] for msg in kafka_messages]
            LOG.debug("KAFKA: %d messages to send", len(kafka_messages))

            listen_topic = self.kafka_topic_listen_to.format(
                **dict(list(asdict(self).items()) + list(asdict(operation).items()))
            )

            kafka_recvc = KafkaRecvClient(
                uid=f"kafka-{i}",
                message_ids=message_ids,
                topic=listen_topic,
                id_key=self.message_id_key,
                bootstrap_servers=self.kafka_bootstrap_servers,
                username=self.kafka_username,
                password=self.kafka_password,
                group_id=self.kafka_group_id,
                timeout=self.timeout,
                retries=self.retries,
                errors=errors,
                received=received,
            )
            kafka_recvt = KafkaRecvThread(kafka_recvc)
            kafka_recvt.start()

            send_errors = KafkaSendClient(
                messages=kafka_messages,
                bootstrap_servers=self.kafka_bootstrap_servers,
                username=self.kafka_username,
                password=self.kafka_password,
                retries=self.kafka_retries,
                errors=errors,
                fallback_base=self.kafka_fallback_base,
                fallback_factor=self.kafka_fallback_factor,
            ).run()

            if send_errors:
                LOG.warning("KAFKA: Send errors occurred: %s", send_errors)
                kafka_recvc.close()
                return received, send_errors, 1

            kafka_recvt.join()
            kafka_recvt.stop()

            for x in range(self.retries - 1):
                errors = kafka_recvc.get_errors()
                if errors and errors[0].name == "MessagingTimeout":
                    LOG.info("KAFKA: RETRYING %s", x)
                    _messages = []
                    for msg in kafka_messages:
                        if msg.body["request_id"] not in received:
                            _messages.append(msg)
                    if x != self.retries - 1:
                        errors.pop(0)
                    kafka_messages = _messages
                    message_ids = [msg.body["request_id"] for msg in kafka_messages]

                    LOG.info("KAFKA: Retrying recv")
                    kafka_recvc = KafkaRecvClient(
                        uid=f"kafka-{i}-{x}",
                        message_ids=message_ids,
                        topic=listen_topic,
                        id_key=self.message_id_key,
                        bootstrap_servers=self.kafka_bootstrap_servers,
                        username=self.kafka_username,
                        password=self.kafka_password,
                        group_id=self.kafka_group_id,
                        timeout=self.timeout,
                        retries=self.retries,
                        errors=errors,
                        received=received,
                    )
                    kafka_recvt = KafkaRecvThread(kafka_recvc)
                    kafka_recvt.start()
                    kafka_recvt.join()
                elif not errors:
                    break

            errors = kafka_recvc.get_errors()
            if not errors:
                break

        return kafka_recvc.recv, kafka_recvc.get_errors(), 0 if not kafka_recvc.get_errors() else 1

    def _umb_send_and_receive(
        self, messages: List[Any], operation: SignOperation
    ) -> Tuple[Dict[int, Any], List[MsgError], int]:
        received: Dict[int, Any] = {}
        errors: List[MsgError] = []

        for i in range(self.send_retries):
            message_ids = [message.body["request_id"] for message in messages]
            LOG.debug(f"{len(messages)} messages to send")
            recvc = RecvClient(
                uid=str(i),
                message_ids=message_ids,
                topic=self.topic_listen_to.format(
                    **dict(list(asdict(self).items()) + list(asdict(operation).items()))
                ),
                id_key=self.message_id_key,
                broker_urls=self.messaging_brokers,
                cert=self.messaging_cert_key,
                ca_cert=self.messaging_ca_cert,
                timeout=self.timeout,
                retries=self.retries,
                errors=errors,
                received=received,
            )
            recvt = RecvThread(recvc)
            recvt.start()

            errors = SendClient(
                messages=messages,
                broker_urls=self.messaging_brokers,
                cert=self.messaging_cert_key,
                ca_cert=self.messaging_ca_cert,
                retries=self.retries,
                errors=errors,
            ).run()
            # check sender errors
            if errors:
                # signer_results.status = "error"
                # for error in errors:
                #     signer_results.error_message += f"{error.name} : {error.description}\n"
                recvt.stop()
                recvt.join(timeout=5)
                return received, errors, 1

            # wait for receiver to finish
            recvt.join()
            recvt.stop()

            # check receiver errors
            for x in range(self.retries - 1):
                errors = recvc.get_errors()
                if errors and errors[0].name == "MessagingTimeout":
                    LOG.info("RETRYING %s", x)
                    _messages = []
                    for message in messages:
                        if message.body["request_id"] not in received:
                            _messages.append(message)
                    if x != self.retries - 1:
                        errors.pop(0)
                    messages = _messages
                    message_ids = [message.body["request_id"] for message in messages]

                    LOG.info("Retrying recv")
                    recvc = RecvClient(
                        uid=str(i) + "-" + str(x),
                        message_ids=message_ids,
                        topic=self.topic_listen_to.format(
                            **dict(list(asdict(self).items()) + list(asdict(operation).items()))
                        ),
                        id_key=self.message_id_key,
                        broker_urls=self.messaging_brokers,
                        cert=self.messaging_cert_key,
                        ca_cert=self.messaging_ca_cert,
                        timeout=self.timeout,
                        retries=self.retries,
                        errors=errors,
                        received=received,
                    )
                    recvt = RecvThread(recvc)
                    recvt.start()
                    recvt.join()
                elif not errors:
                    break
            errors = recvc.get_errors()
            if not errors:
                break

        return recvc.recv, recvc.get_errors(), 0 if not recvc.get_errors() else 1

    def _send_and_receive(
        self, messages: List[Any], operation: SignOperation
    ) -> Tuple[Dict[int, Any], List[MsgError], int]:
        """Send and receive messages via the configured transport."""
        umb_configured = bool(self.messaging_brokers)
        kafka_configured = self.kafka_enabled

        if not umb_configured and not kafka_configured:
            raise ValueError("No messaging transport configured")

        if kafka_configured:
            LOG.info("Using Kafka transport")
            return self._kafka_send_and_receive(messages, operation)
        else:
            LOG.info("Using UMB transport")
            return self._umb_send_and_receive(messages, operation)

    def clear_sign(self: MsgSigner, operation: ClearSignOperation) -> SigningResults:
        """Run the clearsign operation.

        Args:
            operation (ClearSignOperation): signing operation

        Returns:
            SigningResults: results of the signing operation
        """
        set_log_level(LOG, self.log_level)
        messages = []
        message_to_data = {}
        for in_data in operation.inputs:
            _key_messages = self._create_msg_messages(
                base64.b64encode(in_data.encode("latin1")).decode("latin-1"),
                operation.repo,
                operation,
                SignRequestType.CLEARSIGN,
                extra_attrs={self.task_id_attribute: operation.task_id},
            )
            for message in _key_messages:
                message_to_data[message.body["request_id"]] = message
                messages.append(message)

        all_messages = [x for x in messages]

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = ClearSignResult(
            signing_keys=operation.signing_keys, outputs=[""] * len(operation.inputs)
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )
        errors: List[MsgError] = []
        received: Dict[int, Any] = {}
        # LOG.info("errors " + str(errors))

        received, errors, retcode = self._send_and_receive(messages, operation)

        if errors and retcode != 0:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        operation_result = ClearSignResult(
            signing_keys=operation.signing_keys, outputs=[""] * len(all_messages)
        )

        for recv_id, _received in received.items():
            operation_result.outputs[all_messages.index(message_to_data[recv_id])] = _received
        signing_results.operation_result = operation_result
        return signing_results

    @staticmethod
    def create_manifest_claim_message(digest: str, reference: str) -> str:
        """Create manifest claim for container signing.

        See below for the specification for the manifest claim that is created here
        https://github.com/containers/image/blob/main/docs/containers-signature.5.md#json-data-format

        Arguments:
            digest (str): The digest of the container image manifest.
            reference (str): The reference of the container image.

        Returns:
            str: The base64 encoded manifest claim.
        """
        manifest_claim = {
            "critical": {
                "type": "atomic container signature",
                "image": {"docker-manifest-digest": digest},
                "identity": {"docker-reference": reference},
            },
            "optional": {"creator": "pubtools-sign"},
        }
        return base64.b64encode(json.dumps(manifest_claim).encode("latin1")).decode("latin1")

    def _prepare_messages(self, operation: ContainerSignOperation) -> List[List[MsgMessage]]:
        fargs = []
        for digest, reference in zip(operation.digests, operation.references):
            repo = reference.split("/", 1)[1].split(":")[0]
            fargs.append(
                FData(
                    args=[
                        self.create_manifest_claim_message(digest=digest, reference=reference),
                        repo,
                        operation,
                        SignRequestType.CONTAINER,
                    ],
                    kwargs={
                        "extra_attrs": {
                            self.task_id_attribute: operation.task_id,
                            "manifest_digest": digest,
                        }
                    },
                )
            )
        ret = run_in_parallel(self._create_msg_messages, fargs)
        return list(ret.values())

    def container_sign(self: MsgSigner, operation: ContainerSignOperation) -> SigningResults:
        """Run container signing operation.

        Arguments:
            operation (ContainerSignOperation): signing operation

        Results:
            SigningResults: results of the signing operation
        """
        set_log_level(LOG, self.log_level)
        messages = []
        message_to_data = {}
        if len(operation.digests) != len(operation.references):
            raise ValueError("Digests must pairs with references")

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = ContainerSignResult(
            signing_keys=operation.signing_keys, results=[""] * len(operation.digests), failed=False
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )

        LOG.info(f"Container sign operation for {len(operation.digests)}")

        ret = self._prepare_messages(operation)

        for _key_messages in ret:
            for message in _key_messages:
                message_to_data[message.body["request_id"]] = message
                messages.append(message)

        all_messages = [x for x in messages]
        operation_result = ContainerSignResult(
            signing_keys=operation.signing_keys, results=[""] * len(all_messages), failed=False
        )

        LOG.info(f"Signing {len(all_messages)} requests")

        LOG.debug(f"{len(messages)} messages to send")

        errors: List[MsgError] = []
        received: Dict[int, Any] = {}
        LOG.info(
            "Starting signing process. Retries (send: %d, recv:%d), timeout: %d",
            self.send_retries,
            self.retries,
            self.timeout,
        )

        received, errors, retcode = self._send_and_receive(messages, operation)

        if errors and retcode != 0:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        for recv_id, _received in received.items():
            operation_result.failed = True if _received[0]["msg"]["errors"] else False
            operation_result.results[all_messages.index(message_to_data[recv_id])] = _received

        signing_results.operation_result = operation_result
        return signing_results

    def blob_sign(self: MsgSigner, operation: BlobSignOperation) -> SigningResults:
        """Run blob signing operation.

        Arguments:
            operation (BlobSignOperation): signing operation

        Results:
            SigningResults: results of the signing operation
        """
        set_log_level(LOG, self.log_level)
        messages = []
        message_to_data = {}
        for blob in operation.blobs:
            _key_messages = self._create_msg_messages(
                blob,
                "",
                operation,
                SignRequestType.GPGSIGN,
                extra_attrs={self.task_id_attribute: operation.task_id},
            )
            for message in _key_messages:
                message_to_data[message.body["request_id"]] = message
                messages.append(message)

        all_messages = [x for x in messages]

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = BlobSignResult(
            signing_keys=operation.signing_keys, results=[""] * len(all_messages), failed=False
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )
        errors: List[MsgError] = []
        received: Dict[int, Any] = {}
        # LOG.info("errors " + str(errors))

        received, errors, retcode = self._send_and_receive(messages, operation)

        if errors and retcode != 0:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        for recv_id, _received in received.items():
            operation_result.failed = True if _received[0]["msg"]["errors"] else False
            operation_result.results[all_messages.index(message_to_data[recv_id])] = _received

        signing_results.operation_result = operation_result
        return signing_results


class MsgBatchSigner(MsgSigner):
    """Messaging batch signer class."""

    _signer_config_key: str = "msg_batch_signer"

    chunk_size: int = field(
        init=False,
        metadata={
            "description": "Identify how many signing claims should be send in one message",
            "sample": 10,
        },
    )

    SUPPORTED_OPERATIONS: ClassVar[List[Type[SignOperation]]] = [
        ContainerSignOperation,
    ]

    def _construct_signing_batch_message(
        self: Self,
        claims: List[str],
        signing_keys: List[str],
        repo: str,
        signing_key_names: List[str] = [],
        extra_attrs: Optional[Dict[str, Any]] = None,
        sig_type: str = SignRequestType.BATCH,
    ) -> dict[str, Any]:
        data_attr = "claims" if sig_type == SignRequestType.BATCH else "data"
        _extra_attrs = extra_attrs or {}
        processed_claims = [
            {
                "claim_file": claim,
                "sig_keynames": signing_key_names,
                "sig_key_ids": [sig_key[-8:] for sig_key in signing_keys],
                "manifest_digest": digest,
                "repo": repo,
            }
            for claim, digest in zip(claims, _extra_attrs.get("manifest_digest", ""))
        ]
        message = {
            data_attr: processed_claims,
            "request_id": str(uuid.uuid4()),
            "created": isodate_now(),
            "requested_by": self.creator,
        }
        _extra_attrs.pop("manifest_digest", None)
        message.update(_extra_attrs)
        return message

    def _create_msg_batch_message(
        self: Self,
        data: List[str],
        repo: str,
        operation: SignOperation,
        sig_type: SignRequestType,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> List[MsgMessage]:
        messages = []
        signing_keys = []
        for _signing_key in operation.signing_keys:
            if _signing_key in self.key_aliases:
                signing_keys.append(self.key_aliases[_signing_key])
                LOG.info(
                    f"Using signing key alias {self.key_aliases[_signing_key]} for {_signing_key}"
                )
            else:
                signing_keys.append(_signing_key)

        extra_attrs = extra_attrs or {}
        extra_attrs_headers = extra_attrs.copy()
        extra_attrs_headers.pop("manifest_digest")
        headers = self._construct_headers(sig_type, extra_attrs=extra_attrs_headers)
        ret = MsgMessage(
            headers=headers,
            body=self._construct_signing_batch_message(
                data,
                signing_keys,
                repo,
                signing_key_names=(
                    operation.signing_key_names
                    if operation.signing_key_names
                    else ["" * len(signing_keys)]
                ),
                extra_attrs=extra_attrs,
                sig_type=sig_type.value,
            ),
            address=self.topic_send_to.format(
                **dict(list(asdict(self).items()) + list(asdict(operation).items()))
            ),
            ttl=self.timeout * self.retries,
        )
        LOG.debug(f"Construted message with request_id {ret.body['request_id']}")
        messages.append(ret)
        return messages

    def _prepare_messages(self: Self, operation: ContainerSignOperation) -> List[List[MsgMessage]]:
        messages: List[List[MsgMessage]] = []
        repo_groups: Dict[str, Dict[str, List[str]]] = {}
        for digest, reference in zip(operation.digests, operation.references):
            repo = reference.split("/", 1)[1].split(":")[0]
            if repo not in repo_groups:
                repo_groups[repo] = cast(dict[str, list[str]], {"digests": [], "references": []})
            repo_groups[repo]["digests"].append(digest)
            repo_groups[repo]["references"].append(reference)

        batch_data: List[FData] = []
        for repo, group in repo_groups.items():
            claims = []
            digests = []

            for digest, reference in zip(group["digests"], group["references"]):
                claims.append(
                    self.create_manifest_claim_message(digest=digest, reference=reference)
                )
                digests.append(digest)
                if len(claims) >= self.chunk_size:
                    fdata = FData(
                        args=[claims, repo, operation, SignRequestType.BATCH],
                        kwargs={
                            "extra_attrs": {
                                "pipeline_run_id": str(operation.task_id),
                                "manifest_digest": digests,
                            }
                        },
                    )
                    batch_data.append(fdata)
                    claims = []
                    digests = []
            if claims:
                fdata = FData(
                    args=[claims, repo, operation, SignRequestType.BATCH],
                    kwargs={
                        "extra_attrs": {
                            "pipeline_run_id": str(operation.task_id),
                            "manifest_digest": digests,
                        }
                    },
                )
                batch_data.append(fdata)

        ret = run_in_parallel(self._create_msg_batch_message, batch_data)
        messages.extend(list(ret.values()))
        return messages

    def load_config(self: Self, config_data: Dict[str, Any]) -> None:
        """Load configuration of messaging signer.

        Arguments:
            config_data (dict): configuration data to load

        The config file determines which transport to use based on which section is present.
        Only one transport can be configured per config file.
        """
        umb_config = config_data.get("msg_batch_signer")
        kafka_config = config_data.get("kafka_batch_signer") or config_data.get("kafka_signer")

        if umb_config and kafka_config:
            raise ValueError("Config file cannot have both msg_batch_signer and kafka_batch_signer. Choose one.")

        if not umb_config and not kafka_config:
            raise ValueError("Config file must have either msg_batch_signer or kafka_batch_signer")

        if umb_config:
            LOG.info("Loading msg_batch_signer configuration")
            self.messaging_brokers = umb_config["messaging_brokers"]
            self.messaging_cert_key = os.path.expanduser(umb_config["messaging_cert_key"])
            self.messaging_ca_cert = os.path.expanduser(umb_config["messaging_ca_cert"])
            self.topic_send_to = umb_config["topic_send_to"]
            self.topic_listen_to = umb_config["topic_listen_to"]
            self.environment = umb_config["environment"]
            self.service = umb_config["service"]
            self.message_id_key = umb_config["message_id_key"]
            self.retries = umb_config["retries"]
            self.send_retries = umb_config["send_retries"]
            self.log_level = umb_config["log_level"]
            self.timeout = umb_config["timeout"]
            self.creator = self._get_cert_subject_cn()
            self.key_aliases = umb_config.get("key_aliases", {})
            self.chunk_size = umb_config["chunk_size"]
            self.task_id_attribute = umb_config.get("task_id_attribute", "pub_task_id")
            self.kafka_enabled = False
        else:
            self.messaging_brokers = []
            self.messaging_cert_key = ""
            self.messaging_ca_cert = ""
            self.topic_send_to = ""
            self.topic_listen_to = ""
            self.environment = kafka_config.get("environment", "prod")
            self.service = kafka_config.get("service", "pubtools-sign")
            self.message_id_key = "request_id"
            self.retries = kafka_config.get("retries", 3)
            self.send_retries = kafka_config.get("send_retries", 2)
            self.log_level = "INFO"
            self.timeout = kafka_config.get("timeout", 600)
            self.creator = kafka_config.get("creator", "pubtools-sign")
            self.key_aliases = {}
            self.chunk_size = kafka_config.get("chunk_size", 100)
            self.task_id_attribute = "pub_task_id"
            self._load_kafka_config_batch(config_data)

    def _load_kafka_config_batch(self: Self, config_data: Dict[str, Any]) -> None:
        """Load Kafka configuration from config data for batch signer.

        Uses kafka_batch_signer if present, otherwise falls back to kafka_signer.
        Kafka is automatically enabled when required fields are present:
        bootstrap_servers, topic_send_to, topic_listen_to.

        Arguments:
            config_data (dict): configuration data to load
        """
        kafka_config = config_data.get("kafka_batch_signer") or config_data.get("kafka_signer")

        if not kafka_config:
            self.kafka_enabled = False
            return

        self.kafka_bootstrap_servers = kafka_config.get("bootstrap_servers", [])
        self.kafka_username = kafka_config.get("username", "")
        self.kafka_password = kafka_config.get("password", "")
        self.kafka_topic_send_to = kafka_config.get("topic_send_to", "")
        self.kafka_topic_listen_to = kafka_config.get("topic_listen_to", "")
        self.kafka_group_id = kafka_config.get("group_id", "pubtools-sign-batch")
        self.kafka_retries = kafka_config.get("retries", 3)
        self.kafka_fallback_base = kafka_config.get("fallback_base", 1.0)
        self.kafka_fallback_factor = kafka_config.get("fallback_factor", 2.0)

        missing = []
        if not self.kafka_bootstrap_servers:
            missing.append("bootstrap_servers")
        if not self.kafka_topic_send_to:
            missing.append("topic_send_to")
        if not self.kafka_topic_listen_to:
            missing.append("topic_listen_to")

        if missing:
            LOG.debug(
                "Kafka config section present but missing required fields: %s. "
                "Kafka messaging will not be enabled.",
                ", ".join(missing),
            )
            self.kafka_enabled = False
        else:
            self.kafka_enabled = True
            LOG.info(
                "Kafka messaging enabled for batch signer. "
                "Brokers: %s, Send topic: %s, Recv topic: %s",
                self.kafka_bootstrap_servers,
                self.kafka_topic_send_to,
                self.kafka_topic_listen_to,
            )


def msg_clear_sign(
    inputs: List[str],
    signing_keys: List[str] = [],
    task_id: str = "",
    config_file: str = "",
    repo: str = "",
    requester: str = "",
) -> Dict[str, Any]:
    """Run clearsign operation on provided inputs.

    Arguments:
        inputs (List[str]): List of input strings or file paths(when prefixed with '@') to sign.
        signing_key (str): 8 characters key fingerprint of key which should be used for signing.
        task_id (str): Task id identifier.
        config_file (str): Path to the pubtools-sign configuration file.
        repo (str): Repository reference.
        requester (str): Use this requester instead one from certificate file.

    Returns:
        Dict[str, Any]: Dictionary containing the signing results,
        operation results, operation details, and signing key.
    """
    msg_signer = MsgSigner()
    config = _get_config_file(config_file)
    msg_signer.load_config(load_config(os.path.expanduser(config)))
    if requester:
        msg_signer.creator = requester

    str_inputs = []
    for input_ in inputs:
        if input_.startswith("@"):
            str_inputs.append(open(input_.lstrip("@")).read())
        else:
            str_inputs.append(input_)
    operation = ClearSignOperation(
        inputs=str_inputs,
        signing_keys=signing_keys,
        task_id=task_id,
        repo=repo,
        requester=requester,
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": cast(ClearSignResult, signing_result.operation_result).outputs,
        "operation": signing_result.operation.to_dict(),
        "signing_keys": signing_result.operation_result.signing_keys,
    }


def msg_container_sign(
    signing_keys: List[str] = [],
    signing_key_names: List[str] = [],
    task_id: str = "",
    config_file: str = "",
    digest: list[str] = [],
    reference: list[str] = [],
    requester: str = "",
    signer_type: str = "single",
) -> Dict[str, Any]:
    """Run containersign operation with cli arguments."""
    if signer_type == "single":
        msg_signer = MsgSigner()
    elif signer_type == "batch":
        msg_signer = MsgBatchSigner()

    config = _get_config_file(config_file)
    msg_signer.load_config(load_config(os.path.expanduser(config)))
    if requester:
        msg_signer.creator = requester

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        signing_keys=signing_keys,
        signing_key_names=signing_key_names,
        task_id=task_id,
        requester=requester,
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.results,
        "operation": signing_result.operation.to_dict(),
        "signing_keys": signing_result.operation_result.signing_keys,
    }


def msg_blob_sign(
    signing_keys: List[str],
    signing_key_names: List[str],
    task_id: str,
    config_file: str,
    blob_files: List[str],
    requester: str = "",
    signer_type: str = "single",
) -> Dict[str, Any]:
    """Run blobsign operation with cli arguments."""
    if signer_type == "single":
        msg_signer = MsgSigner()
    elif signer_type == "batch":
        raise NotImplementedError("Batch signer does not support blob signing yet")

    config = _get_config_file(config_file)
    msg_signer.load_config(load_config(os.path.expanduser(config)))
    if requester:
        msg_signer.creator = requester

    blobs = []
    for blob_file in blob_files:
        with open(blob_file, "rb") as bf:
            blobs.append(base64.b64encode(bf.read()).decode("utf-8"))

    operation = BlobSignOperation(
        blobs=blobs,
        signing_keys=signing_keys,
        signing_key_names=signing_key_names,
        task_id=task_id,
        requester=requester,
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.results,
        "operation": signing_result.operation.to_dict(),
        "signing_keys": signing_result.operation_result.signing_keys,
    }


@click.command()
@click.option(
    "--signing-key",
    required=True,
    multiple=True,
    help="8 characters key fingerprint of key which should be used for signing or key alias",
)
@click.option("--task-id", required=True, help="Task id identifier (usually pub task-id)")
@click.option("--config-file", default=CONFIG_PATHS[0], help="path to the config file")
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Set log level",
)
@click.option(
    "--requester",
    required=False,
    multiple=False,
    type=str,
    help="Use this requester instead one from certificate file.",
)
@click.option("--repo", help="Repository reference")
@click.argument("inputs", nargs=-1)
def msg_clear_sign_main(
    inputs: List[str],
    signing_key: List[str] = [],
    task_id: str = "",
    config_file: str = "",
    raw: bool = False,
    log_level: str = "INFO",
    requester: str = "",
    repo: str = "",
) -> None:
    """Entry point method for clearsign operation.

    Print following json output on stdout if `--raw` is set:

    >   {
    >     "signer_result": [pubtools.sign.signers.msgsigner.MsgSignerResults][],
    >     "operation_results": [pubtools.sign.results.clearsign.ClearSignResult][],
    >     "operation": [pubtools.sign.operations.clearsign.ClearSignOperation][],
    >     "signing_key": "signing_key_id"
    >   }

    Otherwise prints one clearsigned output per line if sucessfull or error messages if not
    """
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, sanitize_log_level(log_level)))

    LOG.addHandler(ch)
    logging.basicConfig(level=getattr(logging, sanitize_log_level(log_level)))

    ret = msg_clear_sign(
        inputs,
        signing_keys=signing_key,
        task_id=task_id,
        repo=repo,
        requester=requester,
        config_file=config_file,
    )
    if not raw:
        click.echo(json.dumps(ret))
        if ret["signer_result"]["status"] == "error":
            sys.exit(1)
    else:
        if ret["signer_result"]["status"] == "error":
            print(ret["signer_result"]["error_message"], file=sys.stderr)
            sys.exit(1)
        else:
            for claim in ret["operation_results"]:
                if claim[0]["msg"]["errors"]:
                    for error in claim[0]["msg"]["errors"]:
                        print(error, file=sys.stderr)
                    sys.exit(1)
                else:
                    print(claim[0]["msg"]["signed_data"])


@click.command()
@click.option(
    "--signing-key",
    required=True,
    multiple=True,
    help="8 characters key fingerprint of key which should be used for signing or key alias",
)
@click.option(
    "--signing-key-name",
    required=False,
    multiple=True,
    help="signing key name",
)
@click.option("--task-id", required=True, help="Task id identifier (usually pub task-id)")
@click.option("--config-file", default=CONFIG_PATHS[0], help="path to the config file")
@click.option(
    "--digest",
    required=True,
    multiple=True,
    type=str,
    help="Digests which should be signed.",
)
@click.option(
    "--reference",
    required=True,
    multiple=True,
    type=str,
    help="References which should be signed.",
)
@click.option(
    "--requester",
    required=False,
    multiple=False,
    type=str,
    help="Use this requester instead one from certificate file.",
)
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Set log level",
)
@click.option(
    "--signer-type", type=click.Choice(["single", "batch"]), default="single", help="Signer type"
)
def msg_container_sign_main(
    signing_key: List[str] = [],
    signing_key_name: List[str] = [],
    task_id: str = "",
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
    requester: str = "",
    raw: bool = False,
    log_level: str = "INFO",
    signer_type: str = "single",
) -> None:
    """Entry point method for containersign operation.

    Print following json output on stdout when `--raw` is set:

    {
        "signer_result": [pubtools.sign.signers.msgsigner.MsgSignerResults][],
        "operation_results": [pubtools.sign.results.containersign.ContainerSignResult][],
        "operation": [pubtools.sign.operations.containersign.ContainerSignOperation][],
        "signing_keys": ["signing_key_id"]
    }

    Otherwise prints one signed claim per line if sucessfull or error messages if not
    """
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, sanitize_log_level(log_level)))
    LOG.addHandler(ch)
    logging.basicConfig(level=getattr(logging, sanitize_log_level(log_level)))

    ret = msg_container_sign(
        signing_keys=signing_key,
        signing_key_names=signing_key_name,
        task_id=task_id,
        config_file=config_file,
        digest=digest,
        reference=reference,
        requester=requester,
        signer_type=signer_type,
    )
    if not raw:
        click.echo(json.dumps(ret))
        if ret["signer_result"]["status"] == "error":
            sys.exit(1)
    else:
        for claim in ret["operation_results"]:
            if claim[0]["msg"]["errors"]:
                for error in claim[0]["msg"]["errors"]:
                    print(error, file=sys.stderr)
                sys.exit(1)
            else:
                print(claim[0]["msg"]["signed_claim"])


@click.command()
@click.option(
    "--signing-key",
    required=True,
    multiple=True,
    help="8 characters key fingerprint of key which should be used for signing or key alias",
)
@click.option(
    "--signing-key-name",
    required=False,
    multiple=True,
    help="signing key name",
)
@click.option("--task-id", required=True, help="Task id identifier (usually pub task-id)")
@click.option("--config-file", default=CONFIG_PATHS[0], help="path to the config file")
@click.option(
    "--blob-file",
    required=True,
    multiple=True,
    type=str,
    help="Blob files to sign (paths to files whose contents will be signed).",
)
@click.option(
    "--requester",
    required=False,
    multiple=False,
    type=str,
    help="Use this requester instead of the one from the certificate file.",
)
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Set log level",
)
@click.option(
    "--signer-type", type=click.Choice(["single", "batch"]), default="single", help="Signer type"
)
def msg_blob_sign_main(
    signing_key: List[str],
    signing_key_name: List[str],
    task_id: str = "",
    config_file: str = "",
    blob_file: List[str] = [],
    requester: str = "",
    raw: bool = False,
    log_level: str = "INFO",
    signer_type: str = "single",
) -> None:
    """Entry point method for blobsign operation.

    Print following json output on stdout when `--raw` is NOT set:

    {
        "signer_result": [pubtools.sign.signers.msgsigner.MsgSignerResults][],
        "operation_results": [pubtools.sign.results.blobsign.BlobSignResult][],
        "operation": [pubtools.sign.operations.blobsign.BlobSignOperation][],
        "signing_keys": ["signing_key_id"]
    }

    Otherwise prints one signed claim per line if sucessfull or error messages
    """
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, sanitize_log_level(log_level)))
    LOG.addHandler(ch)
    logging.basicConfig(level=getattr(logging, sanitize_log_level(log_level)))

    ret = msg_blob_sign(
        signing_keys=signing_key,
        signing_key_names=signing_key_name,
        task_id=task_id,
        config_file=config_file,
        blob_files=blob_file,
        requester=requester,
        signer_type=signer_type,
    )
    if not raw:
        click.echo(json.dumps(ret))
        if ret["signer_result"]["status"] == "error":
            sys.exit(1)
    else:
        if ret["signer_result"]["status"] == "error":
            print(ret["signer_result"]["error_message"], file=sys.stderr)
            sys.exit(1)
        else:
            for claim in ret["operation_results"]:
                if claim[0]["msg"]["errors"]:
                    for error in claim[0]["msg"]["errors"]:
                        print(error, file=sys.stderr)
                    sys.exit(1)
                else:
                    print(claim[0]["msg"]["signed_payload"])
