from __future__ import annotations

import base64
from dataclasses import field, dataclass, asdict
import enum
import json
import logging
from typing import cast, Dict, List, ClassVar, Any, Optional, Type
from typing_extensions import Self
import uuid
import os
import sys

from OpenSSL import crypto
import click

from . import Signer
from ..operations.base import SignOperation
from ..operations import ClearSignOperation, ContainerSignOperation
from ..results.signing_results import SigningResults
from ..results import ClearSignResult, ContainerSignResult
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


LOG = logging.getLogger("pubtools.sign.signers.msgsigner")


class SignRequestType(str, enum.Enum):
    """Sign request type enum."""

    CONTAINER = "container_signature"
    CLEARSIGN = "clearsign_signature"


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

    SUPPORTED_OPERATIONS: ClassVar[List[Type[SignOperation]]] = [
        ContainerSignOperation,
        ClearSignOperation,
    ]

    _signer_config_key: str = "msg_signer"

    def _construct_signing_message(
        self: MsgSigner,
        claim: str,
        signing_key: str,
        repo: str,
        extra_attrs: Optional[Dict[str, Any]] = None,
        sig_type: str = SignRequestType.CONTAINER,
    ) -> dict[str, Any]:
        data_attr = "claim_file" if sig_type == SignRequestType.CONTAINER else "data"
        _extra_attrs = extra_attrs or {}
        message = {
            "sig_key_id": signing_key[-8:],
            data_attr: claim,
            "request_id": str(uuid.uuid4()),
            "created": isodate_now(),
            "requested_by": self.creator,
            "repo": repo,
        }
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

    def _create_msg_message(
        self: MsgSigner,
        data: str,
        repo: str,
        operation: SignOperation,
        sig_type: SignRequestType,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> MsgMessage:
        if operation.signing_key in self.key_aliases:
            signing_key = self.key_aliases[operation.signing_key]
        else:
            signing_key = operation.signing_key
        ret = MsgMessage(
            headers=self._construct_headers(sig_type, extra_attrs=extra_attrs),
            body=self._construct_signing_message(
                data,
                signing_key,
                repo,
                extra_attrs=extra_attrs,
                sig_type=sig_type.value,
            ),
            address=self.topic_send_to.format(
                **dict(list(asdict(self).items()) + list(asdict(operation).items()))
            ),
        )
        LOG.debug(f"Construted message with request_id {ret.body['request_id']}")
        return ret

    def load_config(self: MsgSigner, config_data: Dict[str, Any]) -> None:
        """Load configuration of messaging signer."""
        self.messaging_brokers = config_data["msg_signer"]["messaging_brokers"]
        self.messaging_cert_key = os.path.expanduser(
            config_data["msg_signer"]["messaging_cert_key"]
        )
        self.messaging_ca_cert = os.path.expanduser(config_data["msg_signer"]["messaging_ca_cert"])
        self.topic_send_to = config_data["msg_signer"]["topic_send_to"]
        self.topic_listen_to = config_data["msg_signer"]["topic_listen_to"]
        self.environment = config_data["msg_signer"]["environment"]
        self.service = config_data["msg_signer"]["service"]
        self.message_id_key = config_data["msg_signer"]["message_id_key"]
        self.retries = config_data["msg_signer"]["retries"]
        self.send_retries = config_data["msg_signer"]["send_retries"]
        self.log_level = config_data["msg_signer"]["log_level"]
        self.timeout = config_data["msg_signer"]["timeout"]
        self.creator = self._get_cert_subject_cn()
        self.key_aliases = config_data["msg_signer"].get("key_aliases", {})

    def _get_cert_subject_cn(self) -> str:
        x509 = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(os.path.expanduser(self.messaging_cert_key)).read().encode()
        )
        return x509.get_subject().CN or x509.get_subject().UID  # type: ignore[attr-defined]

    def operations(self: MsgSigner) -> List[Type[SignOperation]]:
        """Return list of supported operations."""
        return self.SUPPORTED_OPERATIONS

    def sign(self: MsgSigner, operation: SignOperation) -> SigningResults:
        """Run signing operation.

        :param operation: signing operation
        :type operation: SignOperation

        :return: SigningResults
        """
        if isinstance(operation, ClearSignOperation):
            return self.clear_sign(operation)
        elif isinstance(operation, ContainerSignOperation):
            return self.container_sign(operation)
        else:
            raise UnsupportedOperation(operation)

    def clear_sign(self: MsgSigner, operation: ClearSignOperation) -> SigningResults:
        """Run the clearsign operation.

        :param operation: signing operation
        :type operation: ClearSignOperation

        :return: SigningResults
        """
        set_log_level(LOG, self.log_level)
        messages = []
        message_to_data = {}
        for in_data in operation.inputs:
            message = self._create_msg_message(
                base64.b64encode(in_data.encode("latin1")).decode("latin-1"),
                operation.repo,
                operation,
                SignRequestType.CLEARSIGN,
                extra_attrs={"pub_task_id": operation.task_id},
            )
            message_to_data[message.body["request_id"]] = message
            messages.append(message)

        all_messages = [x for x in messages]

        signing_key = operation.signing_key
        if signing_key in self.key_aliases:
            signing_key = self.key_aliases[signing_key]
            LOG.info(f"Using signing key alias {signing_key} for {operation.signing_key}")

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = ClearSignResult(
            signing_key=operation.signing_key, outputs=[""] * len(operation.inputs)
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )
        errors: List[MsgError] = []
        received: Dict[int, Any] = {}
        LOG.info("errors " + str(errors))

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
                signer_results.status = "error"
                for error in errors:
                    signer_results.error_message += f"{error.name} : {error.description}\n"
                return signing_results

            # wait for receiver to finish
            recvt.join()
            recvt.stop()

            # check receiver errors
            for x in range(self.retries - 1):
                errors = recvc._errors
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

        errors = recvc._errors
        if errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        operation_result = ClearSignResult(
            signing_key=operation.signing_key, outputs=[""] * len(all_messages)
        )

        for recv_id, _received in recvc.recv.items():
            operation_result.outputs[all_messages.index(message_to_data[recv_id])] = _received
        signing_results.operation_result = operation_result
        return signing_results

    @staticmethod
    def create_manifest_claim_message(signature_key: str, digest: str, reference: str) -> str:
        """Create manifest claim for container signing.

        See below for the specification for the manifest claim that is created here
        https://github.com/containers/image/blob/master/docs/atomic-signature.md
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

    def container_sign(self: MsgSigner, operation: ContainerSignOperation) -> SigningResults:
        """Run container signing operation.

        :param operation: signing operation
        :type operation: ContainerSignOperation

        :return: SigningResults
        """
        set_log_level(LOG, self.log_level)
        messages = []
        message_to_data = {}
        if len(operation.digests) != len(operation.references):
            raise ValueError("Digests must pairs with references")

        signing_key = operation.signing_key
        if signing_key in self.key_aliases:
            signing_key = self.key_aliases[signing_key]
            LOG.info(f"Using signing key alias {signing_key} for {operation.signing_key}")

        LOG.info(f"Container sign operation for {len(operation.digests)}")

        fargs = []
        for digest, reference in zip(operation.digests, operation.references):
            repo = reference.split("/", 1)[1].split(":")[0]
            fargs.append(
                FData(
                    args=[
                        self.create_manifest_claim_message(
                            signing_key, digest=digest, reference=reference
                        ),
                        repo,
                        operation,
                        SignRequestType.CONTAINER,
                    ],
                    kwargs={
                        "extra_attrs": {"pub_task_id": operation.task_id, "manifest_digest": digest}
                    },
                )
            )
        ret = run_in_parallel(self._create_msg_message, fargs)
        for n, message in ret.items():
            message_to_data[message.body["request_id"]] = message
            messages.append(message)

        all_messages = [x for x in messages]
        LOG.info(f"Signing {len(all_messages)}")

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = ContainerSignResult(
            signing_key=operation.signing_key, results=[""] * len(operation.digests), failed=False
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )
        LOG.debug(f"{len(messages)} messages to send")

        errors: List[MsgError] = []
        received: Dict[int, Any] = {}
        LOG.info(
            "Starting signing process. Retries %d,%d, timeout: %d",
            self.send_retries,
            self.retries,
            self.timeout,
        )

        for i in range(self.send_retries):
            message_ids = [message.body["request_id"] for message in messages]
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
                signer_results.status = "error"
                for error in errors:
                    signer_results.error_message += f"{error.name} : {error.description}\n"
                return signing_results

            # wait for receiver to finish
            recvt.join()
            recvt.stop()
            received = recvc.get_received()

            for x in range(self.retries):
                errors = recvc.get_errors()
                if errors and errors[0].name == "MessagingTimeout":
                    LOG.info("Retrying receiving %s/%s", x, self.retries)
                    _messages = []
                    for message in messages:
                        if message.body["request_id"] not in received:
                            _messages.append(message)
                    if x != self.retries - 1:
                        errors.pop(0)
                    messages = _messages
                    if not messages:
                        break
                    message_ids = [message.body["request_id"] for message in messages]

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
                received = recvc.get_received()

            # check receiver errors
            errors = recvc.get_errors()
            if not errors:
                break

        if errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        operation_result = ContainerSignResult(
            signing_key=operation.signing_key, results=[""] * len(all_messages), failed=False
        )
        for recv_id, _received in recvc.recv.items():
            operation_result.failed = True if _received[0]["msg"]["errors"] else False
            operation_result.results[all_messages.index(message_to_data[recv_id])] = _received
        signing_results.operation_result = operation_result
        return signing_results


def msg_clear_sign(
    inputs: List[str],
    signing_key: str = "",
    task_id: str = "",
    config_file: str = "",
    repo: str = "",
) -> Dict[str, Any]:
    """Run clearsign operation."""
    msg_signer = MsgSigner()
    config = _get_config_file(config_file)
    msg_signer.load_config(load_config(os.path.expanduser(config)))

    str_inputs = []
    for input_ in inputs:
        if input_.startswith("@"):
            str_inputs.append(open(input_.lstrip("@")).read())
        else:
            str_inputs.append(input_)
    operation = ClearSignOperation(
        inputs=str_inputs, signing_key=signing_key, task_id=task_id, repo=repo
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": cast(ClearSignResult, signing_result.operation_result).outputs,
        "operation": signing_result.operation.to_dict(),
        "signing_key": signing_result.operation_result.signing_key,
    }


def msg_container_sign(
    signing_key: str = "",
    task_id: str = "",
    config_file: str = "",
    digest: list[str] = [],
    reference: list[str] = [],
) -> Dict[str, Any]:
    """Run containersign operation with cli arguments."""
    msg_signer = MsgSigner()
    config = _get_config_file(config_file)
    msg_signer.load_config(load_config(os.path.expanduser(config)))

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        signing_key=signing_key,
        task_id=task_id,
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.results,
        "operation": signing_result.operation.to_dict(),
        "signing_key": signing_result.operation_result.signing_key,
    }


@click.command()
@click.option(
    "--signing-key",
    required=True,
    help="8 characters key fingerprint of key which should be used for signing",
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
@click.option("--repo", help="Repository reference")
@click.argument("inputs", nargs=-1)
def msg_clear_sign_main(
    inputs: List[str],
    signing_key: str = "",
    task_id: str = "",
    config_file: str = "",
    raw: bool = False,
    log_level: str = "INFO",
    repo: str = "",
) -> None:
    """Entry point method for clearsign operation."""
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, sanitize_log_level(log_level)))

    LOG.addHandler(ch)
    logging.basicConfig(level=getattr(logging, sanitize_log_level(log_level)))

    ret = msg_clear_sign(
        inputs,
        signing_key=signing_key,
        task_id=task_id,
        repo=repo,
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
    help="8 characters key fingerprint of key which should be used for signing",
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
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Set log level",
)
def msg_container_sign_main(
    signing_key: str = "",
    task_id: str = "",
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
    raw: bool = False,
    log_level: str = "INFO",
) -> None:
    """Entry point method for containersign operation."""
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, sanitize_log_level(log_level)))
    LOG.addHandler(ch)
    logging.basicConfig(level=getattr(logging, sanitize_log_level(log_level)))

    ret = msg_container_sign(
        signing_key=signing_key,
        task_id=task_id,
        config_file=config_file,
        digest=digest,
        reference=reference,
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
