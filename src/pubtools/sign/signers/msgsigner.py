from __future__ import annotations

import base64
from dataclasses import field, dataclass, asdict
import enum
import json
import logging
from typing import Dict, List, ClassVar, Any, Optional
import uuid
import os
import sys

import OpenSSL
import click

from . import Signer
from ..operations.base import SignOperation
from ..operations import ClearSignOperation, ContainerSignOperation
from ..results.signing_results import SigningResults
from ..results import ClearSignResult, ContainerSignResult
from ..results import SignerResults
from ..exceptions import UnsupportedOperation
from ..clients.msg_send_client import SendClient
from ..clients.msg_recv_client import RecvClient
from ..models.msg import MsgMessage
from ..conf.conf import load_config, CONFIG_PATHS
from ..utils import set_log_level, isodate_now


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

    def to_dict(self: SignerResults):
        """Return dict representation of MsgSignerResults model."""
        return {"status": self.status, "error_message": self.error_message}

    @classmethod
    def doc_arguments(cls: SignerResults) -> Dict[str, Any]:
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
        metadata={"description": "Timeout for messaging sent/receive", "sample": 1},
    )
    retries: int = field(
        init=False,
        default=60,
        metadata={"description": "Retries for messaging sent/receive", "sample": 3},
    )
    message_id_key: str = field(
        init=False,
        metadata={
            "description": "Attribute name in message body which should be used as message id",
            "sample": "123",
        },
    )
    log_level: str = field(init=False, metadata={"description": "Log level", "sample": "debug"})

    SUPPORTED_OPERATIONS: ClassVar[List[SignOperation]] = [
        ContainerSignOperation,
        ClearSignOperation,
    ]

    def _construct_signing_message(
        self: MsgSigner,
        claim,
        signing_key: str,
        repo: str,
        extra_attrs: Optional[Dict] = None,
        sig_type: SignRequestType = SignRequestType.CONTAINER,
    ):
        data_attr = "claim_file" if sig_type == SignRequestType.CONTAINER else "data"
        _extra_attrs = extra_attrs or {}
        message = {
            "sig_key_id": signing_key,
            data_attr: claim,
            "request_id": str(uuid.uuid4()),
            "created": isodate_now(),
            "requested_by": self.creator,
            "repo": repo,
        }
        message.update(_extra_attrs)
        return message

    def _construct_headers(self: MsgSigner, sig_type, extra_attrs: Optional[Dict] = None):
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
        self: MsgSigner, data, operation: SignOperation, sig_type: SignRequestType, extra_attrs=None
    ):
        ret = MsgMessage(
            headers=self._construct_headers(sig_type, extra_attrs=extra_attrs),
            body=self._construct_signing_message(
                data,
                operation.signing_key,
                repo=operation.repo,
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
        self.log_level = config_data["msg_signer"]["log_level"]
        self.timeout = config_data["msg_signer"]["timeout"]
        self.creator = self._get_cert_subject_cn()

    def _get_cert_subject_cn(self):
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, open(os.path.expanduser(self.messaging_cert_key)).read()
        )
        return x509.get_subject().CN

    def operations(self: MsgSigner) -> List[SignOperation]:
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

    def clear_sign(self: MsgSigner, operation: ClearSignOperation):
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
                operation,
                SignRequestType.CLEARSIGN,
                extra_attrs={"pub_task_id": operation.task_id},
            )
            message_to_data[message.body["request_id"]] = message
            messages.append(message)

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
        LOG.debug(f"{len(messages)} messages to send")

        errors = []
        errors = SendClient(
            messages=messages,
            broker_urls=self.messaging_brokers,
            cert=self.messaging_cert_key,
            ca_cert=self.messaging_ca_cert,
            retries=self.retries,
            errors=errors,
        ).run()

        if errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        message_ids = [message.body["request_id"] for message in messages]

        recvc = RecvClient(
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
        )
        recvc.run()
        errors = recvc.errors
        if errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        operation_result = ClearSignResult(
            signing_key=operation.signing_key, outputs=[""] * len(messages)
        )
        for recv_id, received in recvc.recv.items():
            operation_result.outputs[messages.index(message_to_data[recv_id])] = received
        signing_results.operation_result = operation_result
        return signing_results

    @staticmethod
    def create_manifest_claim_message(signature_key, digest, reference):
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

    def container_sign(self: MsgSigner, operation: ContainerSignOperation):
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

        for digest, reference in zip(operation.digests, operation.references):
            message = self._create_msg_message(
                self.create_manifest_claim_message(
                    operation.signing_key, digest=digest, reference=reference
                ),
                operation,
                SignRequestType.CONTAINER,
                extra_attrs={"pub_task_id": operation.task_id, "manifest_digest": digest},
            )
            message_to_data[message.body["request_id"]] = message
            messages.append(message)

        signer_results = MsgSignerResults(status="ok", error_message="")
        operation_result = ContainerSignResult(
            signing_key=operation.signing_key, signed_claims=[""] * len(operation.digests)
        )
        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )
        LOG.debug(f"{len(messages)} messages to send")

        errors = []
        errors = SendClient(
            messages=messages,
            broker_urls=self.messaging_brokers,
            cert=self.messaging_cert_key,
            ca_cert=self.messaging_ca_cert,
            retries=self.retries,
            errors=errors,
        ).run()

        if errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        message_ids = [message.body["request_id"] for message in messages]

        recvc = RecvClient(
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
        )
        recvc.run()
        errors = recvc.errors

        if recvc.errors:
            signer_results.status = "error"
            for error in errors:
                signer_results.error_message += f"{error.name} : {error.description}\n"
            return signing_results

        operation_result = ContainerSignResult(
            signing_key=operation.signing_key, signed_claims=[""] * len(messages)
        )
        for recv_id, received in recvc.recv.items():
            operation_result.signed_claims[messages.index(message_to_data[recv_id])] = received
        signing_results.operation_result = operation_result
        return signing_results


def _get_config_file(config_candidate):
    if not os.path.exists(config_candidate):
        for config_candidate in CONFIG_PATHS:
            if os.path.exists(os.path.expanduser(config_candidate)):
                break
        else:
            raise ValueError(
                "No configuration file found: %s" % list(set(CONFIG_PATHS + [config_candidate]))
            )
    return config_candidate


def msg_clear_sign(inputs, signing_key=None, task_id=None, config="", repo=""):
    """Run clearsign operation."""
    msg_signer = MsgSigner()
    config = _get_config_file(config)
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
        "operation_results": signing_result.operation_result.outputs,
        "signing_key": signing_result.operation_result.signing_key,
    }


def msg_container_sign(
    signing_key=None, task_id=None, config="", digest=None, reference=None, repo=None
):
    """Run containersign operation with cli arguments."""
    msg_signer = MsgSigner()
    config = _get_config_file(config)
    msg_signer.load_config(load_config(os.path.expanduser(config)))

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        signing_key=signing_key,
        task_id=task_id,
        repo=repo,
    )
    signing_result = msg_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.signed_claims,
        "signing_key": signing_result.operation_result.signing_key,
    }


@click.command()
@click.option(
    "--signing-key",
    required=True,
    help="8 characters key fingerprint of key which should be used for signing",
)
@click.option("--task-id", required=True, help="Task id identifier (usually pub task-id)")
@click.option("--config", default=CONFIG_PATHS[0], help="path to the config file")
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
@click.option("--repo", help="Repository reference")
@click.argument("inputs", nargs=-1)
def msg_clear_sign_main(inputs, signing_key=None, task_id=None, config=None, raw=None, repo=None):
    """Entry point method for clearsign operation."""
    ret = msg_clear_sign(inputs, signing_key=signing_key, task_id=task_id, repo=repo, config=config)
    if not raw:
        click.echo(json.dumps(ret))
        print(ret)
        if ret["signer_result"]["status"] == "error":
            sys.exit(1)
    else:
        if ret["signer_result"]["status"] == "error":
            print(ret["signer_result"]["error_message"], file=sys.stderr)
            sys.exit(1)
        else:
            for claim in ret["operation_results"]:
                print(claim)


@click.command()
@click.option(
    "--signing-key",
    required=True,
    help="8 characters key fingerprint of key which should be used for signing",
)
@click.option("--task-id", required=True, help="Task id identifier (usually pub task-id)")
@click.option("--config", default=CONFIG_PATHS[0], help="path to the config file")
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
@click.option("--repo", help="Repository reference")
def msg_container_sign_main(
    signing_key=None,
    task_id=None,
    config=None,
    digest=None,
    reference=None,
    raw=None,
    repo=None,
):
    """Entry point method for containersign operation."""
    ret = msg_container_sign(
        signing_key=signing_key,
        task_id=task_id,
        config=config,
        digest=digest,
        reference=reference,
        repo=repo,
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
                print(claim)
