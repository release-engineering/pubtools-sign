from __future__ import annotations

from dataclasses import field, dataclass
import json
import logging
from typing import Dict, List, ClassVar, Any
import os
import sys

import click

from . import Signer
from ..operations.base import SignOperation
from ..operations import ContainerSignOperation
from ..results.signing_results import SigningResults
from ..results import ContainerSignResult
from ..results import SignerResults
from ..exceptions import UnsupportedOperation
from ..conf.conf import load_config, CONFIG_PATHS
from ..utils import set_log_level, run_command, _get_config_file


LOG = logging.getLogger("pubtools.sign.signers.cosignsigner")


@dataclass()
class CosignSignerResults(SignerResults):
    """CosignSignerResults model."""

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
class CosignSigner(Signer):
    """Messaging signer class."""

    cosign_bin: str = field(
        init=False,
        metadata={
            "description": "Path to cosign binary",
            "sample": "/usr/local/bin/cosign",
        },
        default="/usr/bin/cosign",
    )
    timeout: str = field(
        init=False,
        metadata={
            "description": "Timeout for cosign operations with units",
            "sample": "60s",
        },
        default="3m0s",
    )
    allow_http_registry: bool = field(
        init=False,
        metadata={
            "description": "Allow http registry",
            "sample": False,
        },
        default=False,
    )
    allow_insecure_registry: bool = field(
        init=False,
        metadata={
            "description": "Allow insecure registry",
            "sample": False,
        },
        default=False,
    )
    rekor_url: str = field(
        init=False,
        metadata={
            "description": "URL for rekor stl server",
            "sample": "https://rekor.sigstore.dev",
        },
        default="https://rekor.sigstore.dev",
    )
    env_variables: Dict[str, str] = field(
        init=False,
        metadata={
            "description": "environment variables used for signing",
            "sample": '{"AWS_ACCESS_KEY_ID": "xxxxxxx", "AWS_SECRET_ACCESS_KEY":"yyyyyyyyy"}',
        },
        default_factory=dict,
    )
    upload_tlog: bool = field(
        init=False,
        metadata={"description": "upload signing record to rekor", "sample": "False"},
        default=True,
    )
    log_level: str = field(
        init=False, metadata={"description": "Log level", "sample": "debug"}, default="info"
    )

    SUPPORTED_OPERATIONS: ClassVar[List[SignOperation]] = [
        ContainerSignOperation,
    ]

    _signer_config_key: str = "cosign_signer"

    def __post_init__(self):
        """Post initialization of the class."""
        set_log_level(LOG, self.log_level)

    def load_config(self: CosignSigner, config_data: Dict[str, Any]) -> None:
        """Load configuration of messaging signer."""
        self.cosign_bin = config_data["cosign_signer"].get("cosign_bin", self.cosign_bin)
        self.timeout = config_data["cosign_signer"].get("timeout", self.timeout)
        self.allow_http_registry = config_data["cosign_signer"].get(
            "allow_http_registry", self.allow_http_registry
        )
        self.allow_insecure_registry = config_data["cosign_signer"].get(
            "allow_insecure_registry", self.allow_insecure_registry
        )
        self.rekor_url = config_data["cosign_signer"].get("rekor_url", self.rekor_url)
        self.upload_tlog = config_data["cosign_signer"].get("upload_tlog", self.upload_tlog)
        self.env_variables = config_data["cosign_signer"].get("env_variables", self.env_variables)

    def operations(self: CosignSigner) -> List[SignOperation]:
        """Return list of supported operations."""
        return self.SUPPORTED_OPERATIONS

    def sign(self: CosignSigner, operation: SignOperation) -> SigningResults:
        """Run signing operation.

        :param operation: signing operation
        :type operation: SignOperation

        :return: SigningResults
        """
        if type(operation) not in self.SUPPORTED_OPERATIONS:
            raise UnsupportedOperation(operation)
        if isinstance(operation, ContainerSignOperation):
            return self.container_sign(operation)

    def container_sign(self: CosignSigner, operation: ContainerSignOperation):
        """Run container signing operation.

        :param operation: signing operation
        :type operation: ContainerSignOperation

        :return: SigningResults
        """
        if operation.references and len(operation.digests) != len(operation.references):
            raise ValueError("Digests must pair with references")

        signer_results = CosignSignerResults(status="ok", error_message="")

        operation_result = ContainerSignResult(
            signing_key=operation.signing_key, results=[], failed=False
        )

        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )

        outputs = {}
        processes = {}
        common_args = [
            self.cosign_bin,
            "-t",
            self.timeout,
            "sign",
            "-y",
            "--key",
            operation.signing_key,
            "--allow-http-registry=%s" % ("true" if self.allow_http_registry else "false"),
            "--allow-insecure-registry=%s" % ("true" if self.allow_insecure_registry else "false"),
            "--rekor-url",
            self.rekor_url,
            "--tlog-upload=%s" % ("true" if self.upload_tlog else "false"),
        ]
        env_vars = os.environ.copy()
        env_vars.update(self.env_variables)
        if operation.references:
            for ref, digest in zip(operation.references, operation.digests):
                repo, tag = ref.rsplit(":", 1)
                processes[f"{repo}:{digest}"] = run_command(
                    common_args + ["-a", f"tag={tag}", f"{repo}@{digest}"],
                    env=env_vars,
                )
        else:
            for ref_digest in operation.digests:
                processes[f"{ref_digest}"] = run_command(
                    common_args + [ref_digest], env=self.env_variables
                )
        for ref, process in processes.items():
            stdout, stderr = process.communicate()
            outputs[ref] = (stdout, stderr, process.returncode)

        for ref, (stdout, stderr, returncode) in outputs.items():
            if returncode != 0:
                operation_result.results.append(stderr)
                operation_result.failed = True
                signing_results.signer_results.status = "failed"
            else:
                operation_result.results.append(stderr)
        signing_results.operation_result = operation_result
        return signing_results


def cosign_container_sign(signing_key=None, config="", digest=None, reference=None):
    """Run containersign operation with cli arguments."""
    cosign_signer = CosignSigner()
    config = _get_config_file(config)
    cosign_signer.load_config(load_config(os.path.expanduser(config)))

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        signing_key=signing_key,
        task_id="",
        repo="",
    )
    signing_result = cosign_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.results,
        "signing_key": signing_result.operation_result.signing_key,
    }


@click.command()
@click.option(
    "--signing-key",
    required=True,
    help="signing key used by cosign.",
)
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
    required=False,
    multiple=True,
    type=str,
    help="References which should be signed.",
)
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
def cosign_container_sign_main(
    signing_key=None,
    config=None,
    digest=None,
    reference=None,
    raw=None,
):
    """Entry point method for containersign operation."""
    ret = cosign_container_sign(
        signing_key=signing_key,
        config=config,
        digest=digest,
        reference=reference,
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
