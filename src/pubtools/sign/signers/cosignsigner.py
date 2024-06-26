from __future__ import annotations

from dataclasses import field, dataclass
import itertools
import json
import logging
from typing import Dict, List, ClassVar, Any, Tuple, Type
from typing_extensions import Self
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
from ..clients.registry import ContainerRegistryClient, AuthTokenWrapper


LOG = logging.getLogger("pubtools.sign.signers.cosignsigner")


@dataclass()
class CosignSignerResults(SignerResults):
    """CosignSignerResults model."""

    status: str
    error_message: str

    def to_dict(self: SignerResults) -> Dict[str, Any]:
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
    key_aliases: Dict[str, str] = field(
        init=False,
        metadata={
            "description": "Aliases for signing keys",
            "sample": "{'production':'abcde1245'}",
        },
        default_factory=dict,
    )

    registry_user: str = field(
        init=False,
        metadata={"description": "Registry basic user", "sample": "username"},
        default="",
    )

    registry_password: str = field(
        init=False,
        metadata={"description": "Registry basic password", "sample": "password"},
        default="",
    )
    registry_auth_file: str = field(
        init=False,
        metadata={"description": "Registry basic auth file", "sample": "auth.json"},
        default="",
    )
    retries: int = field(
        init=False,
        metadata={"description": "Number of retries for http requests", "sample": 5},
        default=5,
    )

    SUPPORTED_OPERATIONS: ClassVar[List[Type[SignOperation]]] = [
        ContainerSignOperation,
    ]

    _signer_config_key: str = "cosign_signer"

    def __post_init__(self) -> None:
        """Post initialization of the class."""
        set_log_level(LOG, self.log_level)
        self.container_registry_client = ContainerRegistryClient(
            username=self.registry_user,
            password=self.registry_password,
            auth_file=self.registry_auth_file,
            log_level=self.log_level,
        )
        self.auth_token = AuthTokenWrapper(token="")

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
        self.key_aliases = config_data["cosign_signer"].get("key_aliases", {})
        self.registry_user = config_data["cosign_signer"].get("registry_user", self.registry_user)
        self.registry_password = config_data["cosign_signer"].get(
            "registry_password", self.registry_password
        )
        self.retries = config_data["cosign_signer"].get("retries", self.retries)
        self.container_registry_client = ContainerRegistryClient(
            username=self.registry_user,
            password=self.registry_password,
            auth_file=self.registry_auth_file,
            log_level=self.log_level,
        )

    def operations(self: CosignSigner) -> List[Type[SignOperation]]:
        """Return list of supported operations."""
        return self.SUPPORTED_OPERATIONS

    def sign(self: CosignSigner, operation: SignOperation) -> SigningResults:
        """Run signing operation.

        :param operation: signing operation
        :type operation: SignOperation

        :return: SigningResults
        """
        if isinstance(operation, ContainerSignOperation):
            return self.container_sign(operation)
        else:
            raise UnsupportedOperation(operation)

    def container_sign(self: CosignSigner, operation: ContainerSignOperation) -> SigningResults:
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
        signing_key = operation.signing_key
        if signing_key in self.key_aliases:
            signing_key = self.key_aliases[signing_key]
            LOG.info(f"Using signing key alias {signing_key} for {operation.signing_key}")

        signing_results = SigningResults(
            signer=self,
            operation=operation,
            signer_results=signer_results,
            operation_result=operation_result,
        )

        outputs = {}
        ref_args = {}
        identity_args = {}
        common_args = [
            self.cosign_bin,
            "-t",
            self.timeout,
            "sign",
            "-y",
            "--key",
            signing_key,
            "--allow-http-registry=%s" % ("true" if self.allow_http_registry else "false"),
            "--allow-insecure-registry=%s" % ("true" if self.allow_insecure_registry else "false"),
            "--rekor-url",
            self.rekor_url,
            "--tlog-upload=%s" % ("true" if self.upload_tlog else "false"),
        ]
        if self.registry_user:
            common_args += ["--registry-username", self.registry_user]
        if self.registry_password:
            common_args += ["--registry-password", self.registry_password]
        env_vars = os.environ.copy()
        env_vars.update(self.env_variables)
        if operation.references:
            for ref, identity, digest in itertools.zip_longest(
                operation.references, operation.identity_references, operation.digests, fillvalue=""
            ):
                repo, tag = ref.rsplit(":", 1)
                ref_args[f"{repo}@{digest}"] = ["-a", f"tag={tag}", f"{repo}@{digest}"]
                if identity:
                    identity_args[f"{repo}@{digest}"] = ["--sign-container-identity", identity]

        else:
            for ref_digest, identity in itertools.zip_longest(
                operation.digests, operation.identity_references, fillvalue=""
            ):
                ref_args[ref_digest] = [ref_digest]
                if identity:
                    repo, digest = ref_digest.rsplit("@", 1)
                    identity_args[f"{repo}@{digest}"] = ["--sign-container-identity", identity]

        for ref, args in ref_args.items():
            _identity_args = identity_args.get(ref, [])
            outputs[ref] = run_command(
                common_args + _identity_args + args, env=env_vars, tries=self.retries
            )

        for ref, (stdout, stderr, returncode) in outputs.items():
            if returncode != 0:
                operation_result.results.append(stderr)
                operation_result.failed = True
                signing_results.signer_results.status = "failed"
                signing_results.signer_results.error_message += stderr
            else:
                operation_result.results.append(stderr)
        signing_results.operation_result = operation_result
        return signing_results

    def existing_signatures(self, reference: str) -> Tuple[bool, str]:
        """Return list of existing signatures for given reference.

        Args:
            reference (str): reference to get list of signatures for
        Returns:
            Tuple[bool, str]: tuple of success flag and error message or result string
        """
        common_args = [
            self.cosign_bin,
            "-t",
            self.timeout,
            "triangulate",
            "--allow-http-registry=%s" % ("true" if self.allow_http_registry else "false"),
            "--allow-insecure-registry=%s" % ("true" if self.allow_insecure_registry else "false"),
        ]
        if self.registry_user:
            common_args += ["--registry-username", self.registry_user]
        if self.registry_password:
            common_args += ["--registry-password", self.registry_password]
        env_vars = os.environ.copy()
        env_vars.update(self.env_variables)
        stdout, stderr, returncode = run_command(
            common_args + [reference],
            env=env_vars,
        )
        if returncode != 0:
            return False, stderr
        else:
            ret, err_msg = self.container_registry_client.check_container_image_exists(
                stdout.strip("\n"), auth_token=self.auth_token
            )
            if ret:
                return True, stdout.split("\n")
            elif err_msg:
                return False, err_msg
            return True, ""


def cosign_container_sign(
    signing_key: str = "",
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
    identity: List[str] = [],
) -> Dict[str, Any]:
    """Run containersign operation with cli arguments.

    Args:
        signing_key (str): path to the signing key
        config_file (str): path to the config file
        digest (str): digest of the image to sign
        reference (str): reference of the image to sign
        identity (str): identity to sign the image with
    Returns:
        dict: signing result
    """
    cosign_signer = CosignSigner()
    config = _get_config_file(config_file)
    cosign_signer.load_config(load_config(os.path.expanduser(config)))

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        identity_references=identity,
        signing_key=signing_key,
        task_id="",
    )
    signing_result = cosign_signer.sign(operation)
    return {
        "signer_result": signing_result.signer_results.to_dict(),
        "operation_results": signing_result.operation_result.results,
        "operation": signing_result.operation.to_dict(),
        "signing_key": signing_result.operation_result.signing_key,
    }


def cosign_list_existing_signatures(config_file: str, reference: str) -> Tuple[bool, str]:
    """List existing signatures for given reference.

    Args:
        config_file (str): path to the config file
        reference (str): reference to get list of signatures for
    Returns:
        Tuple[bool, str]: tuple of success flag and error message or result string
    """
    cosign_signer = CosignSigner()
    config = _get_config_file(config_file)
    cosign_signer.load_config(load_config(os.path.expanduser(config)))
    return cosign_signer.existing_signatures(reference)


@click.command()
@click.option(
    "--signing-key",
    required=True,
    help="signing key used by cosign.",
)
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
    required=False,
    multiple=True,
    type=str,
    help="References which should be signed.",
)
@click.option(
    "--identity",
    required=False,
    multiple=True,
    type=str,
    help="Identity reference.",
)
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
def cosign_container_sign_main(
    signing_key: str = "",
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
    identity: List[str] = [],
    raw: bool = False,
) -> None:
    """Entry point method for containersign operation."""
    ret = cosign_container_sign(
        signing_key=signing_key,
        config_file=config_file,
        digest=digest,
        reference=reference,
        identity=identity,
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
