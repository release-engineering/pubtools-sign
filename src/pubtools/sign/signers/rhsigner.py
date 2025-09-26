from __future__ import annotations

import base64
from dataclasses import field, dataclass
import itertools
import json
import logging
import tempfile
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
from ..utils import (
    set_log_level,
    run_command,
    _get_config_file,
    run_in_parallel,
    FData,
    create_container_atomic_signature,
)


LOG = logging.getLogger("pubtools.sign.signers.rhsigner")


@dataclass()
class RHSignerResults(SignerResults):
    """CosignSignerResults model."""

    status: str
    error_message: str

    def to_dict(self: Self) -> Dict[str, Any]:
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
class RHSigner(Signer):
    """RH signer class."""

    application: str = field(
        init=False,
        metadata={
            "description": "Application name to use for signing",
            "sample": "pubtools-sign",
        },
        default="pubtools-sign",
    )
    rh_signer_bin: str = field(
        init=False,
        metadata={
            "description": "Path to cosign binary",
            "sample": "/usr/local/bin/rh-sign-client",
        },
        default="/usr/bin/rh-sign-client",
    )
    hostname: str = field(
        init=False,
        metadata={
            "description": "RH signing server URL",
            "sample": "https://signing.server.com",
        },
        default="",
    )
    principal: str = field(
        init=False,
        metadata={"description": "Principal to use for signing", "sample": "user@domain"},
        default="",
    )
    keytab: str = field(
        init=False,
        metadata={"description": "Kerberos keytab file", "sample": "/path/to/keytab"},
        default="",
    )
    insecure: bool = field(
        init=False,
        metadata={
            "description": "Allow insecure connection to the signing server",
            "sample": False,
        },
        default=False,
    )
    NAT: bool = field(
        init=False,
        metadata={
            "description": "Use NAT traversal when connecting to the signing server",
            "sample": False,
        },
        default=False,
    )
    retries: int = field(
        init=False,
        metadata={
            "description": "Number of retries for running rh-sign-client command",
            "sample": 3,
        },
        default=3,
    )
    onbehalfof: str = field(
        init=False,
        metadata={
            "description": "User to sign on behalf of",
            "sample": "user@domain",
        },
        default="",
    )
    num_threads: int = field(
        init=False,
        metadata={
            "description": "The number of threads for running cosign command",
            "sample": 10,
        },
        default=10,
    )
    key_aliases: Dict[str, str] = field(
        init=False,
        metadata={
            "description": "Aliases for signing keys",
            "sample": "{'production':'abcde1245'}",
        },
        default_factory=dict,
    )
    log_level: str = field(
        init=False, metadata={"description": "Log level", "sample": "debug"}, default="info"
    )

    SUPPORTED_OPERATIONS: ClassVar[List[Type[SignOperation]]] = [
        ContainerSignOperation,
    ]

    _signer_config_key: str = "rh_signer"

    def __post_init__(self) -> None:
        """Post initialization of the class."""
        set_log_level(LOG, self.log_level)

    def load_config(self: Self, config_data: Dict[str, Any]) -> None:
        """Load configuration of messaging signer.

        Arguments:
            config_data (dict): configuration data to load
        """
        self.rh_signer_bin = config_data["rh_signer"].get("rh_signer_bin", self.rh_signer_bin)
        self.application = config_data["rh_signer"].get("application", self.application)
        self.hostname = config_data["rh_signer"].get("hostname", self.hostname)
        self.principal = config_data["rh_signer"].get("principal", self.principal)
        self.keytab = config_data["rh_signer"].get("keytab", self.keytab)
        self.insecure = config_data["rh_signer"].get("insecure", self.insecure)
        self.NAT = config_data["rh_signer"].get("NAT", self.NAT)
        self.retries = config_data["rh_signer"].get("retries", self.retries)
        self.onbehalfof = config_data["rh_signer"].get("onbehalfof", self.onbehalfof)
        self.num_threads = config_data["rh_signer"].get("num_threads", self.num_threads)
        self.log_level = config_data["rh_signer"].get("log_level", self.log_level)
        self.key_aliases = config_data["rh_signer"].get("key_aliases", {})
        set_log_level(LOG, self.log_level)

    def operations(self: Self) -> List[Type[SignOperation]]:
        """Return list of supported signing operation classes.

        Returns:
            List[Type[SignOperation]]: list of supported operations
        """
        return self.SUPPORTED_OPERATIONS

    def _sign_container(
        self,
        args: List[str],
        tries: int,
        reference: str = "",
        ref_digest: str = "",
    ) -> Any:
        LOG.info(f"Signing {reference} ({ref_digest})")
        with tempfile.NamedTemporaryFile() as tmpf_o:
            with tempfile.NamedTemporaryFile() as tmpf:
                tmpf.write(
                    json.dumps(create_container_atomic_signature(ref_digest, reference)).encode(
                        "utf-8"
                    )
                )
                stdout, stderr, code = run_command(
                    args + ["-o", tmpf_o.name, tmpf.name], env={}, tries=tries
                )
                if code != 0:
                    LOG.error(f"Failed to sign {reference} ({ref_digest}): {stderr}")
                    return "", stdout, stderr, code
                with open(tmpf_o.name, "rb") as f:
                    output = f.read().strip()
                    return output, stdout, stderr, code

    def sign(self: Self, operation: SignOperation) -> SigningResults:
        """Run signing operation.

        Arguments:
            operation (SignOperation): signing operation to run

        Returns:
            SigningResults: results of the signing operation
        """
        if isinstance(operation, ContainerSignOperation):
            return self.container_sign(operation)
        else:
            raise UnsupportedOperation(operation)

    def container_sign(self: Self, operation: ContainerSignOperation) -> SigningResults:
        """Run container signing operation.

        Arguments:
            operation (ContainerSignOperation): container signing operation to run

        Returns:
            SigningResults: results of the container signing operation
        """
        if operation.references and len(operation.digests) != len(operation.references):
            raise ValueError("Digests must pair with references")

        signer_results = RHSignerResults(status="ok", error_message="")

        operation_result = ContainerSignResult(
            signing_keys=operation.signing_keys, results=[], failed=False
        )
        for _signing_key in operation.signing_keys:
            if _signing_key in self.key_aliases:
                signing_key = self.key_aliases[_signing_key]
                LOG.info(f"Using signing key alias {signing_key} for {_signing_key}")
            else:
                signing_key = _signing_key

            signing_results = SigningResults(
                signer=self,
                operation=operation,
                signer_results=signer_results,
                operation_result=operation_result,
            )

            ref_args_group: dict[str, List[Tuple[List[str], Dict[str, Any]]]] = {}
            common_args = [
                self.rh_signer_bin,
                "-a",
                self.application,
                "--key",
                signing_key,
                "-R",
                str(self.retries),
                "--gpgsign",
            ]
            if self.hostname:
                common_args += ["--server", self.hostname]
            if self.hostname:
                common_args += ["--hostname", self.hostname]
            if self.principal:
                common_args += ["--principal", self.principal]
            if self.keytab:
                common_args += ["--keytab", self.keytab]
            if self.insecure:
                common_args += ["-K"]
            if self.NAT:
                common_args += ["--nat"]
            if self.onbehalfof:
                common_args += ["--onbehalfof", self.onbehalfof]

            for ref_digest, reference in itertools.zip_longest(
                operation.digests, operation.references, fillvalue=""
            ):
                args: List[str] = []
                named_args = {}
                named_args["ref_digest"] = ref_digest
                named_args["reference"] = reference
                ref_args_group.setdefault(ref_digest, [])
                ref_args_group[ref_digest].append((args, named_args))

        # Execute rh-signing-client commands serially in each group
        # while running groups concurrently.
        ret = run_in_parallel(
            lambda args_group, **kwargs: [
                self._sign_container(common_args + args, tries=self.retries, **kwargs)
                for args, kwargs in args_group
            ],
            [
                FData(
                    args=[args_group],
                )
                for args_group in ref_args_group.values()
            ],
            self.num_threads,
        )

        for output, stdout, stderr, returncode in itertools.chain(*ret.values()):
            if returncode != 0:
                operation_result.results.append(stderr)
                operation_result.failed = True
                signing_results.signer_results.status = "error"
                signing_results.signer_results.error_message += stderr
            else:
                operation_result.results.append(base64.b64encode(output).decode("utf-8"))
        signing_results.operation_result = operation_result
        return signing_results


def rh_container_sign(
    signing_keys: List[str] = [],
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
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
    rh_signer = RHSigner()
    config = _get_config_file(config_file)
    rh_signer.load_config(load_config(os.path.expanduser(config)))

    operation = ContainerSignOperation(
        digests=digest,
        references=reference,
        signing_keys=signing_keys,
        task_id="",
    )
    signing_result = rh_signer.sign(operation)
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
    help="signing key used by rhsigner.",
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
@click.option("--raw", default=False, is_flag=True, help="Print raw output instead of json")
def rh_container_sign_main(
    signing_key: List[str] = [],
    config_file: str = "",
    digest: List[str] = [],
    reference: List[str] = [],
    raw: bool = False,
) -> None:
    """Entry point method for containersign operation."""
    ret = rh_container_sign(
        signing_keys=signing_key,
        config_file=config_file,
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
