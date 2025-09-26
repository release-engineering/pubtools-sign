from click.testing import CliRunner
import pytest
from unittest.mock import patch, call, ANY

from pubtools.sign.signers.rhsigner import (
    RHSigner,
    RHSignerResults,
    ContainerSignOperation,
    ContainerSignResult,
    rh_container_sign_main,
)
from pubtools.sign.operations.clearsign import ClearSignOperation
from pubtools.sign.conf.conf import load_config
from pubtools.sign.exceptions import UnsupportedOperation
from pubtools.sign.results.signing_results import SigningResults


@pytest.fixture
def f_expected_container_sign_args(f_config_rh_signer_ok):
    return [
        "--signing-key",
        "test-signing-key",
        "--digest",
        "some-digest",
        "--reference",
        "some-reference",
        "--config-file",
        f_config_rh_signer_ok,
    ]


def test_sign(f_config_rh_signer_ok):
    signer = RHSigner()
    signer.load_config(load_config(f_config_rh_signer_ok))
    container_sign_operation = ContainerSignOperation(
        digests=("some-digest",),
        references=("some-reference",),
        signing_keys=["test-signing-key"],
        task_id="1",
    )
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"], signing_keys=["test-signing-key"], task_id="1", repo="repo"
    )

    with patch("pubtools.sign.signers.rhsigner.RHSigner.container_sign") as patched_container_sign:
        signer.sign(container_sign_operation)
        patched_container_sign.assert_called_once()
        with pytest.raises(UnsupportedOperation):
            signer.sign(clear_sign_operation)


def test_rh_container_sign(f_rh_signer, f_expected_container_sign_args):
    f_rh_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_rh_signer.return_value.sign.return_value.operation_result.results = []
    f_rh_signer.return_value.sign.return_value.operation_result.signing_keys = [""]
    f_rh_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(rh_container_sign_main, f_expected_container_sign_args)
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_rh_container_sign_main_error(f_rh_signer, f_expected_container_sign_args):
    f_rh_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_rh_signer.return_value.sign.return_value.operation_result.results = []
    f_rh_signer.return_value.sign.return_value.operation_result.signing_keys = [""]
    f_rh_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(rh_container_sign_main, f_expected_container_sign_args)
    print(result.stdout)
    print(result.exception)
    assert result.exit_code == 1, result.output


def test_rh_container_sign_raw(f_rh_signer, f_expected_container_sign_args):
    f_rh_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_rh_signer.return_value.sign.return_value.operation_result.results = ["signed claim"]
    f_rh_signer.return_value.sign.return_value.operation_result.signing_keys = [""]

    f_rh_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(rh_container_sign_main, f_expected_container_sign_args + ["--raw"])
    print(result.stderr_bytes)
    print(result.stdout)
    print(result.exception)
    assert result.exit_code == 0, result.output


def test_rh_container_sign_raw_error(f_rh_signer, f_expected_container_sign_args):
    f_rh_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_rh_signer.return_value.sign.return_value.operation_result.results = []
    f_rh_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_rh_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(rh_container_sign_main, f_expected_container_sign_args + ["--raw"])
    print(result.stderr_bytes)
    print(result.stdout)
    assert result.exit_code == 1, result.output


def test_rh_container_sign_error(f_rh_signer, f_config_rh_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 1
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_ok))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/rh-sign-client",
                        "-a",
                        "test",
                        "--key",
                        "beta",
                        "-R",
                        "3",
                        "--gpgsign",
                        "--server",
                        "signing-server.example.com",
                        "--hostname",
                        "signing-server.example.com",
                        "--principal",
                        "test@REALM",
                        "--keytab",
                        "/path/to/keytab",
                        "-o",
                        ANY,
                        ANY,
                    ],
                    env={},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=RHSignerResults(status="error", error_message="stderr"),
            operation_result=ContainerSignResult(
                results=["stderr"], signing_keys=["beta"], failed=True
            ),
        )


def test_container_sign_alias(f_config_rh_signer_aliases, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_aliases))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/rh-sign-client",
                        "-a",
                        "test",
                        "--key",
                        "abcde1245",
                        "-R",
                        "3",
                        "--gpgsign",
                        "--server",
                        "signing-server.example.com",
                        "--hostname",
                        "signing-server.example.com",
                        "--principal",
                        "test@REALM",
                        "--keytab",
                        "/path/to/keytab",
                        "-o",
                        ANY,
                        ANY,
                    ],
                    env={},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=RHSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(results=[""], signing_keys=["beta"], failed=False),
        )


def test_container_sign_insecure(f_config_rh_signer_insecure, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_insecure))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/rh-sign-client",
                        "-a",
                        "test",
                        "--key",
                        "beta",
                        "-R",
                        "3",
                        "--gpgsign",
                        "--server",
                        "signing-server.example.com",
                        "--hostname",
                        "signing-server.example.com",
                        "--principal",
                        "test@REALM",
                        "--keytab",
                        "/path/to/keytab",
                        "-K",
                        "-o",
                        ANY,
                        ANY,
                    ],
                    env={},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=RHSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(results=[""], signing_keys=["beta"], failed=False),
        )


def test_container_sign_nat(f_config_rh_signer_nat, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_nat))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/rh-sign-client",
                        "-a",
                        "test",
                        "--key",
                        "beta",
                        "-R",
                        "3",
                        "--gpgsign",
                        "--server",
                        "signing-server.example.com",
                        "--hostname",
                        "signing-server.example.com",
                        "--principal",
                        "test@REALM",
                        "--keytab",
                        "/path/to/keytab",
                        "--nat",
                        "-o",
                        ANY,
                        ANY,
                    ],
                    env={},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=RHSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(results=[""], signing_keys=["beta"], failed=False),
        )


def test_container_sign_onbehalfof(f_config_rh_signer_onbehalfof, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_onbehalfof))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/rh-sign-client",
                        "-a",
                        "test",
                        "--key",
                        "beta",
                        "-R",
                        "3",
                        "--gpgsign",
                        "--server",
                        "signing-server.example.com",
                        "--hostname",
                        "signing-server.example.com",
                        "--principal",
                        "test@REALM",
                        "--keytab",
                        "/path/to/keytab",
                        "--onbehalfof",
                        "user@REALM",
                        "-o",
                        ANY,
                        ANY,
                    ],
                    env={},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=RHSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(results=[""], signing_keys=["beta"], failed=False),
        )


def test_container_sign_mismatch_refs(f_config_rh_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag1", "some-registry/namespace/repo:tag2"],
        signing_keys=["test-signing-key"],
    )

    with patch("subprocess.Popen") as patched_popen:
        signer = RHSigner()
        signer.load_config(load_config(f_config_rh_signer_ok))
        with pytest.raises(ValueError):
            signer.container_sign(container_sign_operation)

        print(patched_popen.mock_calls)
        patched_popen.assert_not_called()


def test_rhsig_doc_arguments():
    assert RHSigner.doc_arguments() == {
        "options": {
            "NAT": {"description": "Use NAT traversal when connecting to the signing server"},
            "application": {"description": "Application name to use for signing"},
            "hostname": {"description": "RH signing server URL"},
            "insecure": {"description": "Allow insecure connection to the signing server"},
            "keytab": {"description": "Kerberos keytab file"},
            "onbehalfof": {"description": "User to sign on behalf of"},
            "principal": {"description": "Principal to use for signing"},
            "rh_signer_bin": {"description": "Path to cosign binary"},
            "retries": {"description": "Number of retries for running rh-sign-client command"},
            "log_level": {"description": "Log level"},
            "num_threads": {"description": "The number of threads for running cosign command"},
            "key_aliases": {"description": "Aliases for signing keys"},
        },
        "examples": {
            "rh_signer": {
                "NAT": False,
                "application": "pubtools-sign",
                "hostname": "https://signing.server.com",
                "insecure": False,
                "keytab": "/path/to/keytab",
                "num_threads": 10,
                "onbehalfof": "user@domain",
                "principal": "user@domain",
                "retries": 3,
                "log_level": "debug",
                "key_aliases": "{'production':'abcde1245'}",
                "rh_signer_bin": "/usr/local/bin/rh-sign-client",
            }
        },
    }


def test_msgsigresult_to_dict():
    assert RHSignerResults(status="status", error_message="error_message").to_dict() == {
        "status": "status",
        "error_message": "error_message",
    }


def test_rhsigresult_doc_arguments():
    assert RHSignerResults.doc_arguments() == {
        "signer_result": {
            "type": "dict",
            "description": "Signing result status.",
            "returned": "always",
            "sample": {"status": "ok", "error_message": ""},
        }
    }


def test_operations():
    signer = RHSigner()
    assert signer.operations() == [ContainerSignOperation]
