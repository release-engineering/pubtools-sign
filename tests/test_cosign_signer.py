from click.testing import CliRunner
import pytest
from unittest.mock import patch, Mock, call, ANY

from pubtools.sign.signers.cosignsigner import (
    CosignSigner,
    CosignSignerResults,
    ContainerSignOperation,
    ContainerSignResult,
    cosign_container_sign_main,
)
from pubtools.sign.conf.conf import load_config
from pubtools.sign.exceptions import UnsupportedOperation
from pubtools.sign.results.signing_results import SigningResults


def test_cosign_container_sign(f_cosign_signer, f_config_cosign_signer_ok):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--config",
            f_config_cosign_signer_ok,
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_cosign_container_sign_error(f_cosign_signer, f_config_cosign_signer_ok):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--config",
            f_config_cosign_signer_ok,
        ],
    )
    print(result.stdout)
    assert result.exit_code == 1, result.output


def test_cosign_container_sign_raw(f_cosign_signer, f_config_cosign_signer_ok):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = ["signed"]
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--config",
            f_config_cosign_signer_ok,
            "--raw",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output
    assert result.output == "signed\n"


def test_cosign_container_sign_raw_error(f_cosign_signer, f_config_cosign_signer_ok):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--config",
            f_config_cosign_signer_ok,
            "--raw",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 1, result.output
    assert result.output == "simulated error\n"


def test_operations():
    signer = CosignSigner()
    assert signer.operations() == [ContainerSignOperation]


def test_sign(f_config_cosign_signer_ok):
    signer = CosignSigner()
    signer.load_config(load_config(f_config_cosign_signer_ok))
    container_sign_operation = ContainerSignOperation(
        digests=("some-digest",),
        references=("some-reference",),
        signing_key="test-signing-key",
        task_id="",
        repo="r",
    )
    with patch(
        "pubtools.sign.signers.cosignsigner.CosignSigner.container_sign"
    ) as patched_container_sign:
        signer.sign(container_sign_operation)
        patched_container_sign.assert_called_once()
        with pytest.raises(UnsupportedOperation):
            signer.sign(Mock())


def test_container_sign(f_config_cosign_signer_ok, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
        repo="",
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/cosign",
                        "-t",
                        "30s",
                        "sign",
                        "-y",
                        "--key",
                        "test-signing-key",
                        "--allow-http-registry=false",
                        "--allow-insecure-registry=false",
                        "--rekor-url",
                        "https://rekor.sigstore.dev",
                        "--tlog-upload=true",
                        "-a",
                        "tag=tag",
                        "some-registry/namespace/repo@sha256:abcdefg",
                    ],
                    env={"PYTEST_CURRENT_TEST": ANY},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=CosignSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(
                results=["stderr"], signing_key="test-signing-key", failed=False
            ),
        )


def test_container_sign_error(f_config_cosign_signer_ok, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
        repo="",
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 1
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/cosign",
                        "-t",
                        "30s",
                        "sign",
                        "-y",
                        "--key",
                        "test-signing-key",
                        "--allow-http-registry=false",
                        "--allow-insecure-registry=false",
                        "--rekor-url",
                        "https://rekor.sigstore.dev",
                        "--tlog-upload=true",
                        "-a",
                        "tag=tag",
                        "some-registry/namespace/repo@sha256:abcdefg",
                    ],
                    env={"PYTEST_CURRENT_TEST": ANY},
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=CosignSignerResults(status="failed", error_message=""),
            operation_result=ContainerSignResult(
                results=["stderr"], signing_key="test-signing-key", failed=True
            ),
        )


def test_container_sign_digests_only(f_config_cosign_signer_ok, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["some-registry/namespace/repo@sha256:abcdefg"],
        references=[],
        signing_key="test-signing-key",
        repo="",
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))
        res = signer.container_sign(container_sign_operation)

        patched_popen.assert_has_calls(
            [
                call(
                    [
                        "/usr/bin/cosign",
                        "-t",
                        "30s",
                        "sign",
                        "-y",
                        "--key",
                        "test-signing-key",
                        "--allow-http-registry=false",
                        "--allow-insecure-registry=false",
                        "--rekor-url",
                        "https://rekor.sigstore.dev",
                        "--tlog-upload=true",
                        "some-registry/namespace/repo@sha256:abcdefg",
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
            signer_results=CosignSignerResults(status="ok", error_message=""),
            operation_result=ContainerSignResult(
                results=["stderr"], signing_key="test-signing-key", failed=False
            ),
        )


def test_container_sign_mismatch_refs(f_config_cosign_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag1", "some-registry/namespace/repo:tag2"],
        signing_key="test-signing-key",
        repo="",
    )

    with patch("subprocess.Popen") as patched_popen:
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))
        with pytest.raises(ValueError):
            signer.container_sign(container_sign_operation)

        print(patched_popen.mock_calls)
        patched_popen.assert_not_called()


def test_cosignsig_doc_arguments():
    assert CosignSigner.doc_arguments() == {
        "options": {
            "log_level": {"description": "Log level"},
            "rekor_url": {"description": "URL for rekor stl server"},
            "timeout": {"description": "Timeout for cosign operations with units"},
            "upload_tlog": {"description": "upload signing record to rekor"},
            "cosign_bin": {"description": "Path to cosign binary"},
            "allow_http_registry": {"description": "Allow http registry"},
            "allow_insecure_registry": {"description": "Allow insecure registry"},
            "env_variables": {"description": "environment variables used for signing"},
        },
        "examples": {
            "cosign_signer": {
                "log_level": "debug",
                "allow_http_registry": False,
                "allow_insecure_registry": False,
                "cosign_bin": "/usr/local/bin/cosign",
                "env_variables": '{"AWS_ACCESS_KEY_ID": "xxxxxxx",'
                ' "AWS_SECRET_ACCESS_KEY":"yyyyyyyyy"}',
                "rekor_url": "https://rekor.sigstore.dev",
                "timeout": "60s",
                "upload_tlog": "False",
            }
        },
    }


def test_cosignsigresult_to_dict():
    assert CosignSignerResults(status="status", error_message="error_message").to_dict() == {
        "status": "status",
        "error_message": "error_message",
    }


def test_msgsigresult_doc_arguments():
    assert CosignSignerResults.doc_arguments() == {
        "signer_result": {
            "type": "dict",
            "description": "Signing result status.",
            "returned": "always",
            "sample": {"status": "ok", "error_message": ""},
        }
    }
