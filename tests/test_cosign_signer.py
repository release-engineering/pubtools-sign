from click.testing import CliRunner
import pytest
import requests_mock
from unittest.mock import patch, Mock, call, ANY

from pubtools.sign.signers.cosignsigner import (
    CosignSigner,
    CosignSignerResults,
    ContainerSignOperation,
    ContainerSignResult,
    cosign_container_sign_main,
    cosign_list_existing_signatures,
)
from pubtools.sign.conf.conf import load_config
from pubtools.sign.exceptions import UnsupportedOperation
from pubtools.sign.results.signing_results import SigningResults


def mock_registry_responses(requests_mock, registry, repo, sig_response=200, registry_response=401):
    requests_mock.get(  # nosec
        "https://example-registry.io/v2/auth?service=example-registry.io"
        "&scope=repository%3Anamespace%2Frepo%3Apull",
        [
            {
                "headers": {"authorization": "Bearer some-token"},
                "status_code": 200,
                "json": {},
            },
        ],
    )
    requests_mock.get(  # nosec
        "https://example-registry.io/v2/namespace/repo/manifests/sha256-abcdefg.sig",
        [
            {
                "headers": {
                    "www-authenticate": f'Bearer realm="https://{registry}/v2/auth",'
                    f'service="{registry}",scope="repository:{repo}:pull"'
                },
                "status_code": registry_response,
            },
            {
                "headers": {
                    "www-authenticate": f'Bearer realm="https://{registry}/v2/auth",'
                    f'service="{registry}",scope="repository:{repo}:pull'
                },
                "status_code": sig_response,
                "json": {},
            },
        ],
    )


@pytest.fixture
def f_expected_container_sign_args(f_config_cosign_signer_ok):
    return [
        "--signing-key",
        "test-signing-key",
        "--digest",
        "some-digest",
        "--reference",
        "some-reference",
        "--config-file",
        f_config_cosign_signer_ok,
    ]


@pytest.fixture
def f_expected_container_sign_identity_args(f_config_cosign_signer_ok):
    return [
        "--signing-key",
        "test-signing-key",
        "--digest",
        "some-digest",
        "--reference",
        "some-reference",
        "--identity",
        "some-registry/namespace/repo",
        "--config-file",
        f_config_cosign_signer_ok,
    ]


@pytest.fixture
def f_expected_cosign_sign_args():
    return [
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
        "--registry-username",
        "some-user",
        "--registry-password",
        "some-password",
        "-a",
        "tag=tag",
        "some-registry/namespace/repo@sha256:abcdefg",
    ]


@pytest.fixture
def f_expected_cosign_sign_identity_args():
    return [
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
        "--registry-username",
        "some-user",
        "--registry-password",
        "some-password",
        "--sign-container-identity",
        "some-registry/namespace/repo",
        "-a",
        "tag=tag",
        "some-registry/namespace/repo@sha256:abcdefg",
    ]


@pytest.fixture
def f_expected_cosign_triangulate_args():
    return [
        "/usr/bin/cosign",
        "-t",
        "30s",
        "triangulate",
        "--allow-http-registry=false",
        "--allow-insecure-registry=false",
        "--registry-username",
        "some-user",
        "--registry-password",
        "some-password",
        "example-registry.io/namespace/repo:latest",
    ]


def test_cosign_container_sign(f_cosign_signer, f_expected_container_sign_args):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_cosign_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(cosign_container_sign_main, f_expected_container_sign_args)
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_cosign_container_identity_sign(f_cosign_signer, f_expected_container_sign_identity_args):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_cosign_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(cosign_container_sign_main, f_expected_container_sign_identity_args)
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_cosign_container_sign_error(f_cosign_signer, f_expected_container_sign_args):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_cosign_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        cosign_container_sign_main,
        f_expected_container_sign_args,
    )
    print(result.stdout)
    assert result.exit_code == 1, result.output


def test_cosign_container_sign_raw(f_cosign_signer, f_expected_container_sign_args):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = ["signed"]
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main, f_expected_container_sign_args + ["--raw"]
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output
    assert result.output == "signed\n"


def test_cosign_container_sign_raw_error(f_cosign_signer, f_expected_container_sign_args):
    f_cosign_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_cosign_signer.return_value.sign.return_value.operation_result.results = []
    f_cosign_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cosign_container_sign_main, f_expected_container_sign_args + ["--raw"]
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
    )
    with patch(
        "pubtools.sign.signers.cosignsigner.CosignSigner.container_sign"
    ) as patched_container_sign:
        signer.sign(container_sign_operation)
        patched_container_sign.assert_called_once()
        with pytest.raises(UnsupportedOperation):
            signer.sign(Mock())


def test_container_sign(f_config_cosign_signer_ok, f_environ, f_expected_cosign_sign_args):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
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
                    f_expected_cosign_sign_args,
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


def test_container_sign_identity(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_sign_identity_args
):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        identity_references=["some-registry/namespace/repo"],
        signing_key="test-signing-key",
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
                    f_expected_cosign_sign_identity_args,
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


def test_container_sign_alias(f_config_cosign_signer_aliases, f_environ):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="beta",
    )

    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = ("stdout", "stderr")

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_aliases))
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
                        "abcde1245",
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
                results=["stderr"], signing_key="beta", failed=False
            ),
        )


def test_container_sign_error(f_config_cosign_signer_ok, f_environ, f_expected_cosign_sign_args):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
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
                    f_expected_cosign_sign_args,
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
            signer_results=CosignSignerResults(status="failed", error_message="stderr"),
            operation_result=ContainerSignResult(
                results=["stderr"], signing_key="test-signing-key", failed=True
            ),
        )


def test_container_sign_digests_only(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_sign_args
):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["some-registry/namespace/repo@sha256:abcdefg"],
        references=[],
        signing_key="test-signing-key",
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
                        "--registry-username",
                        "some-user",
                        "--registry-password",
                        "some-password",
                        "some-registry/namespace/repo@sha256:abcdefg",
                    ],
                    env=ANY,
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


def test_container_sign_digests_only_indentity(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_sign_args
):
    container_sign_operation = ContainerSignOperation(
        task_id="",
        digests=["some-registry/namespace/repo@sha256:abcdefg"],
        references=[],
        identity_references=["some-registry/namespace/repo"],
        signing_key="test-signing-key",
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
                        "--registry-username",
                        "some-user",
                        "--registry-password",
                        "some-password",
                        "--sign-container-identity",
                        "some-registry/namespace/repo",
                        "some-registry/namespace/repo@sha256:abcdefg",
                    ],
                    env=ANY,
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
            "registry_auth_file": {"description": "Registry basic auth file"},
            "registry_password": {"description": "Registry basic password"},
            "registry_user": {"description": "Registry basic user"},
            "rekor_url": {"description": "URL for rekor stl server"},
            "timeout": {"description": "Timeout for cosign operations with units"},
            "upload_tlog": {"description": "upload signing record to rekor"},
            "cosign_bin": {"description": "Path to cosign binary"},
            "allow_http_registry": {"description": "Allow http registry"},
            "allow_insecure_registry": {"description": "Allow insecure registry"},
            "env_variables": {"description": "environment variables used for signing"},
            "key_aliases": {"description": "Aliases for signing keys"},
            "retries": {"description": "Number of retries for http requests"},
        },
        "examples": {
            "cosign_signer": {
                "log_level": "debug",
                "registry_auth_file": "auth.json",
                "registry_password": "password",
                "registry_user": "username",
                "allow_http_registry": False,
                "allow_insecure_registry": False,
                "cosign_bin": "/usr/local/bin/cosign",
                "env_variables": '{"AWS_ACCESS_KEY_ID": "xxxxxxx",'
                ' "AWS_SECRET_ACCESS_KEY":"yyyyyyyyy"}',
                "rekor_url": "https://rekor.sigstore.dev",
                "timeout": "60s",
                "upload_tlog": "False",
                "key_aliases": "{'production':'abcde1245'}",
                "retries": 5,
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


def test_container_existing_signatures(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(m, "example-registry.io", "namespace/repo")
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (True, ["example-registry.io/namespace/repo:sha256-abcdefg.sig"])


def test_container_existing_signatures_error(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 1
        patched_popen().communicate.return_value = ("stdout1\nstdout2", "stderr")

        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(m, "example-registry.io", "namespace/repo")
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (False, "stderr")


def test_container_existing_signatures_no_signature(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(m, "example-registry.io", "namespace/repo", sig_response=404)
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (True, "")


def test_container_existing_signatures_no_auth_needed(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(
                m, "example-registry.io", "namespace/repo", registry_response=200
            )
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (True, ["example-registry.io/namespace/repo:sha256-abcdefg.sig"])


def test_container_existing_signatures_no_auth_provided(
    f_config_cosign_signer_no_auth, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_no_auth))

        with requests_mock.Mocker() as m:
            mock_registry_responses(
                m, "example-registry.io", "namespace/repo", registry_response=401
            )
            with pytest.raises(ValueError):
                signer.existing_signatures("example-registry.io/namespace/repo:latest")


def test_container_existing_signatures_repo_no_found(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(
                m,
                "example-registry.io",
                "namespace/repo",
                sig_response=200,
                registry_response=404,
            )
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (True, "")


def test_container_existing_signatures_repo_registry_sig_error(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(
                m,
                "example-registry.io",
                "namespace/repo",
                sig_response=500,
            )
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (False, "Unexpected Error: 500 - {}")


def test_container_existing_signatures_repo_registry_registry_error(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        signer = CosignSigner()
        signer.load_config(load_config(f_config_cosign_signer_ok))

        with requests_mock.Mocker() as m:
            mock_registry_responses(
                m,
                "example-registry.io",
                "namespace/repo",
                registry_response=500,
            )
            res = signer.existing_signatures("example-registry.io/namespace/repo:latest")

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (False, "Unexpected Error: 500 - ")


def test_container_existing_signatures_main(
    f_config_cosign_signer_ok, f_environ, f_expected_cosign_triangulate_args
):
    with patch("subprocess.Popen") as patched_popen:
        patched_popen().returncode = 0
        patched_popen().communicate.return_value = (
            "example-registry.io/namespace/repo:sha256-abcdefg.sig",
            "stderr",
        )
        with requests_mock.Mocker() as m:
            mock_registry_responses(m, "example-registry.io", "namespace/repo")
            res = cosign_list_existing_signatures(
                f_config_cosign_signer_ok, "example-registry.io/namespace/repo:latest"
            )

        patched_popen.assert_has_calls(
            [
                call(
                    f_expected_cosign_triangulate_args,
                    env=ANY,
                    stderr=-1,
                    stdout=-1,
                    text=True,
                )
            ]
        )
        assert res == (True, ["example-registry.io/namespace/repo:sha256-abcdefg.sig"])
