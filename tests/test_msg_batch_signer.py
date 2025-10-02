import os

from click.testing import CliRunner
import pytest
from unittest.mock import patch, ANY


from pubtools.sign.models.msg import MsgError
from pubtools.sign.signers.msgsigner import (
    MsgBatchSigner,
    MsgSignerResults,
    ContainerSignOperation,
    ContainerSignResult,
    ClearSignOperation,
    ClearSignResult,
    SignRequestType,
    msg_container_sign_main,
)
from pubtools.sign.conf.conf import load_config
from pubtools.sign.models.msg import MsgMessage
from pubtools.sign.results.signing_results import SigningResults


def test_msg_batch_container_sign(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = []
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_keys = []
    f_msg_batch_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "batch",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_msg_batch_container_sign_unsupported(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = []
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_msg_batch_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "unsuported",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 2, result.output


def test_msg_container_sign_keyname(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = []
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_keys = []
    f_msg_batch_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--signing-key-name",
            "test-signing-key-name",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "batch",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_msg_container_sign_requester(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = []
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_keys = []
    f_msg_batch_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--requester",
            "test-requester",
            "--signer-type",
            "batch",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output


def test_msg_container_sign_error(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "error",
        "error_message": "simulated error",
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = []
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_key = ""
    f_msg_batch_signer.return_value.sign.return_value.operation.to_dict.return_value = {}
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "batch",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 1, result.output


def test_msg_container_sign_raw(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = [
        ({"i": 456, "msg": {"errors": [], "signed_claim": "signed"}}, {})
    ]
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "batch",
            "--raw",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0, result.output
    assert result.output == "signed\n"


def test_msg_container_sign_raw_error(f_msg_batch_signer, f_config_msg_batch_signer_ok):
    f_msg_batch_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok",
        "error_message": "",
    }
    f_msg_batch_signer.return_value.sign.return_value.operation_result.results = [
        (
            {
                "i": 456,
                "msg": {"errors": ['no signing key "test-signing-key"'], "signed_claim": None},
            },
            {},
        )
    ]
    f_msg_batch_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        msg_container_sign_main,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config-file",
            f_config_msg_batch_signer_ok,
            "--signer-type",
            "batch",
            "--raw",
        ],
    )
    print(result.stdout)
    assert result.exit_code == 1, result.output
    assert result.output == 'no signing key "test-signing-key"\n'


def test_operations():
    signer = MsgBatchSigner()
    assert signer.operations() == [ContainerSignOperation]


def test_create_msg_batch_message(f_config_msg_batch_signer_ok):
    signer = MsgBatchSigner()
    signer.load_config(load_config(f_config_msg_batch_signer_ok))

    data = ["claim1", "claim2", "claim3"]
    with patch("uuid.uuid4", return_value="1234-5678-abcd-efgh"):
        with patch("pubtools.sign.signers.msgsigner.isodate_now") as patched_date:
            patched_date.return_value = "created-date-Z"
            operation = ContainerSignOperation(
                digests=["some-digest-1", "some-digest-2", "some-digest-3"],
                references=["some-reference-1", "some-reference-2", "some-reference-3"],
                signing_keys=["test-key"],
                task_id="1",
            )
            assert signer._create_msg_batch_message(
                data, "repo", operation, SignRequestType.CONTAINER
            ) == [
                MsgMessage(
                    headers={
                        "service": "pubtools-sign",
                        "environment": "prod",
                        "owner_id": "pubtools-sign-test",
                        "mtype": SignRequestType.CONTAINER,
                        "source": "metadata",
                    },
                    address="topic://Topic.sign",
                    body={
                        "claims": [
                            {
                                "claim_file": "claim1",
                                "sig_keyname": [""],
                                "sig_key_ids": ["test-key"],
                                "manifest_digest": "some-digest-1",
                            },
                            {
                                "claim_file": "claim2",
                                "sig_keyname": [""],
                                "sig_key_ids": ["test-key"],
                                "manifest_digest": "some-digest-2",
                            },
                            {
                                "claim_file": "claim3",
                                "sig_keyname": [""],
                                "sig_key_ids": ["test-key"],
                                "manifest_digest": "some-digest-3",
                            },
                        ],
                        "request_id": "1234-5678-abcd-efgh",
                        "created": "created-date-Z",
                        "requested_by": "pubtools-sign-test",
                        "repo": "repo",
                    },
                )
            ]


def test_sign(f_config_msg_batch_signer_ok):
    signer = MsgBatchSigner()
    signer.load_config(load_config(f_config_msg_batch_signer_ok))
    container_sign_operation = ContainerSignOperation(
        digests=("some-digest-1", "some-digest-2", "some-digest-3", "some-digest-4"),
        references=("some-reference-1", "some-reference-2", "some-reference-3", "some-reference-4"),
        signing_keys=["test-signing-key"],
        task_id="1",
    )

    with patch(
        "pubtools.sign.signers.msgsigner.MsgBatchSigner.container_sign"
    ) as patched_container_sign:
        signer.sign(container_sign_operation)
        patched_container_sign.assert_called_once()


@patch("uuid.uuid4", side_effect=["1234-5678-abcd-efgh", "abcd-efgh-1234-5678"])
def test_container_sign(
    patched_uuid, f_config_msg_batch_signer_ok, f_client_certificate, f_ca_certificate
):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdef-1", "sha256:abcdefg-2", "sha256:abcdefg-3", "sha256:abcdefg-4"],
        references=[
            "some-registry/namespace/repo:tag1",
            "some-registry/namespace/repo:tag2",
            "some-registry/namespace/repo:tag3",
            "some-registry/namespace/repo:tag4",
        ],
        signing_keys=["test-signing-key"],
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.run.return_value = []
            patched_recv_client.return_value.recv = {
                "1234-5678-abcd-efgh": (
                    {"msg": {"errors": [], "signed_claim": "signed:'claim1'"}},
                    {"fake": "headers"},
                ),
                "abcd-efgh-1234-5678": (
                    {"msg": {"errors": [], "signed_claim": "signed:'claim2'"}},
                    {"fake": "headers"},
                ),
            }
            patched_recv_client.return_value.get_errors.return_value = []

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            res = signer.container_sign(container_sign_operation)

            print(patched_send_client.mock_calls)
            patched_send_client.assert_called_with(
                messages=[ANY, ANY],
                broker_urls=["amqps://broker-01:5671", "amqps://broker-02:5671"],
                cert=f_client_certificate,
                ca_cert=f_ca_certificate,
                retries=3,
                errors=patched_recv_client.return_value.get_errors.return_value,
            )

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(status="ok", error_message=""),
                operation_result=ContainerSignResult(
                    results=[
                        (
                            {"msg": {"errors": [], "signed_claim": "signed:'claim1'"}},
                            {"fake": "headers"},
                        ),
                        (
                            {"msg": {"errors": [], "signed_claim": "signed:'claim2'"}},
                            {"fake": "headers"},
                        ),
                    ],
                    signing_keys=["test-signing-key"],
                    failed=False,
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_alias(
    patched_uuid, f_config_msg_batch_signer_aliases, f_client_certificate
):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["beta"],
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.run.return_value = []
            patched_recv_client.return_value.recv = {
                "1234-5678-abcd-efgh": (
                    {"msg": {"errors": [], "signed_claim": "signed:'claim'"}},
                    {"fake": "headers"},
                )
            }
            patched_recv_client.return_value.get_errors.return_value = []

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_aliases))

            with patch(
                "pubtools.sign.signers.msgsigner.MsgBatchSigner._construct_signing_batch_message"
            ) as patch_construct_signing_message:
                patch_construct_signing_message.return_value = {
                    "request_id": "1234-5678-abcd-efgh",
                }
                res = signer.container_sign(container_sign_operation)
                patch_construct_signing_message.assert_called_once_with(
                    ANY,
                    ["abcde1245"],
                    "namespace/repo",
                    extra_attrs={"pub_task_id": "1", "manifest_digest": ["sha256:abcdefg"]},
                    signing_key_names=[""],
                    sig_type="container_signature",
                )

            patched_send_client.assert_called_with(
                messages=[ANY],
                broker_urls=["amqps://broker-01:5671", "amqps://broker-02:5671"],
                cert=f_client_certificate,
                ca_cert=os.path.expanduser("~/messaging/ca-cert.crt"),
                retries=3,
                errors=patched_recv_client.return_value.get_errors.return_value,
            )

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(status="ok", error_message=""),
                operation_result=ContainerSignResult(
                    results=[
                        (
                            {"msg": {"errors": [], "signed_claim": "signed:'claim'"}},
                            {"fake": "headers"},
                        )
                    ],
                    signing_keys=["beta"],
                    failed=False,
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_recv_errors(patched_uuid, f_config_msg_batch_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["test-signing-key"],
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.get_errors.return_value = [
                MsgError(
                    name="TestError", description="test error description", source="test-source"
                )
            ]
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ContainerSignResult(
                    results=[""], signing_keys=["test-signing-key"], failed=False
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_send_errors(patched_uuid, f_config_msg_batch_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["test-signing-key"],
    )
    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = [
                MsgError(
                    name="TestError", description="test error description", source="test-source"
                )
            ]
            patched_recv_client.return_value.run.return_value = []
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ContainerSignResult(
                    results=[""], signing_keys=["test-signing-key"], failed=False
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_wrong_inputs(patched_uuid, f_config_msg_batch_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag", "some-registry/namespace/repo:tag2"],
        signing_keys=["test-signing-key"],
    )

    signer = MsgBatchSigner()
    signer.load_config(load_config(f_config_msg_batch_signer_ok))
    with pytest.raises(ValueError):
        signer.container_sign(container_sign_operation)


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_recv_timeout_fails(patched_uuid, f_config_msg_batch_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["test-signing-key"],
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.get_errors.return_value = [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
            ]
            patched_recv_client.return_value.recv = {
                "1234-5678-abcd-efgh": (
                    {"msg": {"errors": [], "signed_claim": "signed:'claim'"}},
                    {"fake": "headers"},
                )
            }

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            signer.retries = 2
            signer.send_retries = 1

            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="error",
                    error_message="MessagingTimeout : Out of time when receiving messages\n"
                    "MessagingTimeout : Out of time when receiving messages\n",
                ),
                operation_result=ContainerSignResult(
                    results=[""], signing_keys=["test-signing-key"], failed=False
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_recv_timeout_ok(patched_uuid, f_config_msg_batch_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_keys=["test-signing-key"],
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.get_errors.return_value = [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
            ]
            patched_recv_client.return_value.recv = {
                "1234-5678-abcd-efgh": (
                    {"msg": {"errors": [], "signed_claim": "signed:'claim'"}},
                    {"fake": "headers"},
                )
            }

            signer = MsgBatchSigner()
            signer.retries = 2
            signer.send_retries = 1

            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="ok",
                    error_message="",
                ),
                operation_result=ContainerSignResult(
                    results=[
                        (
                            {"msg": {"errors": [], "signed_claim": "signed:'claim'"}},
                            {"fake": "headers"},
                        )
                    ],
                    signing_keys=["test-signing-key"],
                    failed=False,
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_clear_sign_recv_timeout(patched_uuid, f_config_msg_batch_signer_ok):
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"], signing_keys=["test-signing-key"], task_id="1", repo="repo"
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value._errors = [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source="test-source",
                ),
            ]
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}

            signer = MsgBatchSigner()
            signer.load_config(load_config(f_config_msg_batch_signer_ok))
            signer.retries = 2
            signer.send_retries = 1

            res = signer.clear_sign(clear_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=clear_sign_operation,
                signer_results=MsgSignerResults(
                    status="error",
                    error_message="MessagingTimeout : Out of time when receiving messages\n"
                    "MessagingTimeout : Out of time when receiving messages\n",
                ),
                operation_result=ClearSignResult(outputs=[""], signing_keys=["test-signing-key"]),
            )


def test_recv_client_recv_message_break(
    f_cleanup_msgsigner_messages,
    f_qpid_broker,
    f_msgsigner_listen_to_topic,
    f_fake_msgsigner,
    f_msgsigner_send_to_queue,
    f_client_certificate,
    f_ca_certificate,
    f_config_msg_batch_signer_ok2,
):
    qpid_broker, port = f_qpid_broker
    container_sign_operation = ContainerSignOperation(
        digests=("some-digest",),
        references=("some/reference:some-tag",),
        signing_keys=["test-signing-key"],
        task_id="1",
    )
    with patch(
        "pubtools.sign.clients.msg_recv_client.RecvClient.get_errors", autospec=True
    ) as patched_recv_get_errors, patch(
        "pubtools.sign.clients.msg_recv_client.RecvClient.get_received", autospec=True
    ) as patched_recv_get_received, patch(
        "uuid.uuid4", return_value="1234-5678-abcd-efgh"
    ) as _:
        patched_recv_get_errors.side_effect = [
            [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source=ANY,
                )
            ],
            [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source=ANY,
                )
            ],
            [
                MsgError(
                    name="MessagingTimeout",
                    description="Out of time when receiving messages",
                    source=ANY,
                )
            ],
            [],
        ]
        patched_recv_get_received.side_effect = [{"1234-5678-abcd-efgh": True}]
        signer = MsgBatchSigner()
        signer.load_config(load_config(f_config_msg_batch_signer_ok2))
        signer.retries = 2
        signer.send_retries = 1
        res = signer.container_sign(container_sign_operation)

        assert res == SigningResults(
            signer=signer,
            operation=container_sign_operation,
            signer_results=MsgSignerResults(
                status="error",
                error_message="MessagingTimeout : Out of time when receiving messages\n",
            ),
            operation_result=ContainerSignResult(
                results=[""], signing_keys=["test-signing-key"], failed=False
            ),
        )


def test_msgsig_doc_arguments():
    assert MsgBatchSigner.doc_arguments() == {
        "options": {
            "messaging_brokers": {"description": "List of brokers URLS"},
            "messaging_cert_key": {
                "description": "Client certificate + key for messaging authorization"
            },
            "messaging_ca_cert": {"description": "Messaging CA certificate"},
            "topic_send_to": {"description": "Topic where to send the messages"},
            "topic_listen_to": {"description": "Topic where to listen for replies"},
            "creator": {"description": "Identification of creator of signing request"},
            "environment": {"description": "Environment indetification in sent messages"},
            "service": {"description": "Service identificator"},
            "timeout": {"description": "Timeout for messaging receive"},
            "retries": {"description": "Retries for messaging receive"},
            "send_retries": {"description": "Retries for messaging send+receive"},
            "message_id_key": {
                "description": "Attribute name in message body which should be used as message id"
            },
            "log_level": {"description": "Log level"},
            "key_aliases": {"description": "Aliases for signing keys"},
        },
        "examples": {
            "msg_batch_signer": {
                "messaging_brokers": ["amqps://broker-01:5671", "amqps://broker-02:5671"],
                "messaging_cert_key": "~/messaging/cert.pem",
                "messaging_ca_cert": "~/messaging/ca_cert.crt",
                "topic_send_to": "topic://Topic.sign",
                "topic_listen_to": "queue://Consumer.{{creator}}.{{task_id}}.Topic.sign."
                "{{task_id}}",
                "creator": "pubtools-sign",
                "environment": "prod",
                "service": "pubtools-sign",
                "timeout": 1,
                "retries": 3,
                "send_retries": 2,
                "message_id_key": "123",
                "log_level": "debug",
                "key_aliases": "{'production':'abcde1245'}",
            }
        },
    }


def test_msgsigresult_to_dict():
    assert MsgSignerResults(status="status", error_message="error_message").to_dict() == {
        "status": "status",
        "error_message": "error_message",
    }


def test_msgsigresult_doc_arguments():
    assert MsgSignerResults.doc_arguments() == {
        "signer_result": {
            "type": "dict",
            "description": "Signing result status.",
            "returned": "always",
            "sample": {"status": "ok", "error_message": ""},
        }
    }
