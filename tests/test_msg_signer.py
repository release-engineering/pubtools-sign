import base64
import json

from click.testing import CliRunner
import pytest
from unittest.mock import patch, Mock


from pubtools.sign.models.msg import MsgError
from pubtools.sign.signers.msgsigner import (
    MsgSigner,
    MsgSignerResults,
    msg_clear_sign,
    _msg_clear_sign,
    msg_container_sign,
    ContainerSignOperation,
    ContainerSignResult,
    ClearSignOperation,
    ClearSignResult,
    msg_clear_sign_main,
    msg_container_sign_main,
    _get_config_file,
)
from pubtools.sign.conf.conf import load_config
from pubtools.sign.models.msg import MsgMessage
from pubtools.sign.exceptions import UnsupportedOperation
from pubtools.sign.results.signing_results import SigningResults


def test_msg_container_sign(f_msg_signer, f_config_msg_signer_ok):
    result = CliRunner().invoke(
        msg_container_sign,
        [
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--config",
            f_config_msg_signer_ok,
        ],
    )
    assert result.exit_code == 0, result.output

    f_msg_signer.return_value.load_config.assert_called_with(load_config(f_config_msg_signer_ok))
    operation = ContainerSignOperation(
        digests=("some-digest",),
        references=("some-reference",),
        signing_key="test-signing-key",
        task_id="1",
    )
    f_msg_signer.return_value.sign.assert_called_with(operation)


def test_msg_clearsign_sign(f_msg_signer, f_config_msg_signer_ok):
    result = CliRunner().invoke(
        msg_clear_sign,
        [
            "--signing-key",
            "test-signing-key",
            "--task-id",
            "1",
            "--config",
            f_config_msg_signer_ok,
            "hello world",
        ],
    )
    assert result.exit_code == 0, result.output


def test_msg_clearsign_sign_file_input(f_msg_signer, f_config_msg_signer_ok):
    result = CliRunner().invoke(
        msg_clear_sign,
        [
            "--signing-key",
            "test-signing-key",
            "--task-id",
            "1",
            "--config",
            f_config_msg_signer_ok,
            f"@{f_config_msg_signer_ok}",
        ],
    )
    assert result.exit_code == 0, result.output


def test__msg_clearsign_sign(f_msg_signer, f_config_msg_signer_ok):
    _msg_clear_sign(
        ["hello world"], signing_key="test-signing-key", task_id="1", config=f_config_msg_signer_ok
    )

    f_msg_signer.return_value.load_config.assert_called_with(load_config(f_config_msg_signer_ok))
    operation = ClearSignOperation(
        inputs=["hello world"],
        signing_key="test-signing-key",
        task_id="1",
    )
    f_msg_signer.return_value.sign.assert_called_with(operation)


def test__msg_clearsign_sign_file_input(f_msg_signer, f_config_msg_signer_ok):
    _msg_clear_sign(
        [f"@{f_config_msg_signer_ok}"],
        signing_key="test-signing-key",
        task_id="1",
        config=f_config_msg_signer_ok,
    )

    f_msg_signer.return_value.load_config.assert_called_with(load_config(f_config_msg_signer_ok))
    operation = ClearSignOperation(
        inputs=[open(f_config_msg_signer_ok).read()],
        signing_key="test-signing-key",
        task_id="1",
    )
    f_msg_signer.return_value.sign.assert_called_with(operation)


def test_msg_clear_sign_main():
    with patch("pubtools.sign.signers.msgsigner.msg_clear_sign") as patched:
        patched.return_value = ""
        msg_clear_sign_main()
        patched.assert_called_once()


def test_msg_container_sign_main():
    with patch("pubtools.sign.signers.msgsigner.msg_container_sign") as patched:
        patched.return_value = ""
        msg_container_sign_main()
        patched.assert_called_once()


def test_get_config_file(f_config_msg_signer_ok):
    assert _get_config_file(f_config_msg_signer_ok) == f_config_msg_signer_ok


def test_get_config_file_default(f_config_msg_signer_ok):
    def _patched_exist(fname):
        if fname == "/etc/pubtools-sign/conf.yaml":
            return True
        else:
            return False

    with patch("os.path.exists", side_effect=_patched_exist):
        assert _get_config_file("/non-existining/file") == "/etc/pubtools-sign/conf.yaml"


def test_get_config_no_configuration_found():
    with patch("os.path.exists", return_value=False):
        with pytest.raises(ValueError):
            _get_config_file("/non-existining/file")


def test__construct_signing_message(f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))
    with patch("uuid.uuid4", return_value="1234-5678-abcd-efgh"):
        with patch("pubtools.sign.signers.msgsigner.isodate_now") as patched_date:
            patched_date.return_value = "created-date-Z"
            ret = signer._construct_signing_message("some-claim", "some-signing-key", {})
            assert ret == {
                "sig_key_id": "some-signing-key",
                "claim_file": "some-claim",
                "request_id": "1234-5678-abcd-efgh",
                "created": "created-date-Z",
                "requested_by": "pubtools-sign-test",
            }


def test__construct_headers(f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))
    with patch("uuid.uuid4", return_value="1234-5678-abcd-efgh"):
        with patch("pubtools.sign.signers.msgsigner.isodate_now") as patched_date:
            patched_date.return_value = "created-date-Z"
            ret = signer._construct_headers("test-sign-type", extra_attrs={"extra": "extra"})
            assert ret == {
                "service": "pubtools-sign",
                "environment": "prod",
                "owner_id": "pubtools-sign-test",
                "mtype": "test-sign-type",
                "source": "metadata",
                "extra": "extra",
            }


def test_operations():
    signer = MsgSigner()
    assert signer.operations() == [ContainerSignOperation, ClearSignOperation]


def test_create_msg_message(f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))

    data = "test-data"
    with patch("uuid.uuid4", return_value="1234-5678-abcd-efgh"):
        with patch("pubtools.sign.signers.msgsigner.isodate_now") as patched_date:
            patched_date.return_value = "created-date-Z"
            operation = ClearSignOperation(
                inputs=["test-data-inputs"], signing_key="test-key", task_id="1"
            )
            assert signer._create_msg_message(data, operation, "container_signature") == MsgMessage(
                headers={
                    "service": "pubtools-sign",
                    "environment": "prod",
                    "owner_id": "pubtools-sign-test",
                    "mtype": "container_signature",
                    "source": "metadata",
                },
                address="topic://Topic.sign",
                body={
                    "sig_key_id": "test-key",
                    "claim_file": "test-data",
                    "request_id": "1234-5678-abcd-efgh",
                    "created": "created-date-Z",
                    "requested_by": "pubtools-sign-test",
                },
            )
            assert signer._create_msg_message(data, operation, "clearsign_signature") == MsgMessage(
                headers={
                    "service": "pubtools-sign",
                    "environment": "prod",
                    "owner_id": "pubtools-sign-test",
                    "mtype": "clearsign_signature",
                    "source": "metadata",
                },
                address="topic://Topic.sign",
                body={
                    "sig_key_id": "test-key",
                    "data": "test-data",
                    "request_id": "1234-5678-abcd-efgh",
                    "created": "created-date-Z",
                    "requested_by": "pubtools-sign-test",
                },
            )


def test_sign(f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))
    container_sign_operation = ContainerSignOperation(
        digests=("some-digest",),
        references=("some-reference",),
        signing_key="test-signing-key",
        task_id="1",
    )
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"],
        signing_key="test-signing-key",
        task_id="1",
    )

    with patch("pubtools.sign.signers.msgsigner.MsgSigner.clear_sign") as patched_clear_sign:
        with patch(
            "pubtools.sign.signers.msgsigner.MsgSigner.container_sign"
        ) as patched_container_sign:
            signer.sign(container_sign_operation)
            patched_container_sign.assert_called_once()
            signer.sign(clear_sign_operation)
            patched_clear_sign.assert_called_once()
            with pytest.raises(UnsupportedOperation):
                signer.sign(Mock())


def test_create_manifest_claim_message():
    signer = MsgSigner()
    assert signer.create_manifest_claim_message(
        "some-key", "some-digest", "some-reference"
    ) == base64.b64encode(
        json.dumps(
            {
                "critical": {
                    "type": "atomic container signature",
                    "image": {"docker-manifest-digest": "some-digest"},
                    "identity": {"docker-reference": "some-reference"},
                },
                "optional": {"creator": "pubtools-sign"},
            }
        ).encode("latin-1")
    ).decode(
        "latin-1"
    )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_clear_sign(patched_uuid, f_config_msg_signer_ok):
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"],
        signing_key="test-signing-key",
        task_id="1",
    )
    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.run.return_value = []
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}
            patched_recv_client.return_value.errors = []

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.clear_sign(clear_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=clear_sign_operation,
                signer_results=MsgSignerResults(status="ok", error_message=""),
                operation_result=ClearSignResult(
                    outputs=["signed:'hello world'"], signing_key="test-signing-key"
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_clear_sign_recv_errors(patched_uuid, f_config_msg_signer_ok):
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"],
        signing_key="test-signing-key",
        task_id="1",
    )
    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.errors = [
                MsgError(
                    name="TestError", description="test error description", source="test-source"
                )
            ]
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.clear_sign(clear_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=clear_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ClearSignResult(outputs=[""], signing_key="test-signing-key"),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_clear_sign_send_errors(patched_uuid, f_config_msg_signer_ok):
    clear_sign_operation = ClearSignOperation(
        inputs=["hello world"],
        signing_key="test-signing-key",
        task_id="1",
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

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.clear_sign(clear_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=clear_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ClearSignResult(outputs=[""], signing_key="test-signing-key"),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign(patched_uuid, f_config_msg_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.run.return_value = []
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'claim'"}
            patched_recv_client.return_value.errors = []

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(status="ok", error_message=""),
                operation_result=ContainerSignResult(
                    signed_claims=["signed:'claim'"], signing_key="test-signing-key"
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_recv_errors(patched_uuid, f_config_msg_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
    )

    with patch("pubtools.sign.signers.msgsigner.SendClient") as patched_send_client:
        with patch("pubtools.sign.signers.msgsigner.RecvClient") as patched_recv_client:
            patched_send_client.return_value.run.return_value = []
            patched_recv_client.return_value.errors = [
                MsgError(
                    name="TestError", description="test error description", source="test-source"
                )
            ]
            patched_recv_client.return_value.recv = {"1234-5678-abcd-efgh": "signed:'hello world'"}

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ContainerSignResult(
                    signed_claims=[""], signing_key="test-signing-key"
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_send_errors(patched_uuid, f_config_msg_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag"],
        signing_key="test-signing-key",
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

            signer = MsgSigner()
            signer.load_config(load_config(f_config_msg_signer_ok))
            res = signer.container_sign(container_sign_operation)

            assert res == SigningResults(
                signer=signer,
                operation=container_sign_operation,
                signer_results=MsgSignerResults(
                    status="error", error_message="TestError : test error description\n"
                ),
                operation_result=ContainerSignResult(
                    signed_claims=[""], signing_key="test-signing-key"
                ),
            )


@patch("uuid.uuid4", return_value="1234-5678-abcd-efgh")
def test_container_sign_wrong_inputs(patched_uuid, f_config_msg_signer_ok):
    container_sign_operation = ContainerSignOperation(
        task_id="1",
        digests=["sha256:abcdefg"],
        references=["some-registry/namespace/repo:tag", "some-registry/namespace/repo:tag2"],
        signing_key="test-signing-key",
    )

    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))
    with pytest.raises(ValueError):
        signer.container_sign(container_sign_operation)


def test_msgsig_doc_arguments():
    assert MsgSigner.doc_arguments() == {
        "options": {
            "messaging_brokers": {"description": "List of brokers URLS"},
            "messaging_cert": {"description": "Client certificate for messaging authorization"},
            "messaging_ca_cert": {"description": "Messaging CA certificate"},
            "topic_send_to": {"description": "Topic where to send the messages"},
            "topic_listen_to": {"description": "Topic where to listen for replies"},
            "creator": {"description": "Identification of creator of signing request"},
            "environment": {"description": "Environment indetification in sent messages"},
            "service": {"description": "Service identificator"},
            "timeout": {"description": "Timeout for messaging sent/receive"},
            "retries": {"description": "Retries for messaging sent/receive"},
            "message_id_key": {
                "description": "Attribute name in message body which should be used as message id"
            },
            "log_level": {"description": "Log level"},
        },
        "examples": {
            "msg_signer": {
                "messaging_brokers": ["amqps://broker-01:5671", "amqps://broker-02:5671"],
                "messaging_cert": "~/messaging/cert.crt",
                "messaging_ca_cert": "~/messaging/ca_cert.crt",
                "topic_send_to": "topic://Topic.sign",
                "topic_listen_to": "queue://Consumer.{{creator}}.{{task_id}}.Topic.sign."
                "{{task_id}}",
                "creator": "pubtools-sign",
                "environment": "prod",
                "service": "pubtools-sign",
                "timeout": 1,
                "retries": 3,
                "message_id_key": "123",
                "log_level": "debug",
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
