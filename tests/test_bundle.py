from click.testing import CliRunner

from pubtools.sign.bundle import cli


def test_bundle_msg_container_sign(f_msg_signer, f_config_msg_signer_ok):
    f_msg_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_signer.return_value.sign.return_value.operation_result.signed_claims = []
    f_msg_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cli,
        [
            "msg-container-sign",
            "--signing-key",
            "test-signing-key",
            "--digest",
            "some-digest",
            "--reference",
            "some-reference",
            "--task-id",
            "1",
            "--repo",
            "repo",
            "--config",
            f_config_msg_signer_ok,
        ],
    )
    assert result.exit_code == 0, result.output


def test_bundle_msg_clear_sign(f_msg_signer, f_config_msg_signer_ok):
    f_msg_signer.return_value.sign.return_value.signer_results.to_dict.return_value = {
        "status": "ok"
    }
    f_msg_signer.return_value.sign.return_value.operation_result.outputs = []
    f_msg_signer.return_value.sign.return_value.operation_result.signing_key = ""
    result = CliRunner().invoke(
        cli,
        [
            "msg-clear-sign",
            "--signing-key",
            "test-signing-key",
            "--task-id",
            "1",
            "--repo",
            "repo",
            "--config",
            f_config_msg_signer_ok,
            "hello world",
        ],
    )
    assert result.exit_code == 0, result.output
