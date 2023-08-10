from click.testing import CliRunner

from pubtools.sign.bundle import cli


def test_bundle_msg_container_sign(f_msg_signer, f_config_msg_signer_ok):
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
            "--config",
            f_config_msg_signer_ok,
        ],
    )
    assert result.exit_code == 0, result.output


def test_bundle_msg_clear_sign(f_msg_signer, f_config_msg_signer_ok):
    result = CliRunner().invoke(
        cli,
        [
            "msg-clear-sign",
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
