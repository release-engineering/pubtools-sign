import json
from unittest.mock import patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from pubtools.sign.ansible import msg_clear_sign
from pubtools.sign.conf.conf import load_config
from pubtools.sign.operations import ClearSignOperation
from pubtools.sign.results import ClearSignResult
from pubtools.sign.results.signing_results import SigningResults
from pubtools.sign.signers.msgsigner import MsgSigner, MsgSignerResults


def set_module_args(args):
    """Prepare arguments so that they will be picked up during module creation.

    :param args: ansible module input args
    :type args: dict
    """
    args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
    basic._ANSIBLE_ARGS = to_bytes(args)


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case."""

    pass


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case."""

    pass


def exit_json(*args, **kwargs):
    """Patch over exit_json, package return data into an exception."""
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """Patch over fail_json, package return data into an exception."""
    kwargs["failed"] = True
    raise AnsibleFailJson(kwargs)


@patch.multiple(basic.AnsibleModule, exit_json=exit_json)
@patch("pubtools.sign.signers.msgsigner.MsgSigner.clear_sign")
def test_run_module_ok(clear_sign_mock, f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))

    parameters = {
        "inputs": ["hello world"],
        "signing_key": "test-signing-key",
        "task_id": "1",
        "config": f_config_msg_signer_ok,
        "repo": "repo",
    }

    clear_sign_operation = ClearSignOperation(
        inputs=parameters["inputs"],
        signing_key=parameters["signing_key"],
        task_id="1",
        repo="repo",
    )

    clear_sign_mock.return_value = SigningResults(
        signer=signer,
        operation=clear_sign_operation,
        signer_results=MsgSignerResults(status="ok", error_message=""),
        operation_result=ClearSignResult(
            outputs=["signed:'hello world'"], signing_key="test-signing-key"
        ),
    )

    set_module_args(parameters)
    with pytest.raises(AnsibleExitJson) as result:
        msg_clear_sign.run_module()
    assert result.value.args[0]["changed"]
    assert (
        result.value.args[0]["message"]["signer_result"]
        == clear_sign_mock.return_value.signer_results.to_dict()
    )
    assert (
        result.value.args[0]["message"]["operation_results"]
        == clear_sign_mock.return_value.operation_result.outputs
    )
    assert (
        result.value.args[0]["message"]["signing_key"]
        == clear_sign_mock.return_value.operation_result.signing_key
    )


@patch.multiple(basic.AnsibleModule, fail_json=fail_json)
@patch("pubtools.sign.signers.msgsigner.MsgSigner.clear_sign")
def test_run_module_failed(clear_sign_mock, f_config_msg_signer_ok):
    signer = MsgSigner()
    signer.load_config(load_config(f_config_msg_signer_ok))

    parameters = {
        "inputs": [f"@{f_config_msg_signer_ok}"],
        "signing_key": "test-signing-key",
        "task_id": "1",
        "config": f_config_msg_signer_ok,
        "repo": "repo",
    }

    clear_sign_operation = ClearSignOperation(
        inputs=parameters["inputs"],
        signing_key=parameters["signing_key"],
        task_id="1",
        repo="repo",
    )

    clear_sign_mock.return_value = SigningResults(
        signer=signer,
        operation=clear_sign_operation,
        signer_results=MsgSignerResults(status="failed", error_message=""),
        operation_result=ClearSignResult(
            outputs=["signed:'hello world'"], signing_key="test-signing-key"
        ),
    )

    set_module_args(parameters)
    with pytest.raises(AnsibleFailJson) as result:
        msg_clear_sign.run_module()
    assert result.value.args[0]["failed"]


@patch.multiple(basic.AnsibleModule, fail_json=fail_json)
@patch("pubtools.sign.signers.msgsigner.MsgSigner.sign")
def test_run_module_exception(sign_mock, f_config_msg_signer_ok):
    sign_mock.side_effect = [ValueError("No configuration file found ...")]
    parameters = {
        "inputs": ["hello world"],
        "signing_key": "test-signing-key",
        "task_id": "1",
        "repo": "repo",
        "config": f_config_msg_signer_ok,
    }
    set_module_args(parameters)
    with pytest.raises(AnsibleFailJson) as result:
        msg_clear_sign.run_module()
    assert result.value.args[0]["failed"]


@patch.multiple(basic.AnsibleModule, exit_json=exit_json)
@patch("pubtools.sign.signers.msgsigner.MsgSigner.sign")
def test_run_module_check_mode(sign_mock, f_config_msg_signer_ok):
    parameters = {
        "inputs": ["hello world"],
        "signing_key": "test-signing-key",
        "task_id": "1",
        "config": f_config_msg_signer_ok,
        "_ansible_check_mode": True,
        "repo": "repo",
    }
    set_module_args(parameters)
    with pytest.raises(AnsibleExitJson):
        msg_clear_sign.run_module()
