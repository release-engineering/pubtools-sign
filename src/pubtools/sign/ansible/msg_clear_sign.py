#!/usr/bin/python

from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule

import yaml

from pubtools.sign.results import ClearSignResult
from pubtools.sign.operations.clearsign import ClearSignOperation
from pubtools.sign.signers.msgsigner import MsgSigner, msg_clear_sign, MsgSignerResults

__metaclass__ = type


DOCUMENTATION = r"""
---
module: msg_clear_sign
version_added: "0.1"
short_description: This is used to do clear sign
description:
    - Sign data with clear sign.
{0}  config:
    description:
      - Config file path.
      - By default, it will read from "~/.config/pubtools-sign/conf.yaml" or
        "/etc/pubtools-sign/conf.yaml"
    required: false
    type: str
{1}
extends_documentation_fragment:
    - action_common_attributes
attributes:
    check_mode:
        support: full
    diff_mode:
        support: none
    platform:
        platforms: posix
author:
    - zxiong (@redhat.com)
""".format(
    yaml.dump({"options": ClearSignOperation.doc_arguments().get("options")}),
    yaml.dump({"config file options": MsgSigner.doc_arguments().get("options")}),
)

EXAMPLES = r"""
# Example for msg clear sign
{0}
The example of the config file /etc/pubtools-sign/conf.yaml:
{1}
""".format(
    yaml.dump([{"msg_clear_sign": ClearSignOperation.doc_arguments().get("examples")}]),
    yaml.dump(MsgSigner.doc_arguments().get("examples")),
)

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return
# values.
{0}
{1}
""".format(
    yaml.dump(MsgSignerResults.doc_arguments()), yaml.dump(ClearSignResult.doc_arguments())
)


def run_module():
    """Run clearsign module."""
    # Define available arguments/parameters a user can pass to the module
    module_args = dict(
        inputs=dict(type="list", required=True),
        signing_key=dict(type="str", required=True),
        task_id=dict(type="str", required=True),
        repo=dict(type="str", required=True),
        config=dict(type="str", required=False),
    )

    result = dict(changed=False, message="")
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # If the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    inputs = module.params["inputs"]
    signing_key = module.params["signing_key"]
    task_id = module.params["task_id"]
    config = module.params["config"]
    repo = module.params["repo"]

    # Call clear sign and return signed data
    try:
        signing_result = msg_clear_sign(
            inputs, signing_key=signing_key, task_id=task_id, config=config, repo=repo
        )
    except Exception as ex:
        module.fail_json(msg=str(ex), exception=ex)

    result["message"] = signing_result

    # signing failed
    if signing_result["signer_result"]["status"] != "ok":
        module.fail_json(msg=signing_result["signer_result"]["error_message"], **result)

    # signing successfully
    result["changed"] = True
    module.exit_json(**result)


if __name__ == "__main__":
    run_module()
