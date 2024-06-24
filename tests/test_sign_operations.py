from pubtools.sign.operations import (
    ClearSignOperation,
    ContainerSignOperation,
)


def test_containersign_operation_doc_argument():
    assert ContainerSignOperation.doc_arguments() == {
        "options": {
            "digests": {"description": "List of digest to sign"},
            "references": {"description": "List of references to sign"},
            "signing_key": {"description": "Signing key short id which should be used for signing"},
            "task_id": {
                "description": "Usually pub task id, serves as identifier for in signing request"
            },
            "identity_references": {"description": "List of references to sign"},
        },
        "examples": {
            "digests": "",
            "references": "",
            "signing_key": "",
            "task_id": "",
            "identity_references": "",
        },
    }


def test_clearsign_operation_doc_argument():
    assert ClearSignOperation.doc_arguments() == {
        "options": {
            "inputs": {"type": "list", "description": "Signing data", "required": "true"},
            "signing_key": {
                "type": "str",
                "description": "Signing key short id which should be used for signing",
                "required": "true",
            },
            "task_id": {
                "type": "str",
                "description": "Usually pub task id, serves as identifier for in signing request",
                "required": "true",
            },
            "repo": {
                "type": "str",
                "description": "Repository name",
                "required": "true",
            },
        },
        "examples": {
            "inputs": ["input1", "input2"],
            "signing_key": "123",
            "task_id": "1",
            "repo": "repo",
        },
    }


def test_container_sign_to_dict():
    assert ContainerSignOperation(
        digests=["digest"],
        references=["references"],
        signing_key="sig-key",
        task_id="task-id",
    ).to_dict() == dict(
        digests=["digest"],
        references=["references"],
        signing_key="sig-key",
        task_id="task-id",
    )


def test_clear_sign_to_dict():
    assert ClearSignOperation(
        inputs=["input1"], signing_key="sig-key", task_id="task-id", repo="repo"
    ).to_dict() == dict(inputs=["input1"], signing_key="sig-key", task_id="task-id", repo="repo")
