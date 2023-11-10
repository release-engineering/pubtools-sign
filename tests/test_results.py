from pubtools.sign.signers.msgsigner import (
    ContainerSignResult,
    ClearSignResult,
)


def test_containeroperation_result_to_dict():
    assert ContainerSignResult(
        results=["test"], signing_key="signing_key", failed=False
    ).to_dict() == {
        "results": ["test"],
        "signing_key": "signing_key",
        "failed": False,
    }


def test_clearoperation_result_to_dict():
    assert ClearSignResult(outputs=["test"], signing_key="signing_key").to_dict() == {
        "outputs": ["test"],
        "signing_key": "signing_key",
    }
