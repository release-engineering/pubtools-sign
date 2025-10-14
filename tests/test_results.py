from pubtools.sign.signers.msgsigner import ContainerSignResult, ClearSignResult, BlobSignResult


def test_containeroperation_result_to_dict():
    assert ContainerSignResult(
        results=["test"], signing_keys=["signing_key"], failed=False
    ).to_dict() == {
        "results": ["test"],
        "signing_keys": ["signing_key"],
        "failed": False,
    }


def test_clearoperation_result_to_dict():
    assert ClearSignResult(outputs=["test"], signing_keys=["signing_key"]).to_dict() == {
        "outputs": ["test"],
        "signing_keys": ["signing_key"],
    }


def test_bloboperation_result_to_dict():
    assert BlobSignResult(
        results=["test"], signing_keys=["signing_key"], failed=False
    ).to_dict() == {"results": ["test"], "signing_keys": ["signing_key"], "failed": False}
