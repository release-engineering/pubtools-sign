from unittest.mock import patch
import tempfile

from pytest import fixture


@fixture
def f_cosign_signer(f_config_msg_signer_ok):
    with patch("pubtools.sign.signers.cosignsigner.CosignSigner") as signer:
        yield signer


@fixture
def f_config_cosign_signer_ok(f_client_certificate):
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            """
cosign_signer:
  timeout: 30s
  rekor_url: https://rekor.sigstore.dev
  registry_user: some-user
  registry_password: some-password
  log_level: debug
        """.encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name


@fixture
def f_config_cosign_signer_aliases(f_client_certificate):
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            """
cosign_signer:
  timeout: 30s
  rekor_url: https://rekor.sigstore.dev
  log_level: debug
  key_aliases:
    beta: abcde1245
        """.encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name


@fixture
def f_config_cosign_signer_no_auth(f_client_certificate):
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(
            """
cosign_signer:
  timeout: 30s
  rekor_url: https://rekor.sigstore.dev
  log_level: debug
        """.encode(
                "utf-8"
            )
        )
        tmpf.flush()
        yield tmpf.name
