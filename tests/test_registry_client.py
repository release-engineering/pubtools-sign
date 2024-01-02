import pytest
import requests
import requests_mock
from unittest.mock import patch

from pubtools.sign.clients.registry import ContainerRegistryClient


@pytest.fixture
def mocked_auth_config_files():
    with patch("pubtools.sign.clients.registry.open") as mock_open:
        with patch("pubtools.sign.clients.registry.os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with patch("pubtools.sign.clients.registry.json") as mocked_json:
                mocked_json.load.return_value = {
                    "auths": {"registry.example.com": {"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="}}
                }
                yield mock_open, mocked_json


def test_resolve_authentication(mocked_auth_config_files):
    client = ContainerRegistryClient()
    auth = client.resolve_authentication("registry.example.com/foo/bar:latest")
    assert auth == ["username", "password"]


def test_authenticate_to_registry(mocked_auth_config_files):
    client = ContainerRegistryClient()
    with requests_mock.Mocker() as m:
        m.get(
            "https://auth.example.com/auth?service=example.com&scope=repository%3Afoo%2Fbar%3Apull",
            json={"token": "some-token"},
        )
        token = client.authenticate_to_registry(
            "registry.example.com/foo/bar",
            'www-authenticate: Bearer realm="https://auth.example.com/auth",'
            'service="example.com",'
            'scope="repository:foo/bar:pull"',
        )
        assert token == "some-token"


def test_authenticate_to_registry_error(mocked_auth_config_files):
    client = ContainerRegistryClient()
    with requests_mock.Mocker() as m:
        m.get(
            "https://auth.example.com/auth?service=example.com&scope=repository%3Afoo%2Fbar%3Apull",
            status_code=401,
        )
        with pytest.raises(requests.exceptions.HTTPError):
            client.authenticate_to_registry(
                "registry.example.com/foo/bar",
                'www-authenticate: Bearer realm="https://auth.example.com/auth",'
                'service="example.com",'
                'scope="repository:foo/bar:pull"',
            )
