import dataclasses
import base64
import json
import os
import logging

from urllib.parse import urlparse, urlunparse, urlencode
from urllib.request import parse_http_list, parse_keqv_list
from typing import Optional, Tuple, Any, Union

import requests
from requests.adapters import HTTPAdapter, Retry

from ..utils import set_log_level

LOG = logging.getLogger("pubtools.sign.signers.msgsigner")

AUTH_FILES = [
    "${XDG_CONFIG_HOME}/containers/auth.json",
    "${HOME}/.docker/config.json",
    "${REGISTRY_AUTH_FILE}",
]
"""Default authentication files to search for credentials in container registry client."""


@dataclasses.dataclass
class AuthTokenWrapper:
    """Carrier of the auth token for container registry."""

    token: str


class ContainerRegistryClient:
    """Client for interacting with container registries."""

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_file: Optional[str] = None,
        retries: int = 5,
        log_level: str = "INFO",
    ):
        """Initialize.

        Args:
            username (Optional[str]): Username for authentication.
            password (Optional[str]): Password for authentication.
            auth_file (Optional[str]): Path to the auth file.
            retries (int): Number of retries for HTTP requests.
        """
        self.username = username
        self.password = password
        self.auth_file = auth_file
        self._session: Union[None, requests.Session] = None
        self.retries = retries
        set_log_level(LOG, log_level)

    @property
    def session(self) -> requests.Session:
        """Get the session object.

        Returns:
            requests.Session: The session object for making HTTP requests.
        """
        if not self._session:
            self._session = requests.Session()
            retries = Retry(
                total=self.retries, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
            )
            self._session.mount("http://", HTTPAdapter(max_retries=retries))
        return self._session

    def resolve_authentication(self, image_reference: str) -> Tuple[str, str]:
        """Resolve authentication for the given image reference.

        When username and password are provided in registry client, they are used.
        Otherwise `AUTH_FILES` are search for specific authentication
        entry based on host of image reference.

        Args:
            image_reference (str): Image reference to resolve authentication for.

        Returns:
            Tuple[str, str]: Username and password for authentication.
        """
        if self.username and self.password:
            return (self.username, self.password)

        parsed = urlparse(image_reference)
        if not parsed.scheme:
            parsed = urlparse(f"docker://{image_reference}")
        registry = parsed.netloc
        existing_auth_files = []
        auth_files = AUTH_FILES if not self.auth_file else [self.auth_file] + AUTH_FILES
        for af in auth_files:
            if os.path.exists(os.path.expandvars(af)):
                existing_auth_files.append(os.path.expandvars(af))
        for eaf in existing_auth_files:
            parsed_conf = json.load(open(os.path.expandvars(eaf)))
            parsed_auths = parsed_conf.get("auths")
            if registry in parsed_auths:
                auth = (
                    base64.b64decode(parsed_auths.get(registry)["auth"].encode("utf-8"))
                    .decode("utf-8")
                    .split(":")
                )
                auth_tuple = (auth[0], auth[1])
                break
        else:
            raise ValueError("No authentication found")
        return auth_tuple

    def authenticate_to_registry(self, image_reference: str, auth_header: str) -> Union[str, Any]:
        """Ask for auth token based on given auth header.

        Args:
            image_reference (str): Image reference to resolve authentication for.
            auth_header (str): Authentication header from the registry.

        Returns:
            str: Authentication token.
        """
        _, _, value = auth_header.partition("Bearer")
        items = parse_http_list(value)
        opts = parse_keqv_list(items)
        unparse_parts = [
            "https",
            opts["realm"].replace("https://", "").split("/", 1)[0],
            opts["realm"].replace("https://", "").split("/", 1)[1],
            "",
            urlencode({"service": opts["service"], "scope": opts["scope"]}),
            "",
        ]
        auth_url = urlunparse(unparse_parts)
        username, password = self.resolve_authentication(image_reference)
        response = self.session.get(auth_url, auth=(username, password))

        response.raise_for_status()
        return response.json().get("token")

    def check_container_image_exists(
        self, image_reference: str, auth_token: AuthTokenWrapper
    ) -> Tuple[bool, str]:
        """Check if the given container image exists.

        Args:
            image_reference (str): Image reference to check.
            auth_token (AuthTokenWrapper): Authentication token.

        Returns:
            Tuple[bool, str]: [True, ""] if the image exists,
            Tuple[False, <error_message>] otherwise.
        """
        repo_ref, tag = image_reference.rsplit(":", 1)
        registry, repo = repo_ref.split("/", 1)
        manifest_url = f"https://{registry}/v2/{repo}/manifests/{tag}"
        headers = {"Authorization": f"Bearer {auth_token.token}"}
        response = self.session.get(manifest_url, headers=headers)

        if response.status_code == 200:
            return True, ""
        elif response.status_code == 401:
            auth_header = response.headers["www-authenticate"]
            auth_token.token = self.authenticate_to_registry(image_reference, auth_header)
            # Retry the original request with the token
            headers = {"Authorization": f"Bearer {auth_token.token}"}
            response = self.session.get(manifest_url, headers=headers)
            if response.status_code == 200:
                return True, ""
            elif response.status_code == 404:
                return False, ""
            else:
                LOG.error(f"Unexpected Error: {response.status_code} - {response.text}")
                return False, f"Unexpected Error: {response.status_code} - {response.text}"
        elif response.status_code == 404:
            return False, ""
        else:
            LOG.error(f"Unexpected Error: {response.status_code} - {response.text}")
            return False, f"Unexpected Error: {response.status_code} - {response.text}"
