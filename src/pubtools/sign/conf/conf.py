from typing import Any

import marshmallow as ma
from piny import MarshmallowValidator, StrictMatcher, YamlLoader

CONFIG_PATHS = ["~/.config/pubtools-sign/conf.yaml", "/etc/pubtools-sign/conf.yaml"]


class MsgSignerSchema(ma.Schema):
    """Radas signer configuration schema."""

    messaging_brokers = ma.fields.List(ma.fields.String(), required=True)
    messaging_cert_key = ma.fields.String(required=True)
    messaging_ca_cert = ma.fields.String(required=True)
    topic_send_to = ma.fields.String(required=True)
    topic_listen_to = ma.fields.String(required=True)
    environment = ma.fields.String(required=True)
    service = ma.fields.String(required=True)
    timeout = ma.fields.Integer(required=True)
    retries = ma.fields.Integer(required=True)
    send_retries = ma.fields.Integer(required=True)
    message_id_key = ma.fields.String(required=True)
    log_level = ma.fields.String(default="INFO")
    key_aliases = ma.fields.Dict(required=False, keys=ma.fields.String(), values=ma.fields.String())


class CosignSignerSchema(ma.Schema):
    """Cosign signer configuration schema."""

    cosign_bin = ma.fields.String(required=False)
    timeout = ma.fields.String(required=False)
    allow_http_registry = ma.fields.Bool(required=False)
    allow_insecure_registry = ma.fields.Bool(required=False)
    rekor_url = ma.fields.String(required=False)
    upload_tlog = ma.fields.Bool(required=False)
    log_level = ma.fields.String(default="INFO")
    env_variables = ma.fields.Dict(required=False)
    key_aliases = ma.fields.Dict(required=False, keys=ma.fields.String(), values=ma.fields.String())
    registry_user = ma.fields.String(required=False)
    registry_password = ma.fields.String(required=False)
    retries = ma.fields.Integer(required=False)


class ConfigSchema(ma.Schema):
    """pubtools-sign configuration schema."""

    msg_signer = ma.fields.Nested(MsgSignerSchema)
    cosign_signer = ma.fields.Nested(CosignSignerSchema)


def load_config(fname: str) -> Any:
    """Load configuration from a filename.

    :param fname: filename
    :type fname: str

    :return Any:
    """
    config = YamlLoader(
        path=fname,
        matcher=StrictMatcher,
        validator=MarshmallowValidator,
        schema=ConfigSchema,
    ).load(many=False)
    return config
