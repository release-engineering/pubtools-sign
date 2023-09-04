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
    message_id_key = ma.fields.String(required=True)
    log_level = ma.fields.String(default="INFO")


class ConfigSchema(ma.Schema):
    """pubtools-sign configuration schema."""

    msg_signer = ma.fields.Nested(MsgSignerSchema)


def load_config(fname: str):
    """Load configuration from a filename.

    :param fname: filename
    :type fname: str

    :return Dict[str, Any]:
    """
    config = YamlLoader(
        path=fname,
        matcher=StrictMatcher,
        validator=MarshmallowValidator,
        schema=ConfigSchema,
    ).load(many=False)
    return config
