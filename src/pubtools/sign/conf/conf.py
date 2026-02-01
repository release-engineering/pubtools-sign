from typing import Any

import marshmallow as ma
from piny import MarshmallowValidator, StrictMatcher, YamlLoader

CONFIG_PATHS = ["~/.config/pubtools-sign/conf.yaml", "/etc/pubtools-sign/conf.yaml"]


class MsgSignerSchema(ma.Schema):
    """Msg signer configuration schema."""

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
    log_level = ma.fields.String(required=False)
    key_aliases = ma.fields.Dict(required=False, keys=ma.fields.String(), values=ma.fields.String())
    task_id_attribute = ma.fields.String(required=False)


class MsgBatchSignerSchema(MsgSignerSchema):
    """Msg batch signer configuration schema."""

    chunk_size = ma.fields.Integer(required=False)


class KafkaSignerSchema(ma.Schema):
    """Kafka signer configuration schema."""

    bootstrap_servers = ma.fields.List(ma.fields.String(), required=True)
    username = ma.fields.String(required=False)
    password = ma.fields.String(required=False)
    security_protocol = ma.fields.String(required=False, load_default="SASL_SSL")
    sasl_mechanism = ma.fields.String(required=False, load_default="SCRAM-SHA-512")
    topic_send_to = ma.fields.String(required=True)
    topic_listen_to = ma.fields.String(required=True)
    group_id = ma.fields.String(required=False, load_default="pubtools-sign")
    environment = ma.fields.String(required=False, load_default="prod")
    service = ma.fields.String(required=False, load_default="pubtools-sign")
    timeout = ma.fields.Integer(required=False, load_default=60)
    retries = ma.fields.Integer(required=False, load_default=3)
    send_retries = ma.fields.Integer(required=False, load_default=2)
    message_id_key = ma.fields.String(required=False, load_default="request_id")
    log_level = ma.fields.String(required=False)
    key_aliases = ma.fields.Dict(required=False, keys=ma.fields.String(), values=ma.fields.String())
    task_id_attribute = ma.fields.String(required=False)
    fallback_base = ma.fields.Float(required=False, load_default=1.0)
    fallback_factor = ma.fields.Float(required=False, load_default=2.0)


class KafkaBatchSignerSchema(KafkaSignerSchema):
    """Kafka batch signer configuration schema."""

    chunk_size = ma.fields.Integer(required=False)
    group_id = ma.fields.String(required=False, load_default="pubtools-sign-batch")


class CosignSignerSchema(ma.Schema):
    """Cosign signer configuration schema."""

    cosign_bin = ma.fields.String(required=False)
    timeout = ma.fields.String(required=False)
    allow_http_registry = ma.fields.Bool(required=False)
    allow_insecure_registry = ma.fields.Bool(required=False)
    rekor_url = ma.fields.String(required=False)
    upload_tlog = ma.fields.Bool(required=False)
    log_level = ma.fields.String(required=False)
    env_variables = ma.fields.Dict(required=False)
    key_aliases = ma.fields.Dict(required=False, keys=ma.fields.String(), values=ma.fields.String())
    registry_user = ma.fields.String(required=False)
    registry_password = ma.fields.String(required=False)
    retries = ma.fields.Integer(required=False)
    num_threads = ma.fields.Integer(required=False)


class ConfigSchema(ma.Schema):
    """pubtools-sign configuration schema."""

    msg_signer = ma.fields.Nested(MsgSignerSchema, required=False)
    msg_batch_signer = ma.fields.Nested(MsgBatchSignerSchema, required=False)
    cosign_signer = ma.fields.Nested(CosignSignerSchema)
    kafka_signer = ma.fields.Nested(KafkaSignerSchema, required=False)
    kafka_batch_signer = ma.fields.Nested(KafkaBatchSignerSchema, required=False)


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
