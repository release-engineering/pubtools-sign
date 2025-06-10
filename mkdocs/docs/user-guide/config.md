# Configuration file

Here's an example configuration file for a service that uses the `msg_signer` and `cosign_signer` components. This file is structured in YAML format.

```
msg_signer:
  messaging_brokers:
    - amqps://<your-broker>:5671
  messaging_cert_key: <path-to-ssl-certificate-and-key> 
  messaging_ca_cert: <path-to-ca-certificate>
  topic_send_to: topic://<topic-where-you-want-to-send-signing-requests>
  topic_listen_to: queue://<topic-where-signing-server-sends-signed-requests> (see section bellow)
  environment: <>your-environment-id>
  service: <id-of-service-which-sends-signing-request> 
  timeout: <integer-timeout-for-receiving-message>
  retries: <integer-number-of-retries-for-receiving-messages>
  send_retries: <integer-number-of-retries-for-sending-messages>
  message_id_key: <attribute-in-signed-request-which-identifies-the-request>
  log_level: <log-level>
  key_aliases:
    <alias>: <real-signing-key>
cosign_signer:
  rekor_url: <rekor-url>
  upload_tlog: <upload-tlog> 
  registry_user: <docker-registry-user-where-signatures-will-be-stored>
  registry_password: <docker-registry-password> 
  log_level: <log-level>
  env_variables:
    <ENV>: <value>
    # any additional environment variables you want to set for cosign
  key_aliases:
    <alias>: <real-signing-key>
```

## Configuration details

- Messaging signer `topic_listen_to` attribute also supports templating attributes {creator} 
  and {task_id}. Creator is UID or CN fetched from the client ceritificate or provided
  on the input by user. Task id is any user provided string which servers to identify the message.

To read more about signer you can check the [[msg-signer|Messaging Signer]]  and 
[[cosign-signer|Cosign signer]] documentation.

