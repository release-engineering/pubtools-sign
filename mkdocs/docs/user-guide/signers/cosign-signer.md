# Cosign signer details

Cosign signer use [cosign](https://github.com/sigstore/cosign) project to sign container images and other artifacts.

``` mermaid
sequenceDiagram
  autonumber
  Client->>Cosign binary: Request to sign container
  Cosign binary->>Container registry: Upload signature to desired container image
  Note right of Cosign binary: Optionally
  Cosign binary->>Rekor: Upload signing record to transparency log
```

## Configuration
Cosign signer is configured using the `cosign_signer` section in the `config.yaml` file. Check [[config|Configuration]] for details. 
Cosign signer requires the following configuration fields to be present in a configuration file:

### rekor_url

The URL of the Rekor transparency log server where the signing records will be uploaded. This is used to ensure the integrity and transparency of the signing process.

### upload_tlog
A boolean value indicating whether to upload the signing record to the transparency log. If set to `true`, the signing record will be uploaded to the Rekor server.

### registry_user
The username for the Docker registry where the signatures will be stored. This is used for authentication when pushing the signed artifacts to the registry.

### registry_password
The password for the Docker registry where the signatures will be stored. This is used for authentication when pushing the signed artifacts to the registry.

### log_level
The log level for the cosign signer. This can be set to `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` depending on the desired verbosity of the logs.

### env_variables
A dictionary of environment variables that will be set for the cosign binary when it is executed. This can include any additional environment variables required for the signing process.

### key_aliases
A dictionary of key aliases that map to the real signing keys. This allows for easier management of signing keys, especially when using multiple keys for different purposes. You can also use same key for different signers.

