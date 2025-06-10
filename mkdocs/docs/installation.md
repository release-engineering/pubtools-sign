# Installation Guide

> [!INFO] Warning
> If you plan to use msg signer with amqps protocol, you need to install `python3-qpid-proton`
> provided by your package manager (e.g. `dnf install python3-qpid-proton` for Fedora).
> as vesion in pypi seems to not be built with SSL support.
> That's also the reason why the package is not listed in `requirements.txt`.

## Relased version

To install released version, you need to run
```bash
pip install pubtools-sign
```

## Development version

To install the necessary dependencies for this project, you can use the following command:
```bash
pip install -r requirements.txt
```
To install the project itself, you can use the following command:

```bash
pip install .
```

## Optional dependencies
If you want to use cosign signer, [cosign](https://github.com/sigstore/cosign?tab=readme-ov-file) binary needs to be available in your `PATH`.


