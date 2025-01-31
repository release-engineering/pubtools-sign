ChangeLog
=========

0.0.11 (31-01-2025)
-------------------
* Improved logging
* Ignore amqp:connection:framing-error error in messaging signer


0.0.10.1 (23-10-2024)
------------------
* Fix building AppImage failure


0.0.10 (18-10-2024)
------------------
* Fix building AppImage failure
* Run cosign commands in parallel


0.0.9 (17-07-2024)
------------------
* Support multiple tags and identities


0.0.8 (27-06-2024)
------------------
* Added identity support for cosign signer which translates to cosign --sign-container-identity argument


0.0.7 (02-05-2024)
-------------------
Fixed cosign OOM

0.0.6 (25-04-2024)
-------------------
Add OTEL trace instrument for signing
Added send+recv retry cycles

0.0.5 (19-02-2024)
-------------------
* Added cosin support
* Added support of key aliases
* Added --log-level for cli entrypoints
* Exposed operation model to signed results
* Starts receiver before sender in msg signer

0.0.4 (06-11-2023)
-------------------
* Fixed raw pushes

0.0.3 (22-09-2023)
-------------------
* Added extra arguments to messaging signer requests

0.0.2 (12-09-2023)
-------------------
* Support raw output for cli 
* Fixed appimage ssl error


0.0.1 (24-08-2023)
-------------------
* Initial release
