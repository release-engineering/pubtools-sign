
## Clearsign

### Messaging signer

Messaging signer works as client which communicates with the server via messaging bus. User data
to be signed are wrapped into signing requests and sent to the server. The server replies with 
signed requests which are composed from the original signing request and the signature. Signature
is base64 encoded clearsign of user data.
