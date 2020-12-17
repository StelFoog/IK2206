# Security Analysis

## Flaw One
#### No authentication
### Issue
During the handshake client and server verify that the others certificate has been signed by the CA. But we never verify that it comes from the correct source. This leaves us open to, for example, someone pretending to be the server sending us their certificate.

### Solution
One solution could be to send a nounce encrypted with the others public key. If we get back the same nounce we know that the person with the certificate also has the corresponding private key.

---

## Flaw Two
#### Too much open information
### Issue
Although we encrypt the session key and IV we send the target and session port in plaintext resulting in two issues.

1. Anyone can see the true target we wish to access.
2. Anyone can see the port we will forward through

The first one is problematic if we are using the VPN to hide what we are doing.

The second is problematic since a malicious user could flood the session port with useless data to slow down the regular users connection.

### Solution
After Client- and ServerHello we encrypt all the rest of the handshake (except maybe the parameters) with the others public key.
