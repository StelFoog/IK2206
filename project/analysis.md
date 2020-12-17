# Security Analysis

## Flaw One
#### No authentication of server
### Issue
During the handshake client and server verify that the others certificate has been signed by the CA. But we never verify that it comes from the correct source. This leaves us open to, for example, someone pretending to be the server sending us their certificate.

### Solution
One solution could be to send a nounce encrypted with the servers public key. If we get back the same nounce we know that the person with the certificate also has the corresponding private key.

---

## Flaw Two
#### No DoS protection
### Issue
The server is left open to recive many malicious HandshakeRequests, aimed only at filling up it's sockets, from a single host. 

### Solution
We add a registrar of what hosts we have a connection with currently and do not allow handshakes from hosts that already have too many connections. What to many is is based on what we want to use the VPN for, for example a resonable amount if we only want to watch e.g. british Netflix would be 1 since resonable people don't watch more than one movie/tv-show at once.

This way no one host can use all of the servers computational power and/or ports.
