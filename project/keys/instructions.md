# Project instructions

## Key instructions

### CA Certificate

**CERTIFICATE GENERATION BROKEN**

**NONE OF CERTIFICATES VERIFYABLE**

- Generating new private key for CA: `openssl genrsa -out ca-private.pem`

- Generating CA certificate: `openssl req -new -x509 -key ca-private.pem -out ca.pem`
  - Country Name (2 letter code) []: `SE`
  - State or Province Name (full name) []: ` ` (Should be left blank)
  - Locality Name (eg, city) []: `Stockholm`
  - Organization Name (eg, company) []: `KTH`
  - Organizational Unit Name (eg, section) []: `IK2206 Internet Security and Privacy`
  - Common Name (eg, fully qualified host name) []: `ca-pf.ik2206.kth.se`
  - Email Address []: `samlar@kth.se`

### Server Certificate

- Generating new private key for Server: `openssl genpkey -outform DER -out server-private.der -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
  
- Generate Server CSR: `openssl req -new -key server-private.der -keyform DER -out server.csr`
  - Country Name (2 letter code) []: `SE`
  - State or Province Name (full name) []: ` ` (Should be left blank)
  - Locality Name (eg, city) []: `Stockholm`
  - Organization Name (eg, company) []: `KTH`
  - Organizational Unit Name (eg, section) []: `IK2206 Internet Security and Privacy`
  - Common Name (eg, fully qualified host name) []: `server-pf.ik2206.kth.se`
  - Email Address []: `samlar@kth.se`
  
- Generate Server certificate: `openssl x509 -req -days 360 -inform DER -outform PEM -in server.csr -CA ca.pem -CAkey ca-private.pem -CAcreateserial -out server.pem`

### Client Certificate

- Generating new private key for User: `openssl genpkey -outform DER -out client-private.der -algorithm RSA -pkeyopt rsa_keygen_bits:2048`

- Generate Server CSR: `openssl req -new -key client-private.der -keyform DER -out client.csr`
  - Country Name (2 letter code) []: `SE`
  - State or Province Name (full name) []: ` ` (Should be left blank)
  - Locality Name (eg, city) []: `Stockholm`
  - Organization Name (eg, company) []: `KTH`
  - Organizational Unit Name (eg, section) []: `IK2206 Internet Security and Privacy`
  - Common Name (eg, fully qualified host name) []: `client-pf.ik2206.kth.se`
  - Email Address []: `samlar@kth.se`
  
- Generate Client certificate: `openssl x509 -req -days 360 -inform DER -outform PEM -in client.csr -CA ca.pem -CAkey ca-private.pem -CAcreateserial -out client.pem`

---

## Understanding the project

### The Components

The VPN will work by three components. These are as follows:
- **The Proxy**
  - Will forward (unencrypted) input on a port which `ForwardClient` can read.
  
- **ForwardClient**
  - Will take our `Proxy`'s (unencrypted) input, encrypt it and send the (encrypted) data to the `ForwardServer`.

- **ForwardServer**
  - Will recive `ForwardClient`'s (encrypted) data, decrypt it and send it to the target (which was established during the handshake).

### The Handshake

When we start `ForwardClient` it will attempt to establish a connection with `ForwardServer`.

The handshake works by `ForwardClient` and `ForwardServer` sending four messages to each other, two each.

#### **Protocol**

- **First message** `client -> server`
  - Client sends "hello" message to server containing its certificate.

  | **Parameter**   | **Value**                               |
  | --------------- | --------------------------------------- |
  | `"MessageType"` | "ClientHello"                           |
  | `"Certificate"` | Client's X.509 certificate (PEM format) |

- **Second message** `server -> client`
  - Server varifies certificate and then sends back its own "hello" message with its certificate.
  
  | **Parameter**   | **Value**                               |
  | --------------- | --------------------------------------- |
  | `"MessageType"` | "ServerHello"                           |
  | `"Certificate"` | Server's X.509 certificate (PEM format) |
  
- **Third message** `client -> server`
  - Client varifies server's certificate and then responds with a "forward" message, containing where the server should send what it gets from client.

  | **Parameter**   | **Value**                                   |
  | --------------- | ------------------------------------------- |
  | `"MessageType"` | "Forward"                                   |
  | `"TargetHost"`  | Name of target host                         |
  | `"TargetPort"`  | TCP port number at target host (as string!) |

- **Fourth message** `server -> client`
  - If the server agrees to forward to target it will set up the session. The server generates the session key and initialisation vector and sends them client encrypted with client's public key and encoded as a string in a "session" message.
  - The server also creates, and includes in the "session" message, a new socket endpoint where it will recieve (encrypted) data and continue the session.

  | **Parameter**   | **Value**                                  |
  | --------------- | ------------------------------------------ |
  | `"MessageType"` | "Session"                                  |
  | `"SessionKey"`  | An AES key (encrypted and encoded)         |
  | `"SessionIV"`   | An IV for AES-CTR (encrypted and encoded)  |
  | `"SessionHost"` | Name of host for new socket                |
  | `"SessionPort"` | TCP port number of new socket (as string!) |

  - When running both `ForwardClient` and `ForwardServer` locally on the same machine `"SessionHost"` should be `localhost`

---

## Running the project

To run the project we need to run the `ForwardServer`, the `ForwardClient` and two `proxies`. One `proxy` for sending data and one for recieving data.

- **Starting ForwardServer**: `java ForwardServer --handshakeport=2206 --usercert=keys/server.pem --cacert=keys/ca.pem --key=keys/server-private.der`
  - `handshakeport` takes a number, we can choose freely, but must use the same when setting `handshakeport` for `ForwardClient`. When testing we'll use `2206`.
  - `usercert` takes the filepath to the server certificate. When testing we use `keys/server.pem`.
  - `cacert` takes the filepath to the ca certificate. When testing we use `keys/ca.pem`.
  - `key` takes the filepath for the server's private key. When testing we use `keys/server-private.der`.
    - For all filepaths we would remove `keys/` if we were in the `final` folder, i.e. `keys/ca.pem` would become just `ca.pem`.

- **Starting the proxies**:
  - `nc <host> <port>`
    - Will start netcat at `host`:`port`. Since ForwardClient is running locally, `localhost` is what we will use for the host parameter. We can choose the port ourselves as long as we specify the same port as `proxyport` when running `ForwardClient`. When testing we'll use `12345`.
    - With this proxy we'll be able to send input to `ForwardClient`. After starting it any plaintext we write followed by `enter ↵` sent forward.
  - `nc -l <port>`
    - Will start netcat in listening mode at `port`. When testing we'll use `6789`.
    - This instance of netcat will print any data sent to `port`.
  
- **Starting ForwardClient**: `java ForwardClient --handshakehost=localhost --handshakeport=2206 --proxyport=12345 --targethost=localhost --targetport=6789 --usercert=keys/client.pem --cacert=keys/ca.pem --key=keys/client-private.der`
  - `handshakehost` takes the name of the host to connect to. When testing this will be `localhost` since we're running both client and server locally.
  - `handshakeport` takes the tcp port number to connect to for the handshake. This will be the same value as we used for `handshakeport` on `ForwardServer`. In our case `2206`.
  - `proxyport` takes the port of the proxy we'll use to get input from. This is the same as `port` in `proxy`. In our case `12345`.
  - `targethost` takes the name of the host we want `ForwardServer` to connect to on our behalf. When testing this will be `localhost`.
  - `targetport` takes the tcp port number we want `ForwardServer` to connect to. In our case `6789`.
  - `usercert` takes the filepath to the client certificate. When testing this will be `keys/client.pem`.
  - `cacert` takes the filepath to the ca certificate. When testing we use `keys/ca.pem`.
  - `key` takes the filepath for the clients's private key. When testing we use `keys/client-private.der`.
    - For all filepaths we would remove `keys/` if we were in the `final` folder, i.e. `keys/ca.pem` would become just `ca.pem`.

---

## Using the project

When all parts are up and running we should be able to send data in our input `proxy` and recieve data in our output `proxy`.

### Usage notes

When `ForwardClient` has started and the handshake protocol has completed `ForwardClient` will log target we're sending to and what proxy we're getting our data from.

While running on our test parameters we'd get a result that looks like:
```
Client forwarder to target...
Waiting for incoming connections at...
```
