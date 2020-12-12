# Task 3

### CA Certificate

- Generating new private RSA key: `openssl genrsa -out key.pem`
- Generating corresponding public key: `openssl rsa -in prikey.rsa -pubout -out -pubkey.pub`
- Generating CA certificate: `openssl req -new -x509 -key key.pem -out CA.pem`

### User Certificate

- Generate CSR: `openssl req -new -key key.pem -out gen.csr`
- Generate User Certificate: `openssl x509 -req -days 360 -inform PEM -outform PEM -in gen.csr -CA CA.pem -CAkey key.pem -CAcreateserial -out user.pem`
