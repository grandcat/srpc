Generate Self-Signed Certificates
=================================

To generate self-signed certificates for each party, just run `./gencerts.sh cert_name`.
The script feeds OpenSSL with the necessary information for the certificate generation.
Due to self-signing, the certificate requires some special extensions to be configured.
This config applies the necessary configuration as OpenSSL compatible input file:
```bash
###################################################################
# Server / Client Auth for X509 certs
###################################################################
[xauth]
basicConstraints = critical,CA:true
keyUsage         = digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = codeSigning, serverAuth, clientAuth
```
Just append this section to your local OpenSSL configuration `/etc/ssl/openssl.cnf`.