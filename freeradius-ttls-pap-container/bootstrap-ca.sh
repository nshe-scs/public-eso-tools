#!/bin/sh
# Run this outside of the container to bootstrap things (see README)
set -e

# Generate 8-character random serial (uppercase hex letters and digits only)
# This should make it easier for you to find/identify this CA cert later
serial=$(tr -dc 'A-F0-9' </dev/urandom | head -c8)
certfile="eduroam_ca_$serial.pem"
keyfile="eduroam_ca_$serial.key"

# Generate the CA private key using ECDSA, P-256 (sadly, some 802.1x clients still don't like ED25519)
openssl ecparam -genkey -name prime256v1 -noout -out $keyfile

# Create a temporary OpenSSL configuration file to define CA extensions
cat > ca_openssl.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
CN = eduroam Support Organization Root CA ($serial)

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF

# Generate a self-signed CA certificate using the ECDSA key
openssl req -new -x509 -config ca_openssl.cnf -nodes -key $keyfile -sha256 -days 7300 -out $certfile

# Clean up the temporary configuration file
rm ca_openssl.cnf

cat <<EOF
Generated CA certificate ($certfile) and key ($keyfile).
Only run this again if you're redeploying from scratch or running containers for
multiple organizations. A new temporary server cert will be used whenever your
container starts, but this CA cert will stay the same and is valid for 20 years.

Securely store this information. If you lose it after your users start using
eduroam, you'll need to re-run this script and reconfigure all your users'
wireless profiles to trust the new CA certificate. That's no fun.

Here they are in base64 encoded format, ready to paste into your container's
environment. Each is a single line, so remove any line breaks when you paste
them in the appropriate place later:

FR_TLS_CA_CERT_BASE64=$(base64 -w 0 $certfile)

FR_TLS_CA_KEY_BASE64=$(base64 -w 0 $keyfile)

And remember: only include the CA certificate ($certfile, NOT the key) in any
wireless profiles you configure, e.g. in eduroam CAT.
EOF
