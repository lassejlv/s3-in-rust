#!/bin/sh
# A throwaway test CA and two localhost server certificates signed by it (the second one is
# for the certificate reload test). Usage: tests/tls/gen-certs.sh <dir>
set -e
cd "$1"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=s3rs test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca.key -out ca.pem 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n' > leaf.ext
for n in leaf leaf2; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=localhost" -keyout $n.key -out $n.csr 2>/dev/null
  openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile leaf.ext -out $n.pem 2>/dev/null
done
