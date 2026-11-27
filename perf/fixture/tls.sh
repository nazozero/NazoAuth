#!/usr/bin/env bash
# Create a short-lived fixture root and distinct server leaf. Never publish the keys.
set -euo pipefail
dir=${1:?private output directory}
name=${2:?DNS name}
umask 077
mkdir -p "$dir"
openssl req -new -x509 -newkey rsa:2048 -noenc -days 3 -sha256 \
  -subj "/CN=OAuth benchmark fixture CA" -addext basicConstraints=critical,CA:TRUE,pathlen:0 \
  -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$dir/ca.key" -out "$dir/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -noenc -subj "/CN=$name" -keyout "$dir/server.key" -out "$dir/server.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$name" >"$dir/extensions"
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
  -CAcreateserial -days 3 -sha256 -extfile "$dir/extensions" -out "$dir/server.pem" 2>/dev/null
openssl verify -purpose sslserver -verify_hostname "$name" -CAfile "$dir/ca.pem" "$dir/server.pem" >/dev/null
