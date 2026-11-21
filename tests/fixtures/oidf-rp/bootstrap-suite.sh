#!/usr/bin/env bash
# Isolated, disposable GitHub Actions/Linux runner only. No Suite source patches.
set -euo pipefail

task_dir="$(realpath "${1:?usage: bootstrap-suite.sh WORK_DIR}")"
mkdir -p "$task_dir/tls" "$task_dir/evidence/bootstrap"
chmod 700 "$task_dir/tls"
suite_image='registry.gitlab.com/openid/conformance-suite@sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6'
nginx_image='registry.gitlab.com/openid/conformance-suite/nginx@sha256:9a7850826fcc8690cd43373528f50e9551ba33bf8e4a40b67b13267b0aca3675'
mongo_image='mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070'

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
  -keyout "$task_dir/tls/ca.key" -out "$task_dir/tls/ca.crt" \
  -subj '/CN=NazoAuth issue 202 isolated test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$task_dir/tls/server.key" -out "$task_dir/tls/server.csr" \
  -subj '/CN=localhost' 2>/dev/null
cat > "$task_dir/tls/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$task_dir/tls/server.csr" -CA "$task_dir/tls/ca.crt" \
  -CAkey "$task_dir/tls/ca.key" -CAcreateserial -days 2 -sha256 \
  -extfile "$task_dir/tls/server.ext" -out "$task_dir/tls/server.crt" 2>/dev/null
chmod 600 "$task_dir/tls/ca.key" "$task_dir/tls/server.key"
sudo install -m 0644 "$task_dir/tls/ca.crt" /usr/local/share/ca-certificates/nazo-issue202-suite.crt
sudo update-ca-certificates > "$task_dir/evidence/bootstrap/ca-install.txt"

cat > "$task_dir/nginx.conf" <<'EOF'
worker_processes 1;
events { worker_connections 512; }
http {
  log_format evidence '$request_method $uri $status';
  access_log /dev/stdout evidence;
  error_log /dev/null;
  server {
    listen 127.0.0.1:8443 ssl;
    server_name localhost;
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    proxy_read_timeout 120s;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port 8443;
    proxy_set_header X-Forwarded-For $remote_addr;
    location /rp/ { proxy_pass http://127.0.0.1:18080/; }
    location / { proxy_pass http://127.0.0.1:8080; }
  }
}
EOF

docker pull "$suite_image"
docker pull "$nginx_image"
docker pull "$mongo_image"
docker image inspect "$suite_image" "$nginx_image" "$mongo_image" \
  | python3 -c 'import json,sys; print(json.dumps([
      {key: image[key] for key in ("Id", "RepoDigests", "Created", "Architecture", "Os")}
      for image in json.load(sys.stdin)
    ], indent=2))' > "$task_dir/evidence/bootstrap/image-identities.json"
docker run --rm --network none -v "$task_dir/tls:/fixture" --entrypoint keytool \
  "$suite_image" -importcert -noprompt -alias oidf-fixture -file /fixture/ca.crt \
  -keystore /fixture/java.p12 -storepass changeit
docker run -d --name nazo-issue202-mongo --network host \
  "$mongo_image" --bind_ip 127.0.0.1
docker run -d --name nazo-issue202-server --network host \
  -e BASE_URL=https://localhost:8443 \
  -e BASE_MTLS_URL=https://localhost:8444 \
  -e MONGODB_HOST=127.0.0.1 \
  -e SPRING_PROFILES_ACTIVE=dev \
  -e OIDC_GOOGLE_CLIENTID=unused-local-development-client \
  -e OIDC_GOOGLE_SECRET=unused-local-development-secret \
  -e OIDC_GITLAB_CLIENTID=unused-local-development-client \
  -e OIDC_GITLAB_SECRET=unused-local-development-secret \
  -e JAVA_EXTRA_ARGS='-Dfintechlabs.devmode=true -Dserver.address=127.0.0.1 -Djavax.net.ssl.trustStore=/fixture/java.p12 -Djavax.net.ssl.trustStorePassword=changeit' \
  -v "$task_dir/tls/java.p12:/fixture/java.p12:ro" \
  "$suite_image"
docker run -d --name nazo-issue202-nginx --network host \
  -v "$task_dir/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$task_dir/tls/server.crt:/etc/ssl/certs/nginx-selfsigned.crt:ro" \
  -v "$task_dir/tls/server.key:/etc/ssl/private/nginx-selfsigned.key:ro" \
  "$nginx_image"

ready=false
for attempt in $(seq 1 180); do
  if curl --silent --show-error --fail --cacert "$task_dir/tls/ca.crt" \
    https://localhost:8443/api/server > "$task_dir/evidence/bootstrap/suite-server.json" 2>/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  # Raw JVM logs can contain the Suite's private test keys; never upload them.
  docker logs nazo-issue202-server > "$task_dir/server-startup-private.log" 2>&1
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "OIDF_SUITE_CA=$task_dir/tls/ca.crt" >> "$GITHUB_ENV"
  echo "OIDF_WORK_DIR=$task_dir" >> "$GITHUB_ENV"
fi
printf 'OIDF Suite ready at https://localhost:8443; CA: %s\n' "$task_dir/tls/ca.crt"
