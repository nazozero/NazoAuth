#!/usr/bin/env bash
# Isolated, disposable GitHub Actions/Linux runner only. No Suite source patches.
set -euo pipefail

task_dir="$(realpath "${1:?usage: bootstrap-suite.sh WORK_DIR}")"
mkdir -p "$task_dir/tls" "$task_dir/evidence/bootstrap"
chmod 700 "$task_dir/tls"
suite_image='registry.gitlab.com/openid/conformance-suite:release-v5.3.4'
nginx_image='registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.4'
mongo_image='mongo:6.0.13'

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
  access_log /dev/stdout;
  error_log /dev/stderr;
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
  > "$task_dir/evidence/bootstrap/image-identities.json"
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
  -e JAVA_EXTRA_ARGS='-Dfintechlabs.devmode=true -Dserver.address=127.0.0.1' \
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
  docker logs nazo-issue202-server > "$task_dir/evidence/bootstrap/server.log" 2>&1
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "OIDF_SUITE_CA=$task_dir/tls/ca.crt" >> "$GITHUB_ENV"
  echo "OIDF_WORK_DIR=$task_dir" >> "$GITHUB_ENV"
fi
printf 'OIDF Suite ready at https://localhost:8443; CA: %s\n' "$task_dir/tls/ca.crt"
