#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh" >&2
  exit 1
fi

source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "Officially supported host: Ubuntu Server." >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
APP_DIR=/opt/pa-policy-forge
DATA_DIR=/var/lib/pa-policy-forge
APP_UID=10001
APP_GID=10001

packages=()
command -v docker >/dev/null 2>&1 || packages+=(docker.io)
command -v openssl >/dev/null 2>&1 || packages+=(openssl)
command -v python3 >/dev/null 2>&1 || packages+=(python3)
if ! docker compose version >/dev/null 2>&1; then
  packages+=(docker-compose-v2)
fi
if ((${#packages[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates "${packages[@]}"
fi
systemctl enable --now docker

detected_ip="$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i !~ /^127\./ && $i !~ /:/) {print $i; exit}}')"
if [[ -z "$detected_ip" ]]; then
  echo "No non-loopback IPv4 address was detected. Set networking before installation." >&2
  exit 1
fi
bind_address="${PPF_BIND_ADDRESS:-$detected_ip}"
fqdn="${PPF_FQDN:-}"
if [[ -n "$fqdn" ]]; then
  fqdn="${fqdn%.}"
  if [[ ! "$fqdn" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
    echo "PPF_FQDN must contain only a valid fully qualified DNS name." >&2
    exit 1
  fi
  fqdn="$(printf '%s' "$fqdn" | tr '[:upper:]' '[:lower:]')"
fi

install -d -m 0755 "$APP_DIR"
install -d -o "$APP_UID" -g "$APP_GID" -m 0700 "$DATA_DIR"
install -d -o "$APP_UID" -g "$APP_GID" -m 0700 "$APP_DIR/certs"
if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
  install -d -m 0755 "$APP_DIR/app" "$APP_DIR/vendor"
  cp -a "$SOURCE_DIR/app/." "$APP_DIR/app/"
  cp -a "$SOURCE_DIR/vendor/." "$APP_DIR/vendor/"
  cp -a "$SOURCE_DIR/Dockerfile" "$SOURCE_DIR/docker-compose.yml" "$SOURCE_DIR/requirements.txt" "$APP_DIR/"
  [[ ! -f "$SOURCE_DIR/.dockerignore" ]] || cp -a "$SOURCE_DIR/.dockerignore" "$APP_DIR/"
fi

certificate="$APP_DIR/certs/tls.crt"
private_key="$APP_DIR/certs/tls.key"
if [[ ! -s "$certificate" || ! -s "$private_key" ]]; then
  common_name="${fqdn:-$detected_ip}"
  subject_alt_name="IP:$detected_ip,DNS:pa-policy-forge.local"
  [[ -z "$fqdn" ]] || subject_alt_name+=",DNS:$fqdn"
  rm -f -- "$certificate" "$private_key"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj "/CN=$common_name" \
    -addext "subjectAltName=$subject_alt_name" \
    -keyout "$private_key" \
    -out "$certificate"
fi
openssl x509 -in "$certificate" -noout >/dev/null
openssl pkey -in "$private_key" -check -noout >/dev/null
certificate_key_hash="$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
private_key_hash="$(openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
if [[ "$certificate_key_hash" != "$private_key_hash" ]]; then
  echo "The existing TLS certificate and private key do not match." >&2
  exit 1
fi
chown "$APP_UID:$APP_GID" "$certificate" "$private_key" "$APP_DIR/certs"
chmod 0644 "$certificate"
chmod 0600 "$private_key"
chmod 0700 "$APP_DIR/certs"

appliance_config="$DATA_DIR/appliance.json"
if [[ ! -s "$appliance_config" ]]; then
  umask 077
  printf '{"fqdn":"%s"}\n' "$fqdn" > "$appliance_config"
fi
chown "$APP_UID:$APP_GID" "$appliance_config"
chmod 0600 "$appliance_config"

host_fqdn="$(hostname -f 2>/dev/null || true)"
trusted_hosts="$(printf '%s\n' "$detected_ip" "$bind_address" "$host_fqdn" "$fqdn" 127.0.0.1 localhost | awk 'NF && !seen[$0]++' | paste -sd, -)"
env_file="$APP_DIR/.env"
if [[ ! -s "$env_file" ]]; then
  umask 077
  {
    printf 'PPF_BOOTSTRAP_PASSWORD=admin\n'
    printf 'PPF_TRUSTED_HOSTS=%s\n' "$trusted_hosts"
    printf 'PPF_BIND_ADDRESS=%s\n' "$bind_address"
    printf 'PPF_FQDN=%s\n' "$fqdn"
  } > "$env_file"
fi
grep -q '^PPF_BOOTSTRAP_PASSWORD=' "$env_file" || printf 'PPF_BOOTSTRAP_PASSWORD=admin\n' >> "$env_file"
grep -q '^PPF_TRUSTED_HOSTS=' "$env_file" || printf 'PPF_TRUSTED_HOSTS=%s\n' "$trusted_hosts" >> "$env_file"
grep -q '^PPF_BIND_ADDRESS=' "$env_file" || printf 'PPF_BIND_ADDRESS=%s\n' "$bind_address" >> "$env_file"
grep -q '^PPF_FQDN=' "$env_file" || printf 'PPF_FQDN=%s\n' "$fqdn" >> "$env_file"
chmod 0600 "$env_file"
effective_bind_address="$(sed -n 's/^PPF_BIND_ADDRESS=//p' "$env_file" | tail -n 1)"
effective_bind_address="${effective_bind_address:-$bind_address}"

cd "$APP_DIR"
docker compose config --quiet
docker compose up -d --build --remove-orphans

wait_for_healthy() {
  local container="$1"
  local status
  for _attempt in {1..45}; do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    [[ "$status" != "healthy" ]] || return 0
    [[ "$status" != "unhealthy" ]] || break
    sleep 2
  done
  docker compose ps
  echo "$container did not become healthy." >&2
  return 1
}

wait_for_healthy pa-policy-forge
wait_for_healthy pa-policy-forge-http
python3 - "$effective_bind_address" "$detected_ip" <<'PY'
import http.client
import sys

bind_address, detected_ip = sys.argv[1:]
target = detected_ip if bind_address == "0.0.0.0" else bind_address
connection = http.client.HTTPConnection(target, 80, timeout=5)
connection.request("HEAD", "/install-check", headers={"Host": target})
response = connection.getresponse()
if response.status != 308 or not response.getheader("Location", "").startswith("https://"):
    raise SystemExit("HTTP to HTTPS redirect validation failed")
PY

display_host="${fqdn:-$detected_ip}"
echo "PA Policy Forge is available on https://$display_host"
echo "HTTP requests on port 80 are redirected to HTTPS."
echo "Initial login: admin / admin"
echo "A self-signed certificate is active until an FQDN certificate is uploaded in Settings."
