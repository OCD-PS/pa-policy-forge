#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then echo "Run as root: sudo ./install.sh" >&2; exit 1; fi
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]]; then echo "Officially supported host: Ubuntu Server." >&2; exit 1; fi

APP_DIR=/opt/pa-policy-forge
DATA_DIR=/var/lib/pa-policy-forge
install -d -m 0755 "$APP_DIR"
install -d -o 10001 -g 10001 -m 0700 "$DATA_DIR"
install -d -m 0700 "$APP_DIR/certs"

if ! command -v docker >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 openssl
  systemctl enable --now docker
fi

cp -a Dockerfile docker-compose.yml requirements.txt app vendor "$APP_DIR/"
if [[ ! -s "$APP_DIR/certs/tls.key" || ! -s "$APP_DIR/certs/tls.crt" ]]; then
  host_ip="$(hostname -I | awk '{print $1}')"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj "/CN=${host_ip}" \
    -addext "subjectAltName=IP:${host_ip},DNS:pa-policy-forge.local" \
    -keyout "$APP_DIR/certs/tls.key" \
    -out "$APP_DIR/certs/tls.crt"
  chmod 600 "$APP_DIR/certs/tls.key"
fi

cd "$APP_DIR"
if [[ ! -s "$APP_DIR/.env" ]]; then
  umask 077
  trusted_hosts="$(hostname -f),$(hostname -I | awk '{print $1}'),127.0.0.1,localhost"
  bind_address="$(hostname -I | awk '{print $1}')"
  printf 'PPF_BOOTSTRAP_PASSWORD=admin\nPPF_TRUSTED_HOSTS=%s\nPPF_BIND_ADDRESS=%s\n' "$trusted_hosts" "$bind_address" > "$APP_DIR/.env"
fi
if ! grep -q '^PPF_TRUSTED_HOSTS=' "$APP_DIR/.env"; then
  trusted_hosts="$(hostname -f),$(hostname -I | awk '{print $1}'),127.0.0.1,localhost"
  printf 'PPF_TRUSTED_HOSTS=%s\n' "$trusted_hosts" >> "$APP_DIR/.env"
fi
if ! grep -q '^PPF_BIND_ADDRESS=' "$APP_DIR/.env"; then
  printf 'PPF_BIND_ADDRESS=%s\n' "$(hostname -I | awk '{print $1}')" >> "$APP_DIR/.env"
fi
docker compose up -d --build
echo "PA Policy Forge is available on https://$(hostname -I | awk '{print $1}')"
echo "Initial login: admin / admin"
echo "PA Policy Forge requires an immediate password change after the first login."
