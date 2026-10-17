#!/bin/sh
# Keystone: makes .env and the unseal key of OpenBao, starts the stack and prints what the setup wizard asks for.
# Safe to run again: an existing .env and key are kept.
set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  cp .env.example .env
fi
if ! grep -q '^POSTGRES_PASSWORD=..*' .env; then
  PW=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
  if grep -q '^POSTGRES_PASSWORD=' .env; then
    sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$PW/" .env
  else
    echo "POSTGRES_PASSWORD=$PW" >> .env
  fi
fi
chmod 600 .env

mkdir -p openbao/keys openbao/data
[ -s openbao/keys/unseal.key ] || head -c 32 /dev/urandom > openbao/keys/unseal.key

OPENBAO_VERSION=$(sed -n 's/^OPENBAO_VERSION=//p' .env); OPENBAO_VERSION=${OPENBAO_VERSION:-2.6.2}
BAO_IMAGE="openbao/openbao:$OPENBAO_VERSION"
docker pull -q "$BAO_IMAGE" >/dev/null
BAO_UID=$(docker run --rm --entrypoint id "$BAO_IMAGE" -u openbao)
BAO_GID=$(docker run --rm --entrypoint id "$BAO_IMAGE" -g openbao)
chown -R "$BAO_UID:$BAO_GID" openbao/data openbao/keys
chmod 700 openbao/keys openbao/data
chmod 400 openbao/keys/unseal.key

docker compose up -d --build

PORT=$(sed -n 's/^SPA_PORT=//p' .env); PORT=${PORT:-8080}
ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "Keystone: http://${ADDR:-localhost}:$PORT"
echo
echo "If it is not set up yet, the browser shows the setup wizard. It asks for:"
echo "  the setup code:       docker compose logs keystone | grep setup_code"
echo "  PostgreSQL password:  $(sed -n 's/^POSTGRES_PASSWORD=//p' .env)   (host postgres, database spa, user spa)"
echo "  OpenBao:              the built-in one, http://openbao:8200"
echo
echo "Keep openbao/keys/unseal.key, and the OpenBao root token and recovery key the wizard shows, in a safe place."
