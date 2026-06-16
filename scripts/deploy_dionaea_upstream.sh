#!/bin/bash

URL=$1
DEPLOY=$2
SERVER=$(echo ${URL} | awk -F/ '{print $3}')
VERSION=latest
TAGS=""

HOSTNAME=$(hostname)
IP=$(curl -s ifconfig.me)

echo 'Registering sensor with CHN server...'
SENSOR_JSON=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"dionaea-${HOSTNAME}\",\"hostname\":\"${HOSTNAME}\",\"ip\":\"${IP}\",\"honeypot\":\"dionaea\",\"deploy_key\":\"${DEPLOY}\"}" \
  "${URL}/api/sensor/")

IDENTIFIER=$(echo $SENSOR_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['identifier'])")
SECRET=$(echo $SENSOR_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['secret'])")

if [ -z "$IDENTIFIER" ] || [ -z "$SECRET" ]; then
  echo "ERROR: Registration failed. Response was: $SENSOR_JSON"
  exit 1
fi

echo 'Creating hpfeeds.yaml...'
mkdir -p ./dionaea/ihandlers-enabled
cat << EOF > ./dionaea/ihandlers-enabled/hpfeeds.yaml
- name: hpfeeds
  config:
    server: "${SERVER}"
    port: 10000
    ident: "${IDENTIFIER}"
    secret: "${SECRET}"
    reconnect_timeout: 10.0
EOF
echo 'Done!'

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
services:
  dionaea:
    image: dinotools/dionaea:${VERSION}
    restart: always
    network_mode: host
    volumes:
      - ./dionaea/ihandlers-enabled/hpfeeds.yaml:/opt/dionaea/template/etc/dionaea/ihandlers-enabled/hpfeeds.yaml
    env_file:
      - dionaea.env
EOF
echo 'Done!'

echo 'Creating dionaea.env...'
cat << EOF > dionaea.env
LISTEN_ADDRESSES=0.0.0.0
LISTEN_INTERFACES=eth0

# double quotes, comma delimited tags may be specified, which will be included
# as a field in the hpfeeds output.
TAGS=${TAGS}
EOF
echo 'Done!'

echo ''
echo 'Type "docker compose ps" to confirm your honeypot is running'
echo 'You may type "docker compose logs" to get any error or informational logs from your honeypot'
