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
  -d "{\"name\":\"cowrie-${HOSTNAME}\",\"hostname\":\"${HOSTNAME}\",\"ip\":\"${IP}\",\"honeypot\":\"cowrie\",\"deploy_key\":\"${DEPLOY}\"}" \
  "${URL}/api/sensor/")

IDENTIFIER=$(echo $SENSOR_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['identifier'])")
SECRET=$(echo $SENSOR_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['secret'])")

if [ -z "$IDENTIFIER" ] || [ -z "$SECRET" ]; then
  echo "ERROR: Registration failed. Response was: $SENSOR_JSON"
  exit 1
fi

echo 'Creating docker-compose.yml...'
cat << EOF > ./docker-compose.yml
services:
  cowrie:
    image: cowrie/cowrie:${VERSION}
    restart: always
    ports:
      - "22:2222"
      - "23:2223"
    env_file:
      - cowrie.env
EOF
echo 'Done!'

echo 'Creating cowrie.env...'
cat << EOF > cowrie.env
COWRIE_TELNET_ENABLED=yes

COWRIE_OUTPUT_HPFEEDS3_ENABLED=true
COWRIE_OUTPUT_HPFEEDS3_SERVER=${SERVER}
COWRIE_OUTPUT_HPFEEDS3_PORT=10000
COWRIE_OUTPUT_HPFEEDS3_IDENTIFIER=${IDENTIFIER}
COWRIE_OUTPUT_HPFEEDS3_SECRET=${SECRET}
COWRIE_OUTPUT_HPFEEDS3_CHANNEL=cowrie.sessions

# double quotes, comma delimited tags may be specified, which will be included
# as a field in the hpfeeds output.
TAGS=${TAGS}
EOF
echo 'Done!'

echo ''
echo 'Type "docker compose ps" to confirm your honeypot is running'
echo 'You may type "docker compose logs" to get any error or informational logs from your honeypot'
