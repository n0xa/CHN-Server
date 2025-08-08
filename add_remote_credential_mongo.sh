#!/bin/bash
# A Non-Docker/Python replacement to create remote hpfeeds credentials
if (( $# != 2 ))
then
    echo "$0 [ident] [remote_ip]"
    echo "Illegal number of parameters; please include an ident and remote parameter!"
    exit 1
fi
# This generates a new random password and directly inserts it into MongoDB using mongo CLI

IDENT=$1
REMOTE=$2
SECRET=$(cat /dev/urandom | tr -dc "[_A-Za-z0-9]" | dd bs=20 count=1 2>/dev/null)

# MongoDB connection details - adjust as needed
MONGODB_HOST=${MONGODB_HOST:-localhost}
MONGODB_PORT=${MONGODB_PORT:-27017}

# List of channels the remote credential can subscribe to
SUBSCRIBE_CHANNELS="[\"amun.events\",\"conpot.events\",\"thug.events\",\"beeswarm.hive\",\"dionaea.capture\",\"dionaea.connections\",\"thug.files\",\"beeswarm.feeder\",\"cuckoo.analysis\",\"kippo.sessions\",\"cowrie.sessions\",\"glastopf.events\",\"glastopf.files\",\"mwbinary.dionaea.sensorunique\",\"snort.alerts\",\"wordpot.events\",\"p0f.events\",\"suricata.events\",\"shockpot.events\",\"elastichoney.events\",\"rdphoney.sessions\",\"uhp.events\",\"elasticpot.events\",\"spylex.events\",\"big-hp.events\",\"honeydb-agent.events\"]"

echo "Creating hpfeeds credential directly in MongoDB..."
echo "Ident: ${IDENT}"
echo "Remote IP: ${REMOTE}"
echo "MongoDB Host: ${MONGODB_HOST}:${MONGODB_PORT}"

# Use mongo CLI to insert/update the credential
mongo --host "${MONGODB_HOST}:${MONGODB_PORT}" hpfeeds --eval "
db.auth_key.updateOne(
    { \"identifier\": \"${IDENT}\" },
    { \$set: {
        \"owner\": \"chn\",
        \"ident\": \"${IDENT}\",
        \"secret\": \"${SECRET}\",
        \"publish\": [],
        \"subscribe\": ${SUBSCRIBE_CHANNELS}
    }},
    { upsert: true }
);
print('Credential for ${IDENT} created/updated successfully');
"

if [ $? -eq 0 ]; then
    cat << EOF
IDENT=${IDENT}
SECRET=${SECRET}
CHANNELS=amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events,elasticpot.events,spylex.events,big-hp.events,ssh-auth-logger.events,honeydb-agent.events
HPFEEDS_HOST=${REMOTE}
HPFEEDS_PORT=10000

EOF
else
    echo "Failed to create credential. Make sure MongoDB is running and accessible."
    exit 1
fi
