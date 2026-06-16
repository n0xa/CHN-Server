#!/bin/bash

# In development 

set -e
set -x

if [ $# -ne 2 ]
    then
        echo "Wrong number of arguments supplied."
        echo "Usage: $0 <server_url> <deploy_key>."
        exit 1
fi

apt update


server_url=$1
deploy_key=$2

wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "cowrie"

sudo apt install -y git libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv supervisor rustc

systemctl start supervisor || true

sed -i 's/^Port 22$/Port 2101/g' /etc/ssh/sshd_config
sed -i 's/^#Port 22$/Port 2101/g' /etc/ssh/sshd_config

service ssh restart
useradd -d /home/cowrie -s /bin/bash -m cowrie -g users

cd /opt
git clone https://github.com/cowrie/cowrie.git cowrie
cd cowrie
mkdir -p var/log/cowrie/tty
mkdir -p var/log/cowrie/downloads
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
pip install hpfeeds3

hostnames=("dbutil" "mail" "guppie" "jupiter" "luna" "midnight" "halcyon" "snoopy") hostnm=${hostnames[`expr $RANDOM % 8`]}

echo "
[honeypot]
hostname = $hostnm
log_path = var/log/cowrie
download_path = \${honeypot:log_path}/downloads
share_path = share/cowrie
state_path = var/lib/cowrie
etc_path = etc
txtcmds_path = txtcmds
#download_limit_size = 10485760
ttylog = true
ttylog_path = \${honeypot:log_path}/tty
interactive_timeout = 180
authentication_timeout = 120
backend = shell
#out_addr = 0.0.0.0
#fake_addr = 192.168.66.254
#internet_facing_ip = 9.9.9.9
auth_class = UserDB
[shell]
filesystem = \${honeypot:share_path}/fs.pickle
processes = share/cowrie/cmdoutput.json
arch = linux-x64-lsb
kernel_version = 5.10.63-4-amd64
kernel_build_string = #1 SMP Debian 5.10.63-1+deb7u1
hardware_platform = x86_64
operating_system = GNU/Linux
[ssh]
enabled = true
rsa_public_key = \${honeypot:state_path}/ssh_host_rsa_key.pub
rsa_private_key = \${honeypot:state_path}/ssh_host_rsa_key
dsa_public_key = \${honeypot:state_path}/ssh_host_dsa_key.pub
dsa_private_key = \${honeypot:state_path}/ssh_host_dsa_key
ecdsa_public_key = \${honeypot:state_path}/ssh_host_ecdsa_key.pub
ecdsa_private_key = \${honeypot:state_path}/ssh_host_ecdsa_key
ed25519_public_key = \${honeypot:state_path}/ssh_host_ed25519_key.pub
ed25519_private_key = \${honeypot:state_path}/ssh_host_ed25519_key
public_key_auth = ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519
version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
ciphers = aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc
macs = hmac-sha2-512,hmac-sha2-384,hmac-sha2-56,hmac-sha1,hmac-md5
compression = zlib@openssh.com,zlib,none
listen_endpoints = tcp:22:interface=0.0.0.0
sftp_enabled = true
forwarding = true
forward_redirect = false
forward_tunnel = false
auth_keyboard_interactive_enabled = false
[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0
[output_jsonlog]
enabled = true
logfile = \${honeypot:log_path}/cowrie.json
[output_hpfeeds3]
enabled = true
server = $HPF_HOST
port = $HPF_PORT
identifier = $HPF_IDENT
secret = $HPF_SECRET
debug=false
" > etc/cowrie.cfg

chown -R cowrie:users /opt/cowrie/
touch /etc/authbind/byport/22
chown cowrie /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22

touch /etc/authbind/byport/23
chown cowrie /etc/authbind/byport/23
chmod 770 /etc/authbind/byport/23

sed -i 's/AUTHBIND_ENABLED=no/AUTHBIND_ENABLED=yes/' bin/cowrie
sed -i 's/DAEMONIZE=""/DAEMONIZE="-n"/' bin/cowrie

# Config for supervisor
cat > /etc/supervisor/conf.d/cowrie.conf <<EOF
[program:cowrie]
environment=COWRIE_STDOUT=yes
command=/opt/cowrie/bin/cowrie start
directory=/opt/cowrie
stdout_logfile=/opt/cowrie/var/log/cowrie/cowrie.out
stderr_logfile=/opt/cowrie/var/log/cowrie/cowrie.err
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
user=cowrie
EOF

cat >> /etc/crontab <<EOF
0 23 * * * supervisorctl restart all
0 5 * * * find /opt/cowrie/var/log/cowrie -type f -mtime +7 | xargs rm
EOF

sudo systemctl enable supervisor
supervisorctl update
