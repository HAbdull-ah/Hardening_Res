#!/bin/bash

set -e

### CONFIG ###
read -p "Enter Splunk Indexer IP: " INDEXER_IP
echo "You entered Indexer IP: $INDEXER_IP"
read -p "Enter host name to send to Indexer: " CUSTOM_HOSTNAME
INDEXER_PORT="9997"
SPLUNK_USER="admin"
VERSION="9.1.1"

## Determine Unix Distribution ##
if [ -f /etc/os-release ]; then
    source /etc/os-release
else
    echo "Cannot detect OS (No /etc/os-release detected), skipping UF install"
    exit 1
fi
OS_FAMILY="${ID_LIKE:-$ID}"  # Uses ID_LIKE. If no ID_LIKE, uses ID instead
OS_FAMILY="${OS_FAMILY,,}"  # Converts to lowercase; That way, Fedora -> fedora
echo "Detected OS family: $OS_FAMILY"

### Get forwarder ###
wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz"

### Create User/Group ###
echo "Splunk forwarder downloaded"
groupadd -g 1005 splunkfwd
echo "splunkfwd Group Added"
useradd -u 1010 -g 1005 -m -d /opt/splunkfwd -s /usr/sbin/nologin splunkfwd
echo "splunkfwd user added to group splunkfwd"

### Extract .tgz into /opt ###
sudo tar -xzvf splunkforwarder.tgz -C /opt
echo "tar extracted to /opt"

## Create environment ###
export SPLUNK_HOME="/opt/splunkforwarder"
export SPLUNK_BIN="/opt/splunkforwarder/bin"
chown -R splunkfwd:splunkfwd $SPLUNK_HOME
echo "Environment created. Ownership changed to splunkfwd"

### Start splunk instance ###
echo "Attempting to start splunk instance"
sudo $SPLUNK_HOME/bin/splunk start --accept-license --answer-yes

# Wait until UF is fully running
echo "Waiting for Splunk UF to fully start..."
while true; do
    # Check splunk status
    STATUS=$(sudo -u splunkfwd $SPLUNK_HOME/bin/splunk status 2>/dev/null || echo "not running")
    
    if echo "$STATUS" | grep -q "splunkd is running"; then
        echo "Splunk UF is fully started."
        break
    fi
    
    echo "UF not ready yet, sleeping 5s..."
    sleep 5
done

echo "Splunk instance successfully started"

read -p "Re-Enter splunk admin password (IMPORTANT): " SPLUNK_PASS

### Enable custom host-name ###
sudo -u splunkfwd $SPLUNK_HOME/bin/splunk set default-hostname "$CUSTOM_HOSTNAME" -auth "$SPLUNK_USER:$SPLUNK_PASS"
echo "Created custom host name: $CUSTOM_HOSTNAME"


### Enable boot-start
sudo -u splunkfwd $SPLUNK_HOME/bin/splunk stop 
sudo $SPLUNK_HOME/bin/splunk enable boot-start -systemd-managed 1 -user splunkfwd
echo "Restarting splunk"
sudo -u splunkfwd $SPLUNK_HOME/bin/splunk start
echo "Boot-start enabled"

### Add indexer ###
sudo $SPLUNK_HOME/bin/splunk add forward-server ${INDEXER_IP}:${INDEXER_PORT} -auth "$SPLUNK_USER:$SPLUNK_PASS"
echo "Added indexer $INDEXER_IP"

#### CHANGES NEED TO BE MADE TO ADDING MONITORS ######
## Issue: If you try to add a monitor the system doesn't have, it throws an error and ends script.
## Solution: Add a check for system type (Ubuntu, RHEL, Debian, etc.) and add monitors based on that.
## Secondary issue: Current script asks for repeated admin user passwords to start/stop SplunkForwarder.service
## Works, but may want to find a solution for this

### Add log monitors and firewall port 9997 ###
if [[ "$OS_FAMILY" == *"debian"* ]]; then
    [ -f /var/log/auth.log ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/auth.log -index main -sourcetype linux_auth -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/auth.log not found, skipping..."
    [ -f /var/log/syslog ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/syslog -index main -sourcetype linux_messages -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/syslog not found, skipping..."
    [ -f /var/log/kern.log ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/kern.log -index main -sourcetype linux_kernel -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/kern.log not found, skipping..."
    [ -f /var/log/dpkg.log ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/dpkg.log -index main -sourcetype linux_package -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/dpkg.log not found, skipping..."
    sudo ufw allow 9997
elif [[ "$OS_FAMILY" == *"fedora"* ]]; then
    [ -f /var/log/secure ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/secure -index main -sourcetype linux_secure -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/secure not found, skipping..."
    [ -f /var/log/messages ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/messages -index main -sourcetype linux_messages -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/messages not found, skipping..." 
    [ -f /var/log/audit/audit.log ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/audit/audit.log -index main -sourcetype linux_audit -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/audit/audit.log not found, skipping..."
    [ -f /var/log/cron ] && sudo $SPLUNK_HOME/bin/splunk add monitor /var/log/cron -index main -sourcetype linux_cron -auth "$SPLUNK_USER:$SPLUNK_PASS" || echo "var/log/cron not found, skipping..."
    sudo firewall-cmd --add-port=9997/tcp --permanent
    sudo firewall-cmd --reload
else
    echo "Unsupported OS-Family: $OS_FAMILY, Cannot add monitors"
fi

### DISABLE WEB UI (HARDENING) ###
sudo -u splunkfwd $SPLUNK_HOME/bin/splunk disable webserver -auth "$SPLUNK_USER:$SPLUNK_PASS"
echo "Disabled web UI for Splunk UF"

echo "[+] Linux Splunk Universal Forwarder installed and configured successfully"
