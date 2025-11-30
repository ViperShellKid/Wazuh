🛡️ Wazuh – Full Detailed Demonstration (Installation + Configuration + Verification)
Wazuh has 3 main components:

1️⃣ Wazuh Manager
Core brain of the SIEM.

Receives logs, applies rules, creates alerts.

2️⃣ Wazuh Indexer (OpenSearch)
Stores all logs and events.

Powers search and dashboards.

3️⃣ Wazuh Dashboard
Web UI for monitoring.

Visualizes alerts, agents, rules, vulnerabilities.

✅ 1. Install Wazuh Manager, Indexer & Dashboard (All-in-One Deployment)
Wazuh provides an official installation script.

Step 1: Download installer
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
chmod +x wazuh-install.sh
Step 2: Run installation
sudo ./wazuh-install.sh -a
This installs:

wazuh-manager

wazuh-indexer

wazuh-dashboard

Dashboard Access
After installation:

URL: https://<your-server-ip>

Default user: admin

Password: printed at end of installation.

✅ 2. Adding Wazuh Agents (Linux / Windows)
You must install an agent on each endpoint.

🐧 Install Wazuh Agent on Linux
Step 1: Download agent package
curl -sO https://packages.wazuh.com/4.8/wazuh-agent_4.8.0-1_amd64.deb
sudo dpkg -i wazuh-agent_4.8.0-1_amd64.deb
Step 2: Configure agent manager IP
sudo nano /var/ossec/etc/ossec.conf
Add inside <client>:

<server>
    <address>YOUR_WAZUH_SERVER_IP</address>
</server>
Step 3: Start agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
🪟 Install Wazuh Agent on Windows
Download installer from dashboard:
Dashboard → Agents → Deploy new agent

Choose Windows → Copy the PowerShell command.

Run in PowerShell (Administrator).

Agent automatically registers.

🔍 3. Verify Agents Are Connected
Go to:

Wazuh Dashboard → Agents

You should see:

Status: Active

Version: 4.8.x

Last keepalive: few seconds ago

If “Disconnected”:

Check firewall ports: 1514, 1515 open

Restart agent:

sudo systemctl restart wazuh-agent
🛑 4. Generate Test Alerts
Linux test
sudo su -
useradd test123
Dashboard → Security Events → You see:

User added

Privilege escalation

System modification

Malicious file test
echo "malware-test" > /tmp/testfile
You get:

Unusual file created

Suspicious keywords

🛡️ 5. Wazuh Capabilities Demonstration
Here are the features you can show in your demo:

📌 1. File Integrity Monitoring (FIM)
Add folder to monitor:

sudo nano /var/ossec/etc/ossec.conf
Add:

<syscheck>
  <directories>/etc,/home</directories>
</syscheck>
Restart:

sudo systemctl restart wazuh-manager
Modify file:

echo "test123" >> /etc/hosts
You will see an alert:

File modified

Shows old vs new content hash

📌 2. Vulnerability Detection
Enabled by default.

You will see:

Software CVEs

Severity (High, Critical)

CVE numbers

📌 3. Malware Scan (YARA + VirusTotal)
YARA configuration:

<yara-rule>myrules.yar</yara-rule>
VirusTotal integration:

Add API key in ossec.conf.

📌 4. Log Collection
Send logs from:

Syslog (Linux)

Windows Event Logs

Webserver logs (Apache/Nginx)

Example syslog input:

sudo nano /etc/rsyslog.d/wazuh.conf
Add:

*.* @WAZUH_SERVER_IP:514
📌 5. Active Response (Auto Block Attackers)
Enable active response:

<active-response>
  <command>firewalld</command>
  <level>10</level>
</active-response>
Test:

ssh wronguser@server-ip
You see:
✔ multiple failed logins
✔ Wazuh auto-blocks your IP

📊 6. Dashboard Demonstration
Show sections:

→ Security Events
All alerts

Filter by severity

→ Agents Overview
Connected endpoints

OS, IP, uptime

→ Threat Intelligence
CVE detection

MITRE ATT&CK mapping

→ PCI-DSS / GDPR / ISO templates
Built-in compliance.
