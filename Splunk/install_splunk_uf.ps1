# ================= PROMPT =================
$IndexerIP = Read-Host "Enter the Splunk Indexer IP: "
$CustomHostName = Read-Host "Enter host name to send to Indexer: "
$SplunkPass = Read-Host "Please enter Splunk admin password (IMPORTANT): "
$SplunkUser = "admin"
$SplunkAuth = "$SplunkUser`:$SplunkPass"
$IndexerPort = "9997"
$Version = "9.1.1"

$SplunkHome = "C:\Program Files\SplunkUniversalForwarder"
$SplunkBin = "$SplunkHome\bin\splunk.exe"
$InputsDir = "$SplunkHome\etc\apps\local_inputs\local"

# ================= DOWNLOAD SPLUNK UF =================
$URL = "https://download.splunk.com/products/universalforwarder/releases/9.1.1/windows/splunkforwarder-9.1.1-64e843ea36b1-x64-release-airgap.msi"
$Installer = "$env:TEMP\splunkforwarder.msi"

Invoke-WebRequest -Uri $URL -OutFile $Installer
Write-Host "Downloaded Installer"

# ================= INSTALL =================
Write-Host "Attempting to start install"
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$Installer`" AGREETOLICENSE=Yes /quiet /norestart SPLUNKUSERNAME=admin SPLUNKPASSWORD=$SplunkPass"

# ================= START SPLUNK =================
Write-Host "Attempting to start Splunk instance"
& $SplunkBin start --accept-license --answer-yes
$SplunkAuth = "$SplunkUser`:$SplunkPass"

# =============== Set Admin Password =============
# Write-Host "Attempting to edit admin user password"
# & $SplunkBin edit user admin -password "$SplunkPass" -role admin -auth "admin:changeme"

# ================= SET HOSTNAME =================
Write-Host "Attempting to change default hostname"
& $SplunkBin set default-hostname $CustomHostName -auth $SplunkAuth

# ================= ADD INDEXER ================
Write-Host "Attempting to addd forwarder server"
& $SplunkBin add forward-server "$IndexerIP`:$IndexerPort" -auth $SplunkAuth

# ================= CREATE INPUTS.CONF =================
Write-Host "Attempting to create inputs.conf"
New-Item -ItemType Directory -Force -Path $InputsDir | Out-Null

$InputsConf = @"
[WinEventLog://Application]
index = main
disabled = 0

[WinEventLog://System]
index = main
disabled = 0

[WinEventLog://Security]
index = main
disabled = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = main
disabled = 0

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
index = main
disabled = 0
"@
## The last log file is the only one not currently being logged correctly.

Set-Content -Path "$InputsDir\inputs.conf" -Value $InputsConf -Encoding ASCII

# ================= RESTART SPLUNK =================
Write-Host "Restarting Splunk"
& $SplunkBin restart

# ================= HARDEN =================
Write-Host "Attempting to disable web server"
& $SplunkBin disable webserver -auth $SplunkAuth

$RuleName = "Splunk UF 9997 Outbound"

## Only create new rule if it doesn't already exist
if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $RuleName `
                        -Direction Outbound `
                        -Protocol TCP `
                        -LocalPort  Any `
                        -RemotePort 9997 `
                        -RemoteAddress $IndexerIP `
                        -Action Allow
    Write-Host "Opened TCP port 9997 outbound to $IndexerIP"
} else {
    Write-Host "Outbound firewall rule for port 9997 already exists"
}

Write-Host "[+] Windows Splunk Universal Forwarder downloaded, installed, and configured successfully"
