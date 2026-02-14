# ==========================================================
# Windows FTP Server Hardening Script
# Run as Administrator
# ==========================================================

Write-Host "Starting FTP Server Hardening..." -ForegroundColor Cyan

# -------------------------------
# Enable Firewall (All Profiles)
# -------------------------------
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# -------------------------------
# Remove Insecure Firewall Rules
# -------------------------------
Write-Host "Removing overly permissive firewall rules..."
Get-NetFirewallRule | Where-Object {$_.Action -eq "Allow" -and $_.Enabled -eq "True"} |
Where-Object {$_.Direction -eq "Inbound"} |
Where-Object {$_.DisplayName -notmatch "FTP"} |
Disable-NetFirewallRule

# -------------------------------
# Allow FTP Control Channel (21)
# -------------------------------
Write-Host "Allowing FTP port 21..."
New-NetFirewallRule `
  -DisplayName "FTP-Control-21" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 21 `
  -Action Allow

# -------------------------------
# Allow FTP Passive Ports
# Change range if needed
# -------------------------------
Write-Host "Allowing FTP Passive Ports..."
New-NetFirewallRule `
  -DisplayName "FTP-Passive-50000-51000" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 50000-51000 `
  -Action Allow

# -------------------------------
# Disable Anonymous FTP
# -------------------------------
Write-Host "Disabling Anonymous FTP..."
Import-Module WebAdministration
Set-ItemProperty "IIS:\Sites\Default FTP Site" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
Set-ItemProperty "IIS:\Sites\Default FTP Site" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true

# -------------------------------
# Enforce SSL (FTPS)
# -------------------------------
Write-Host "Requiring SSL for FTP..."
Set-ItemProperty "IIS:\Sites\Default FTP Site" -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
Set-ItemProperty "IIS:\Sites\Default FTP Site" -Name ftpServer.security.ssl.dataChannelPolicy -Value 1

# -------------------------------
# Enable FTP Logging
# -------------------------------
Write-Host "Enabling FTP Logging..."
Set-ItemProperty "IIS:\Sites\Default FTP Site" -Name ftpServer.logFile.enabled -Value $true

# -------------------------------
# NTFS Permissions Hardening
# -------------------------------
Write-Host "Restricting NTFS Permissions..."
$ftpRoot = "C:\inetpub\ftproot"

icacls $ftpRoot /inheritance:r
icacls $ftpRoot /grant "Administrators:(OI)(CI)F"
icacls $ftpRoot /grant "FTPUsers:(OI)(CI)RX"

# -------------------------------
# Disable SMBv1
# -------------------------------
Write-Host "Disabling SMBv1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# -------------------------------
# Disable Unnecessary Services
# -------------------------------
Write-Host "Disabling insecure services..."
$services = @(
    "Telnet",
    "SNMP",
    "RemoteRegistry"
)

foreach ($service in $services) {
    Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}

# -------------------------------
# Enable Auditing
# -------------------------------
Write-Host "Enabling audit policies..."
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# -------------------------------
# Restart IIS
# -------------------------------
Write-Host "Restarting IIS..."
iisreset

Write-Host "FTP Hardening Complete!" -ForegroundColor Green
