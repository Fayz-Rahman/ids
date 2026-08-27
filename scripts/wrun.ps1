$ScriptDir = $PSScriptRoot
$RootDir = Split-Path $ScriptDir -Parent
Set-Location $RootDir

Write-Host "=== Network Monitor Startup (Windows) ===" -ForegroundColor Cyan

Write-Host "Building Go binaries..."
go build -o ids.exe .
go build -o relay.exe ./relay

Stop-Process -Name "relay" -ErrorAction SilentlyContinue

$StopScriptPath = Join-Path $ScriptDir "stop.ps1"
Set-Content -Path $StopScriptPath -Value 'Write-Host "Stopping processes..."'

$Webhook = Read-Host "Enter Discord Webhook URL"
$env:DISCORD_WEBHOOK_URL = $Webhook

Write-Host "`nAvailable network interfaces:" -ForegroundColor Yellow
.\ids.exe -list

$Iface = Read-Host "Enter the interface to monitor (e.g., GUID or friendly name)"

Write-Host "Applying configuration..."
$ConfigContent = @"
interface: "$Iface"
bpf: "tcp or udp"
interval_ms: 1000
snaplen: 128
evict_idle_s: 120
rules:
  port_scan_ports: 15
  rate_spike_multiple: 5.0
  syn_flood_ratio: 0.8
notify:
  webhook: "http://127.0.0.1:8080/webhook"
  log_file: "ids.log"
  cooldown_s: 300
"@
Set-Content -Path "config.yaml" -Value $ConfigContent

Write-Host "Starting Discord Relay in the background..."
$RelayProcess = Start-Process -FilePath ".\relay.exe" -ArgumentList "-listen :8080 -path /webhook" -PassThru -NoNewWindow
$RelayPid = $RelayProcess.Id
Add-Content -Path $StopScriptPath -Value "Stop-Process -Id $RelayPid -Force -ErrorAction SilentlyContinue"

Start-Sleep -Seconds 2

Write-Host "`n----------------------------------------"
$RunBg = Read-Host "Run IDS in the background? (y/N)"

if ($RunBg -match "^[Yy]$") {
    Write-Host "Starting IDS in the background (requires Admin)..." -ForegroundColor Green
    $IdsProcess = Start-Process -FilePath ".\ids.exe" -ArgumentList "-config config.yaml" -PassThru -NoNewWindow
    $IdsPid = $IdsProcess.Id
    Add-Content -Path $StopScriptPath -Value "Stop-Process -Id $IdsPid -Force -ErrorAction SilentlyContinue"
    Write-Host "`nAll services are running in the background."
    Write-Host "Run .\script\stop.ps1 whenever you are ready to terminate them."
} else {
    Write-Host "`nStarting IDS in the foreground (requires Admin)..." -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop the IDS, then run .\script\stop.ps1 to kill the background relay."
    .\ids.exe -config config.yaml
}