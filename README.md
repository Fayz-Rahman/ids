# Lightweight Network IDS

A lightweight network anomaly IDS in Go. It watches packets, keeps small per-source counters in memory, checks a few simple rules, and only alerts. It does not block traffic.

## What it detects
* port scans
* sudden traffic spikes
* SYN-heavy bursts

## Requirements
* **Linux:** libpcap development headers and Go
* **Windows:** Go and Npcap

## Quick Start (Automated Setup)
You can use the provided wrapper scripts to automatically build the binaries, select your network interface, generate the configuration, and manage background processes. 

**On Linux:**
`bash
sudo bash script/run.sh
`

**On Windows (Run PowerShell as Administrator):**
`powershell
.\script\run.ps1
`
*(Note: You may need to run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first if Windows blocks the script).*

The script will prompt you for your Webhook URL, generate the `config.yaml`, start the relay in the background, and ask how you want to run the IDS. To easily clean up background processes later, execute the `stop.sh` or `stop.ps1` file that generates in your `script/` folder.

---

## Manual Execution 

If you prefer to run the components manually without the setup scripts, follow these steps.

**1. Start the Relay (Optional)**
The IDS can POST alert JSON to a local relay. The relay can then forward to Discord or another app.
`bash
go run ./relay -listen :8080 -path /webhook
`
Set `notify.webhook` in `config.yaml` to `"http://127.0.0.1:8080/webhook"`.

**2. Build and Run the IDS**

**Linux:**
`bash
go build -o ids .
sudo ./ids -list
sudo ./ids -config config.yaml
`
Use `lo` for safe local testing, or your active NIC for real traffic.

**Windows:**
`powershell
go build -o ids.exe .
.\ids.exe -list
.\ids.exe -config config.yaml
`
Run PowerShell as Administrator and pick the active Wi-Fi or Ethernet adapter in `config.yaml`. 

