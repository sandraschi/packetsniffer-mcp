# packetsniffer-mcp — dev launcher
param([switch]$Headless, [switch]$NoBrowser)

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Parent $PSCommandPath

# Kill any existing server on the port
$port = if ($env:MCP_PORT) { [int]$env:MCP_PORT } else { 10800 }
Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Write-Host "Starting packetsniffer-mcp on http://127.0.0.1:$port" -ForegroundColor Cyan

if (-not $Headless) {
    Start-Process "http://127.0.0.1:$port"
}

Set-Location $ScriptRoot
uv run python -m packetsniffer_mcp --http --port $port
