$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $RepoRoot
$ver = (Select-String '^version = "(.*)"' pyproject.toml).Matches.Groups[1].Value
$null = New-Item -ItemType Directory -Path dist -Force
npx --yes @anthropic-ai/mcpb@latest validate .
npx --yes @anthropic-ai/mcpb@latest pack . "dist/packetsniffer-mcp-v$ver.mcpb"
Write-Host "Created dist/packetsniffer-mcp-v$ver.mcpb" -ForegroundColor Green
