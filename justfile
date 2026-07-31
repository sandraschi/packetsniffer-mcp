set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]

default:
    @just --list

install:
    uv sync --extra dev
    pre-commit install

serve:
    uv run python -m packetsniffer_mcp

web:
    @powershell -ExecutionPolicy Bypass -File start.ps1

lint:
    uv run ruff check .
    uv run ruff format --check .

fix:
    uv run ruff check . --fix
    uv run ruff format .

test:
    uv run pytest tests/ -v

mcpb-pack:
    @powershell.exe -NoProfile -File scripts/pack.ps1

ci: lint test

# Bootstrap: install dev deps + pre-commit hook
bootstrap:
    uv sync --group dev
    uv run pre-commit install
    Write-Host "Pre-commit hooks installed." -ForegroundColor Green