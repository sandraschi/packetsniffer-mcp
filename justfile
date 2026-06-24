set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

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
    ruff check .
    ruff format --check .

fix:
    ruff check . --fix
    ruff format .

test:
    uv run pytest tests/ -v

mcpb-pack:
    @pwsh -NoLogo -File scripts/pack.ps1

ci: lint test
