"""Verify the package imports and initializes cleanly."""


def test_package_imports():
    """All core modules should be importable."""
    import packetsniffer_mcp

    assert packetsniffer_mcp.__version__ == "0.1.0"


def test_config_loads():
    """Config should load with defaults."""
    from packetsniffer_mcp.config import get_llm_config

    cfg = get_llm_config()
    assert cfg.base_url
    assert cfg.model
