"""Tests that optional-dependency fallback paths work when the package is absent."""

import importlib
import sys
import types
import asyncio
import pytest


def _reload_with_missing(module_name: str, missing_dep: str):
    """Reload *module_name* with *missing_dep* replaced by a stub that raises ImportError."""
    # Remove the target module so it will be freshly imported
    to_remove = [k for k in sys.modules if k == module_name or k.startswith(module_name + ".")]
    for k in to_remove:
        del sys.modules[k]

    # Install a broken stub for the optional dependency
    original = sys.modules.pop(missing_dep, None)
    broken = types.ModuleType(missing_dep)

    def _raise(*_a, **_kw):
        raise ImportError(f"No module named '{missing_dep}'")

    broken.__getattr__ = _raise  # type: ignore[attr-defined]
    sys.modules[missing_dep] = broken

    try:
        mod = importlib.import_module(module_name)
    finally:
        # Restore original state
        del sys.modules[missing_dep]
        if original is not None:
            sys.modules[missing_dep] = original
        # Remove the freshly-loaded module so it doesn't pollute other tests
        for k in list(sys.modules):
            if k == module_name or k.startswith(module_name + "."):
                del sys.modules[k]

    return mod


# ---------------------------------------------------------------------------
# config.py – python-dotenv fallback
# ---------------------------------------------------------------------------

class TestConfigDotenvFallback:
    def test_load_dotenv_fallback_returns_false(self, monkeypatch):
        """When dotenv is absent the stub load_dotenv should return False gracefully."""
        # Patch sys.modules so that 'dotenv' appears missing during reload
        monkeypatch.delitem(sys.modules, "dotenv", raising=False)
        monkeypatch.delitem(sys.modules, "ip_discrambler.config", raising=False)

        # Inject a broken dotenv module
        broken = types.ModuleType("dotenv")
        broken.__spec__ = None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "dotenv", broken)

        # Make 'from dotenv import load_dotenv' raise ImportError
        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        import builtins
        real_import = builtins.__import__

        def patched_import(name, *args, **kwargs):
            if name == "dotenv":
                raise ImportError("No module named 'dotenv'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", patched_import)

        # Remove stale module so it is freshly imported
        monkeypatch.delitem(sys.modules, "ip_discrambler.config", raising=False)

        import ip_discrambler.config as cfg_mod

        # The fallback stub must be callable and must return False
        result = cfg_mod.load_dotenv("nonexistent.env")
        assert result is False

    def test_config_from_env_works_without_dotenv(self, monkeypatch):
        """Config.from_env() must not raise even when python-dotenv is absent."""
        import builtins
        real_import = builtins.__import__

        def patched_import(name, *args, **kwargs):
            if name == "dotenv":
                raise ImportError("No module named 'dotenv'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", patched_import)
        monkeypatch.delitem(sys.modules, "ip_discrambler.config", raising=False)

        import ip_discrambler.config as cfg_mod
        cfg = cfg_mod.Config.from_env("/nonexistent/.env")
        assert cfg.request_timeout == 10.0


# ---------------------------------------------------------------------------
# providers/whois_rdap.py – ipwhois fallback
# ---------------------------------------------------------------------------

class TestWhoisRdapFallback:
    def test_lookup_returns_error_when_ipwhois_missing(self, monkeypatch):
        """WhoisRdapProvider.lookup() returns an error dict when ipwhois is absent."""
        import ip_discrambler.providers.whois_rdap as whois_mod
        import ip_discrambler.config as cfg_mod

        # Force the module-level IPWhois to None (simulates ImportError path)
        monkeypatch.setattr(whois_mod, "IPWhois", None)

        provider = whois_mod.WhoisRdapProvider(cfg_mod.Config())
        result = provider.lookup("8.8.8.8")
        assert "error" in result
        assert "ipwhois" in result["error"].lower()


# ---------------------------------------------------------------------------
# providers/threat_intel.py – httpx fallback
# ---------------------------------------------------------------------------

class TestThreatIntelFallback:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_abuseipdb_returns_error_when_httpx_missing(self, monkeypatch):
        import ip_discrambler.providers.threat_intel as ti_mod
        import ip_discrambler.config as cfg_mod

        monkeypatch.setattr(ti_mod, "httpx", None)
        cfg = cfg_mod.Config(abuseipdb_api_key="dummy")
        provider = ti_mod.AbuseIPDBProvider(cfg)
        result = self._run(provider.lookup("1.2.3.4"))
        assert "error" in result
        assert "httpx" in result["error"].lower()

    def test_virustotal_returns_error_when_httpx_missing(self, monkeypatch):
        import ip_discrambler.providers.threat_intel as ti_mod
        import ip_discrambler.config as cfg_mod

        monkeypatch.setattr(ti_mod, "httpx", None)
        cfg = cfg_mod.Config(virustotal_api_key="dummy")
        provider = ti_mod.VirusTotalProvider(cfg)
        result = self._run(provider.lookup("1.2.3.4"))
        assert "error" in result
        assert "httpx" in result["error"].lower()

    def test_shodan_returns_error_when_httpx_missing(self, monkeypatch):
        import ip_discrambler.providers.threat_intel as ti_mod
        import ip_discrambler.config as cfg_mod

        monkeypatch.setattr(ti_mod, "httpx", None)
        cfg = cfg_mod.Config(shodan_api_key="dummy")
        provider = ti_mod.ShodanProvider(cfg)
        result = self._run(provider.lookup("1.2.3.4"))
        assert "error" in result
        assert "httpx" in result["error"].lower()


# ---------------------------------------------------------------------------
# providers/geolocation.py – httpx fallback
# ---------------------------------------------------------------------------

class TestGeolocationFallback:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_ipwhoisgeo_returns_error_when_httpx_missing(self, monkeypatch):
        import ip_discrambler.providers.geolocation as geo_mod
        import ip_discrambler.config as cfg_mod

        monkeypatch.setattr(geo_mod, "httpx", None)
        provider = geo_mod.IPWhoisGeoProvider(cfg_mod.Config())
        result = self._run(provider.lookup("8.8.8.8"))
        assert "error" in result
        assert "httpx" in result["error"].lower()
