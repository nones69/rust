"""
IntentOS Control Surface — configuration schema and persistence.

All runtime state lives here.  Nothing is ever mutated silently.
"""

import json
import os
import copy
import threading

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.json')
_lock = threading.RLock()

# -----------------------------------------------------------------------
# Canonical default configuration
# -----------------------------------------------------------------------
DEFAULTS: dict = {
    "mode": "simple",          # "simple" | "advanced"
    "developer_mode": False,

    "persona": {
        "enforcement_enabled": True,
        "boundary_strictness": 3,      # 1 (loose) – 5 (strict)
        "speculation_block": True,
        "evidence_only_mode": False,
        "emotional_content_block": False,
        "creativity_block": False,
        "override_enabled": False,     # developer-only
    },

    "agents": {
        "strategist": {"enabled": True,  "priority": 1, "concurrency": 1, "timeout": 30},
        "analyst":    {"enabled": True,  "priority": 2, "concurrency": 2, "timeout": 60},
        "indexer":    {"enabled": True,  "priority": 3, "concurrency": 1, "timeout": 120},
        "executor":   {"enabled": True,  "priority": 4, "concurrency": 1, "timeout": 30},
    },

    "skills": {
        "ocr":            {"enabled": True,  "requires_evidence": True,  "domain": "document"},
        "chronology":     {"enabled": True,  "requires_evidence": True,  "domain": "timeline"},
        "summarization":  {"enabled": True,  "requires_evidence": False, "domain": "general"},
        "classification": {"enabled": True,  "requires_evidence": False, "domain": "general"},
        "extraction":     {"enabled": True,  "requires_evidence": True,  "domain": "document"},
        "translation":    {"enabled": False, "requires_evidence": False, "domain": "language"},
        "reasoning":      {"enabled": True,  "requires_evidence": False, "domain": "general"},
        "custom":         {"enabled": False, "requires_evidence": False, "domain": "custom"},
    },

    "determinism": {
        "mode": "strict",                  # "strict" | "relaxed" | "sandbox"
        "reproducibility_enforcement": True,
        "hash_locking": True,
    },

    "evidence": {
        "safe_mode": True,
        "transformation_mode": False,      # developer-only
        "chain_of_custody": True,
        "metadata_extraction": True,
        "ocr_enabled": True,
        "chronology_inference": True,
    },

    "logging": {
        "mode": "standard",                # "judicial" | "standard" | "minimal" | "none"
        "export_enabled": True,
        "redaction_enabled": False,
    },

    "execution": {
        "step_through": False,
        "breakpoints": [],
        "sandbox_mode": False,
    },
}

# Hard safety rules — keys that can NEVER be changed
IMMUTABLE_SAFETY_RULES = {
    "no_self_modification":      True,
    "no_silent_failures":        True,
    "no_evidence_destruction":   True,
    "no_unlogged_transformations": True,
}

# -----------------------------------------------------------------------
# In-memory config (loaded once, mutated via update())
# -----------------------------------------------------------------------
_config: dict = copy.deepcopy(DEFAULTS)


def _load_from_disk() -> None:
    global _config
    try:
        if os.path.exists(_CONFIG_PATH):
            with open(_CONFIG_PATH) as fh:
                saved = json.load(fh)
            # Deep-merge saved values over defaults so new keys are always present
            _deep_merge(_config, saved)
    except Exception:
        pass  # If file is corrupt, start from defaults


def _save_to_disk() -> None:
    try:
        with open(_CONFIG_PATH, 'w') as fh:
            json.dump(_config, fh, indent=2)
    except Exception:
        pass


def _deep_merge(target: dict, source: dict) -> None:
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def get_all() -> dict:
    with _lock:
        return copy.deepcopy(_config)


def get_section(section: str) -> dict:
    with _lock:
        return copy.deepcopy(_config.get(section, {}))


def update(patch: dict) -> dict:
    """Apply a (possibly nested) patch to the live config. Returns updated config."""
    with _lock:
        _deep_merge(_config, patch)
        _save_to_disk()
        return copy.deepcopy(_config)


def update_section(section: str, patch: dict) -> dict:
    """Patch a single top-level section."""
    with _lock:
        if section not in _config:
            _config[section] = {}
        _deep_merge(_config[section], patch)
        _save_to_disk()
        return copy.deepcopy(_config[section])


def reset_to_defaults() -> dict:
    global _config
    with _lock:
        _config = copy.deepcopy(DEFAULTS)
        _save_to_disk()
        return copy.deepcopy(_config)


def get_safety_rules() -> dict:
    return copy.deepcopy(IMMUTABLE_SAFETY_RULES)


# Load persisted state on import
_load_from_disk()
