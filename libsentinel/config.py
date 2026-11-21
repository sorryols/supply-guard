"""Завантаження конфігурації (параметри правила рішення, рівні довіри)."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_CONFIG = DATA_DIR / "default_config.yaml"


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    with open(DEFAULT_CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if path:
        with open(path, encoding="utf-8") as f:
            cfg = _merge(cfg, yaml.safe_load(f) or {})
    return cfg


def config_hash(cfg: Dict[str, Any]) -> str:
    """Хеш конфігурації — для ключа кешу результатів."""
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:16]
