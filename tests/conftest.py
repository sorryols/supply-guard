import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("LIBSENTINEL_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


@pytest.fixture
def cfg():
    from libsentinel.config import load_config
    return load_config()


@pytest.fixture(scope="session")
def synthetic(tmp_path_factory):
    import make_synthetic
    out = tmp_path_factory.mktemp("synthetic")
    make_synthetic.generate(out)
    return out
