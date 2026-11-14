"""Блокові тести модуля deps (D1–D4, К4)."""

import json

import pytest

from libsentinel import deps
from libsentinel.models import Context, PackageVersion


@pytest.mark.parametrize("a,b,d", [("requests", "requests", 0), ("reqeusts", "requests", 2),
                                   ("request", "requests", 1), ("kitten", "sitting", 3)])
def test_levenshtein(a, b, d):
    assert deps.levenshtein(a, b) == d


def test_similar_popular():
    top = ["requests", "numpy", "urllib3"]
    assert deps.similar_popular("reqeusts", top, 2) == "requests"
    assert deps.similar_popular("requests", top, 2) is None
    assert deps.similar_popular("python-numpy", top, 2) == "numpy"
    assert deps.similar_popular("totally-different", top, 2) is None


def test_parse_requires_skips_extras():
    r = deps.parse_requires(["requests>=2", "pytest; extra == 'dev'", "Typing_Extensions"])
    assert set(r) == {"requests", "typing-extensions"}


def test_osv_malicious_mapping():
    v = deps._osv_to_vuln({"id": "MAL-2024-1", "summary": "Malicious code"}, "evil", "1.0")
    assert v.malicious
    v2 = deps._osv_to_vuln({"id": "GHSA-x", "aliases": ["CVE-2024-1"], "database_specific": {"severity": "HIGH"},
                            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]},
                           "lib", "1.0")
    assert not v2.malicious and v2.fixed == "2.0" and "CVE-2024-1" in v2.id


def test_ossf_local(tmp_path):
    d = tmp_path / "osv" / "malicious" / "pypi" / "evilpkg"
    d.mkdir(parents=True)
    (d / "MAL-2025-1.json").write_text(json.dumps(
        {"id": "MAL-2025-1", "affected": [{"versions": ["1.0.1"]}]}))
    assert deps.ossf_local_malicious("evilpkg", "1.0.1", str(tmp_path)) == ["MAL-2025-1"]
    assert deps.ossf_local_malicious("evilpkg", "1.0.0", str(tmp_path)) == []
    assert deps.ossf_local_malicious("goodpkg", "1.0.0", str(tmp_path)) == []


def test_run_offline_new_typosquat_dependency(cfg):
    c = Context(name="demo", old=PackageVersion("demo", "1.0", requires=["packaging"]),
                new=PackageVersion("demo", "1.1", requires=["packaging", "reqeusts>=2"]))
    deps.run(c, http=None, cfg=cfg, offline=True)
    assert c.indicators["D1"].triggered
    assert c.indicators["D2"].triggered
    assert c.indicators["D4"].evaluated is False
