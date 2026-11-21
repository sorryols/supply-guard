"""Інтеграційні тести повного циклу аналізу на синтетичних зразках.

Тести з динамічним аналізом виконуються лише за наявності Docker і образу пісочниці
(libsentinel sandbox-build); інакше вони пропускаються.
"""

import pytest

from libsentinel.analyzer import Analyzer
from libsentinel.config import load_config
from libsentinel.dast import docker_available, image_exists


def run(synthetic, version, dast="never"):
    cfg = load_config()
    an = Analyzer(cfg, use_cache=False)
    return an.analyze("libsentinel-demo", "1.0.0", version, dast_mode=dast, offline=True,
                      old_archives=[synthetic / "libsentinel-demo-1.0.0.tar.gz"],
                      new_archives=[synthetic / f"libsentinel-demo-{version}.tar.gz"], force=True)


@pytest.mark.parametrize("version,decision", [
    ("1.0.1", "allow"),   # безпечне виправлення
    ("1.0.2", "allow"),   # мережа всередині функції
    ("1.1.0", "block"),   # К2: облікові дані + мережа в setup.py
    ("1.1.1", "block"),   # К1: exec(b64decode(...))
    ("1.1.2", "block"),   # К3: новий .pth
    ("1.1.6", "block"),   # К2 під час імпорту
])
def test_static_pipeline(synthetic, version, decision):
    r = run(synthetic, version)
    if version in ("1.0.1", "1.0.2"):
        # без динамічного аналізу зміна setup.py лишається підозрою S1
        assert r["decision"] in ("allow", "warn")
        trig = {i["code"] for i in r["indicators"] if i["evaluated"] and i["value"] > 0}
        assert trig <= {"S1"}, trig
    else:
        assert r["decision"] == decision, r


def _docker_ready():
    ok, _ = docker_available()
    return ok and image_exists(load_config()["dast"]["image"])


@pytest.mark.skipif(not _docker_ready(), reason="Docker або образ пісочниці недоступні")
@pytest.mark.parametrize("version,code", [("1.1.3", "K5"), ("1.1.4", "B2"), ("1.1.7", "B3")])
def test_dynamic_pipeline(synthetic, version, code):
    # примусовий динамічний аналіз: пісочниця має виявити відповідну поведінку
    r = run(synthetic, version, dast="always")
    trig = {i["code"] for i in r["indicators"] if i["evaluated"] and i["value"] > 0}
    assert r["dynamic_analysis"] is True
    assert code in trig
    assert r["decision"] in ("block", "warn")


@pytest.mark.skipif(not _docker_ready(), reason="Docker або образ пісочниці недоступні")
@pytest.mark.parametrize("version", ["1.0.1", "1.1.3", "1.1.4", "1.1.7"])
def test_dast_auto_follows_rule(synthetic, version):
    # режим auto: динамічний аналіз запускається лише при n >= m (типово m = 2)
    r = run(synthetic, version, dast="auto")
    if any(i["critical"] and i["evaluated"] and i["value"] > 0 for i in r["indicators"]
           if i["code"] in ("K1", "K2", "K3", "K4")):
        return  # дострокове блокування без DAST
    n_before = len(r.get("meta", {}).get("triggered_before_dast", []))
    assert r["dynamic_analysis"] is (n_before >= 2), (n_before, r["dynamic_analysis"])


@pytest.mark.skipif(not _docker_ready(), reason="Docker або образ пісочниці недоступні")
def test_dynamic_clears_s1_for_benign(synthetic):
    # чистий динамічний аналіз знімає підозру S1 і оновлення допускається
    r = run(synthetic, "1.0.1", dast="always")
    assert r["dynamic_analysis"] is True
    assert r["decision"] == "allow"
