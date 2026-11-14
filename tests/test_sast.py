"""Блокові тести модуля sast (S1–S6, К1–К3)."""

from pathlib import Path

import pytest

from libsentinel import sast
from libsentinel.fetch import Fetcher
from libsentinel.models import Context
from libsentinel.sast import analyze_source, shannon_entropy


def kinds(src):
    return analyze_source(src).kinds()


def test_network_call_detected_with_alias():
    f = analyze_source("import urllib.request as u\nu.urlopen('http://x')\n")
    assert "network" in f.kinds()
    assert f.by_kind("network")[0].import_time is True


def test_network_inside_function_not_import_time():
    f = analyze_source("import requests\n\ndef get():\n    return requests.get('http://x')\n")
    assert f.by_kind("network")[0].import_time is False


def test_main_guard_not_import_time():
    f = analyze_source("import os\nif __name__ == '__main__':\n    os.system('ls')\n")
    assert f.by_kind("process")[0].import_time is False


def test_process_and_dynexec():
    k = kinds("import subprocess\nsubprocess.run(['ls'])\neval('1+1')\n")
    assert {"process", "dynexec"} <= k


def test_decode_exec_k1():
    f = analyze_source("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")
    assert f.decode_exec, "К1 має спрацювати для exec(b64decode(...))"


def test_decode_exec_via_variable():
    f = analyze_source("from base64 import b64decode as d\npayload = d('eA==')\nexec(payload)\n")
    assert f.decode_exec


def test_decode_exec_dynamic_import():
    f = analyze_source("exec(__import__('base64').b64decode('eA=='))\n")
    assert f.decode_exec


def test_sensitive_env_and_path():
    k = kinds("import os\nt = os.environ.get('GITHUB_TOKEN')\nopen(os.path.expanduser('~/.aws/credentials'))\n")
    assert "sensitive:env:GITHUB_TOKEN" in k
    assert "sensitive:path:.aws" in k


def test_non_sensitive_env_ignored():
    assert not any(x.startswith("sensitive") for x in kinds("import os\nos.environ.get('HOME')\n"))


def test_syntax_error_handled():
    f = analyze_source("def broken(:\n    pass\n" + "A" * 50)
    assert f.parse_error


def test_entropy_values():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def _ctx(tmp_path, synthetic, new_version):
    from libsentinel.cache import Cache
    from libsentinel.config import load_config
    from libsentinel.net import Http
    cfg = load_config()
    fetcher = Fetcher(Http(cfg, Cache(enabled=False)), tmp_path, tmp_path / "arch")
    old, _ = fetcher.prepare("libsentinel-demo", "1.0.0", "old", [synthetic / "libsentinel-demo-1.0.0.tar.gz"])
    new, _ = fetcher.prepare("libsentinel-demo", new_version, "new",
                             [synthetic / f"libsentinel-demo-{new_version}.tar.gz"])
    ctx = Context(name="libsentinel-demo", old=old, new=new)
    sast.run(ctx, cfg)
    return ctx


def triggered(ctx):
    return {c for c, i in ctx.indicators.items() if i.triggered}


def test_benign_bugfix_no_findings(tmp_path, synthetic):
    t = triggered(_ctx(tmp_path, synthetic, "1.0.1"))
    assert not ({"S2", "S3", "S4", "K1", "K2", "K3"} & t)


def test_network_in_function_not_s3(tmp_path, synthetic):
    t = triggered(_ctx(tmp_path, synthetic, "1.0.2"))
    assert "S3" not in t and "K2" not in t


def test_exfil_setup_k2(tmp_path, synthetic):
    t = triggered(_ctx(tmp_path, synthetic, "1.1.0"))
    assert {"K2", "S1", "S4"} <= t


def test_b64_exec_k1(tmp_path, synthetic):
    assert "K1" in triggered(_ctx(tmp_path, synthetic, "1.1.1"))


def test_pth_k3(tmp_path, synthetic):
    assert "K3" in triggered(_ctx(tmp_path, synthetic, "1.1.2"))


def test_import_time_exfil(tmp_path, synthetic):
    t = triggered(_ctx(tmp_path, synthetic, "1.1.6"))
    assert {"S3", "S4", "K2"} <= t


def test_s6_files_absent_in_repo(tmp_path, synthetic):
    from libsentinel.config import load_config
    from libsentinel.cache import Cache
    from libsentinel.net import Http
    cfg = load_config()
    fetcher = Fetcher(Http(cfg, Cache(enabled=False)), tmp_path, tmp_path / "arch")
    old, _ = fetcher.prepare("libsentinel-demo", "1.0.0", "old", [synthetic / "libsentinel-demo-1.0.0.tar.gz"])
    new, _ = fetcher.prepare("libsentinel-demo", "1.0.5", "new", [synthetic / "libsentinel-demo-1.0.5.tar.gz"])
    ctx = Context(name="libsentinel-demo", old=old, new=new)
    # репозиторій містить усе, крім нового модуля text.py
    repo = {"setup.py", "lsdemo/__init__.py", "lsdemo/utils.py"}
    sast.run(ctx, cfg, lambda rel: rel in repo or not rel.endswith(".py"))
    assert ctx.indicators["S6"].triggered
    assert ctx.unmatched_lines > 0
