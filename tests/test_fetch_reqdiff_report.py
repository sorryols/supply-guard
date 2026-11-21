"""Блокові тести модулів fetch (безпечне розпакування), reqdiff і report."""

import io
import json
import tarfile
import zipfile

import pytest

from libsentinel.fetch import UnsafeArchive, choose_files, safe_extract
from libsentinel.report import render_console, to_sarif
from libsentinel.reqdiff import diff_requirements


def _tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def test_safe_extract_blocks_traversal(tmp_path):
    a = tmp_path / "evil.tar.gz"
    _tar(a, [("../../etc/evil", b"x")])
    with pytest.raises(UnsafeArchive):
        safe_extract(a, tmp_path / "out")


def test_safe_extract_blocks_absolute_zip(tmp_path):
    a = tmp_path / "evil.whl"
    with zipfile.ZipFile(a, "w") as z:
        z.writestr("/abs/path.py", "x")
    with pytest.raises(UnsafeArchive):
        safe_extract(a, tmp_path / "out")


def test_safe_extract_ok(tmp_path):
    a = tmp_path / "ok.tar.gz"
    _tar(a, [("pkg-1.0/setup.py", b"print(1)")])
    safe_extract(a, tmp_path / "out")
    assert (tmp_path / "out" / "pkg-1.0" / "setup.py").exists()


def test_choose_files_prefers_pure_wheel():
    files = [{"packagetype": "bdist_wheel", "filename": "a-1-cp312-cp312-manylinux_2_17_x86_64.whl"},
             {"packagetype": "bdist_wheel", "filename": "a-1-py3-none-any.whl"},
             {"packagetype": "sdist", "filename": "a-1.tar.gz"}]
    names = [f["filename"] for f in choose_files(files)]
    assert names == ["a-1.tar.gz", "a-1-py3-none-any.whl"]


def test_requirements_diff():
    old = "requests==2.31.0\nflask==3.0.3\n# comment\nnumpy>=1.0\n"
    new = "requests==2.32.3\nflask==3.0.3\nrich==13.8.0\nnumpy>=1.0\n"
    changes, skipped = diff_requirements(old, new)
    got = {(c.name, c.old, c.new) for c in changes}
    assert got == {("requests", "2.31.0", "2.32.3"), ("rich", None, "13.8.0")}
    assert skipped == []


RESULT = {"package": "demo", "old_version": "1.0", "new_version": "1.1", "decision": "block", "exit_code": 2,
          "triggered_count": 0, "author_trust": None, "danger_level": "критичний",
          "dynamic_analysis": True, "warnings": [], "notes": [], "authors": [], "vulnerabilities": [],
          "timings_seconds": {"total": 1.0},
          "indicators": [{"code": "K5", "name": "Читання файлів-приманок", "value": 1.0, "weight": 0,
                          "critical": True, "triggered": True, "evaluated": True, "note": None,
                          "evidence": [{"message": "Прочитано ~/.ssh/id_rsa"}]}]}


def test_console_report():
    text = render_console(RESULT, color=False)
    assert "ЗАБЛОКУВАТИ" in text and "K5" in text


def test_sarif_report():
    s = to_sarif([RESULT], "requirements.txt", {"demo": 3})
    res = s["runs"][0]["results"]
    assert s["version"] == "2.1.0" and len(res) == 1
    assert res[0]["level"] == "error"
    assert res[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    json.dumps(s)
