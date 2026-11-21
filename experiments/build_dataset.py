"""Підготовка вибірки для експериментального дослідження LibSentinel.

Джерела:
  • шкідливі бібліотеки — відкритий датасет DataDog «Malicious Software Packages Dataset»
    (https://github.com/DataDog/malicious-software-packages-dataset, ліцензія Apache-2.0):
      - compromised_lib  — скомпрометовані версії легітимних бібліотек (сценарій «оновлення»);
      - malicious_intent — бібліотеки, створені зловмисниками (сценарій «нова залежність»);
  • безпечні бібліотеки — реальні оновлення популярних бібліотек PyPI (сценарій «оновлення»)
    і популярні бібліотеки, що додаються як нові залежності.

УВАГА: архіви датасету містять справжнє шкідливе ПЗ. Скрипт НЕ виконує їх код — лише розпаковує
і перепаковує у формат sdist/wheel, щоб засіб міг їх проаналізувати. Запускайте експеримент
із динамічним аналізом лише у віртуальній машині.

Приклад:
  git clone --depth 1 --filter=blob:none --sparse \
      https://github.com/DataDog/malicious-software-packages-dataset.git ~/dd
  git -C ~/dd sparse-checkout set samples/pypi
  python experiments/build_dataset.py --dd ~/dd --intent 100 --benign-new 50
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from packaging.version import InvalidVersion, Version

HERE = Path(__file__).resolve().parent
PASSWORD = b"infected"

# Додаткові реальні безпечні оновлення (доповнюють benign_real.csv до 50 пар)
EXTRA_BENIGN_UPDATES = [
    ("pyparsing", "3.1.2", "3.1.4"), ("anyio", "4.4.0", "4.6.0"), ("httpx", "0.27.0", "0.27.2"),
    ("tzdata", "2024.1", "2024.2"), ("more-itertools", "10.3.0", "10.5.0"), ("zipp", "3.19.2", "3.20.2"),
    ("tabulate", "0.8.10", "0.9.0"), ("soupsieve", "2.5", "2.6"), ("beautifulsoup4", "4.12.2", "4.12.3"),
    ("sniffio", "1.3.0", "1.3.1"), ("decorator", "5.1.0", "5.1.1"), ("termcolor", "2.4.0", "2.5.0"),
    ("docutils", "0.20.1", "0.21.2"), ("markdown", "3.6", "3.7"), ("jmespath", "1.0.0", "1.0.1"),
    ("isodate", "0.6.1", "0.7.2"), ("toml", "0.10.1", "0.10.2"), ("distlib", "0.3.8", "0.3.9"),
    ("pyasn1", "0.6.0", "0.6.1"), ("h11", "0.13.0", "0.14.0"),
]

# Популярні бібліотеки на чистому Python, які додаються як нові залежності
BENIGN_NEW = [
    "requests", "urllib3", "idna", "certifi", "six", "python-dateutil", "click", "jinja2", "attrs",
    "packaging", "pyparsing", "charset-normalizer", "typing-extensions", "filelock", "platformdirs",
    "tomli", "colorama", "tqdm", "pluggy", "iniconfig", "decorator", "docutils", "pygments", "rich",
    "markdown-it-py", "mdurl", "itsdangerous", "werkzeug", "flask", "toml", "jmespath", "soupsieve",
    "beautifulsoup4", "sniffio", "anyio", "h11", "httpcore", "httpx", "pytz", "tzdata", "more-itertools",
    "zipp", "importlib-metadata", "distlib", "cachetools", "pyasn1", "rsa", "oauthlib", "tabulate",
    "termcolor", "isodate", "chardet", "docopt", "markdown", "sqlparse", "pycparser", "idna-ssl",
]


def pypi_releases(name: str) -> Dict[str, list]:
    r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=30)
    if r.status_code != 200:
        return {}
    return r.json().get("releases", {})


def latest_version(name: str) -> Optional[str]:
    r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=30)
    return r.json()["info"]["version"] if r.status_code == 200 else None


def previous_clean(name: str, bad: str, bad_set: set) -> Optional[str]:
    """Найбільша опублікована версія, меншa за скомпрометовану і не позначена як шкідлива."""
    try:
        vbad = Version(bad)
    except InvalidVersion:
        return None
    cands = []
    for v, files in pypi_releases(name).items():
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if files and pv < vbad and v not in bad_set and not pv.is_prerelease:
            cands.append(pv)
    return str(max(cands)) if cands else None


def extract(zpath: Path, dest: Path) -> None:
    try:
        with zipfile.ZipFile(zpath) as z:
            z.extractall(dest, pwd=PASSWORD)
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
        subprocess.run(["unzip", "-q", "-o", "-P", "infected", str(zpath), "-d", str(dest)], check=True)


def _flatten(rel: Path) -> Path:
    """У частині архівів датасету кожен файл лежить у каталозі з тим самим ім'ям: a/b.py/a/b.py."""
    parts = rel.parts
    for i, p in enumerate(parts[:-1]):
        if p == parts[-1]:
            return Path(*parts[i + 1:])
    return rel


def find_roots(base: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """Корінь вихідного дистрибутива (setup.py / pyproject.toml / PKG-INFO) і корінь wheel (*.dist-info)."""
    sdist = wheel = None
    for p in sorted(base.rglob("*"), key=lambda x: len(x.parts)):
        if sdist is None and p.is_file() and p.name in ("setup.py", "pyproject.toml", "PKG-INFO") \
                and not any(part.endswith(".dist-info") for part in p.parts):
            sdist = p.parent
        if wheel is None and p.is_dir() and p.name.endswith(".dist-info"):
            wheel = p.parent
    return sdist, wheel


def pack_sdist(root: Path, name: str, version: str, out: Path) -> Path:
    path = out / f"{name}-{version}.tar.gz"
    top = f"{name}-{version}"
    with tarfile.open(path, "w:gz") as tar:
        for f in sorted(root.rglob("*")):
            if f.is_file() and not f.is_symlink():
                tar.add(f, arcname=f"{top}/{_flatten(f.relative_to(root)).as_posix()}", recursive=False)
    return path


def pack_wheel(root: Path, name: str, version: str, out: Path) -> Path:
    path = out / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        seen = set()
        for f in sorted(root.rglob("*")):
            if f.is_file() and not f.is_symlink() and not f.name.startswith("package_info-"):
                arc = _flatten(f.relative_to(root)).as_posix()
                if arc not in seen:
                    seen.add(arc)
                    z.write(f, arc)
    return path


def prepare_sample(zpath: Path, name: str, version: str, out: Path) -> List[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        extract(zpath, t)
        sroot, wroot = find_roots(t)
        res = []
        if sroot is not None:
            res.append(pack_sdist(sroot, name, version, out))
        if wroot is not None and wroot != sroot:
            res.append(pack_wheel(wroot, name, version, out))
        return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Підготовка вибірки для експерименту")
    ap.add_argument("--dd", required=True, help="Каталог клону DataDog malicious-software-packages-dataset")
    ap.add_argument("--out", default=str(HERE / "dataset"))
    ap.add_argument("--intent", type=int, default=100, help="Скільки зразків malicious_intent узяти (випадково)")
    ap.add_argument("--benign-new", type=int, default=50, help="Скільки безпечних нових залежностей")
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()

    out = Path(a.out)
    arch = out / "archives"
    arch.mkdir(parents=True, exist_ok=True)
    base = Path(a.dd).expanduser() / "samples" / "pypi"
    if not base.is_dir():
        print(f"Не знайдено {base}. Виконайте sparse-checkout samples/pypi", file=sys.stderr)
        return 1
    rows_mal, rows_ben_upd, rows_ben_new = [], [], []

    # 1. Скомпрометовані версії легітимних бібліотек — сценарій «оновлення»
    comp = sorted(base.glob("compromised_lib/*/*/*.zip"))
    bad_by_name: Dict[str, set] = {}
    for z in comp:
        bad_by_name.setdefault(z.parts[-3], set()).add(z.parts[-2])
    print(f"Скомпрометовані версії: {len(comp)}")
    for z in comp:
        name, ver = z.parts[-3], z.parts[-2]
        old = previous_clean(name, ver, bad_by_name[name])
        files = prepare_sample(z, name, ver, arch)
        if not files:
            print(f"  пропущено {name} {ver}: не знайдено вмісту бібліотеки")
            continue
        rows_mal.append({"name": name, "old": old or "", "new": ver, "label": 1,
                         "old_archive": "", "new_archive": ";".join(str(f) for f in files),
                         "kind": "compromised-update" if old else "compromised-new"})
        print(f"  {name} {old or '—'} → {ver}: {', '.join(f.name for f in files)}")

    # 2. Бібліотеки, створені зловмисниками — сценарій «нова залежність»
    intent = sorted(base.glob("malicious_intent/*/*/*.zip"))
    random.Random(a.seed).shuffle(intent)
    taken, names = 0, set()
    for z in intent:
        if taken >= a.intent:
            break
        name, ver = z.parts[-3], z.parts[-2]
        if name in names:
            continue
        try:
            files = prepare_sample(z, name, ver, arch)
        except Exception as e:  # noqa: BLE001
            print(f"  пропущено {name} {ver}: {e}")
            continue
        if not files:
            continue
        names.add(name)
        taken += 1
        rows_mal.append({"name": name, "old": "", "new": ver, "label": 1, "old_archive": "",
                         "new_archive": ";".join(str(f) for f in files), "kind": "malicious-new"})
    print(f"Бібліотеки зловмисників (нові залежності): {taken}")

    # 3. Безпечні оновлення: benign_real.csv + додаткові пари, перевірені в PyPI
    for name, old, new in EXTRA_BENIGN_UPDATES:
        rel = pypi_releases(name)
        if rel.get(old) and rel.get(new):
            rows_ben_upd.append({"name": name, "old": old, "new": new, "label": 0, "old_archive": "",
                                 "new_archive": "", "kind": "benign-update"})
        else:
            print(f"  безпечне оновлення {name} {old}→{new} відсутнє в PyPI — пропущено")

    # 4. Безпечні нові залежності — останні версії популярних бібліотек
    for name in BENIGN_NEW[:a.benign_new]:
        v = latest_version(name)
        if v:
            rows_ben_new.append({"name": name, "old": "", "new": v, "label": 0, "old_archive": "",
                                 "new_archive": "", "kind": "benign-new"})

    fields = ["name", "old", "new", "label", "old_archive", "new_archive", "kind"]
    for fname, rows in (("malicious.csv", rows_mal), ("benign_updates_extra.csv", rows_ben_upd),
                        ("benign_new.csv", rows_ben_new)):
        with open(out / fname, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print(f"{out / fname}: {len(rows)} записів")
    print("\nЗапуск експерименту:\n  python experiments/run_experiment.py experiments/benign_real.csv "
          f"{out}/benign_updates_extra.csv {out}/benign_new.csv {out}/malicious.csv --out experiments/results-dataset")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
