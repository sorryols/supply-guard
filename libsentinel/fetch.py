"""Етап 1. Отримання та підготовка даних.

Завантаження архівів двох версій з PyPI (або з локальних файлів),
перевірка контрольних сум і безпечне розпакування БЕЗ виконання коду.
"""

from __future__ import annotations

import email.parser
import hashlib
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from .models import PackageVersion
from .net import Http, NetError, PyPI

MAX_TOTAL_SIZE = 500 * 1024 * 1024   # 500 МБ розпакованих даних
MAX_FILES = 20000


class UnsafeArchive(Exception):
    pass


def _safe_member_path(name: str) -> PurePosixPath:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or (p.parts and ":" in p.parts[0]):
        raise UnsafeArchive(f"Небезпечний шлях в архіві: {name}")
    return p


def safe_extract(archive: Path, dest: Path) -> None:
    """Розпакування з перевіркою шляхів, посилань і розміру (захист від path traversal)."""
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    name = archive.name.lower()
    if name.endswith((".whl", ".zip", ".egg")):
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            if len(infos) > MAX_FILES:
                raise UnsafeArchive("Забагато файлів в архіві")
            for info in infos:
                rel = _safe_member_path(info.filename)
                # символьні посилання в zip позначаються атрибутами Unix
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise UnsafeArchive(f"Символьне посилання в архіві: {info.filename}")
                total += info.file_size
                if total > MAX_TOTAL_SIZE:
                    raise UnsafeArchive("Перевищено допустимий розмір архіву")
                target = dest / rel
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
    elif name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        with tarfile.open(archive) as t:
            members = t.getmembers()
            if len(members) > MAX_FILES:
                raise UnsafeArchive("Забагато файлів в архіві")
            for m in members:
                rel = _safe_member_path(m.name)
                if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                    # посилання та пристрої не розпаковуються
                    continue
                total += m.size
                if total > MAX_TOTAL_SIZE:
                    raise UnsafeArchive("Перевищено допустимий розмір архіву")
                target = dest / rel
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                src = t.extractfile(m)
                if src is None:
                    continue
                with src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
    else:
        raise UnsafeArchive(f"Невідомий формат архіву: {archive.name}")


def _strip_single_root(d: Path) -> Path:
    """У sdist усі файли лежать у каталозі name-version/ — прибираємо його."""
    items = [p for p in d.iterdir()]
    if len(items) == 1 and items[0].is_dir():
        return items[0]
    return d


def archive_kind(path: Path) -> str:
    return "wheel" if path.name.lower().endswith(".whl") else "sdist"


def choose_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Вибір файлів версії: sdist і один wheel (перевага — py3-none-any)."""
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    chosen = []
    if sdists:
        chosen.append(sdists[0])
    if wheels:
        pure = [w for w in wheels if w["filename"].endswith("-none-any.whl")]
        linux = [w for w in wheels if "manylinux" in w["filename"] and "x86_64" in w["filename"]]
        chosen.append((pure or linux or wheels)[0])
    return chosen


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_requires(root: Path) -> List[str]:
    """Залежності з PKG-INFO (sdist) або METADATA (wheel)."""
    reqs: List[str] = []
    for meta in list(root.glob("sdist/PKG-INFO")) + list(root.glob("wheel/*.dist-info/METADATA")):
        msg = email.parser.Parser().parsestr(meta.read_text(encoding="utf-8", errors="replace"))
        reqs.extend(msg.get_all("Requires-Dist") or [])
    return sorted(set(reqs))


class Fetcher:
    def __init__(self, http: Http, workdir: Path, archive_cache: Path):
        self.http = http
        self.pypi = PyPI(http)
        self.workdir = workdir
        self.archive_cache = archive_cache

    def _download(self, name: str, version: str, f: Dict[str, Any]) -> Path:
        d = self.archive_cache / name.lower() / version
        d.mkdir(parents=True, exist_ok=True)
        dest = d / f["filename"]
        expected = (f.get("digests") or {}).get("sha256")
        if dest.exists() and (not expected or _sha256(dest) == expected):
            return dest
        self.http.download(f["url"], dest)
        if expected and _sha256(dest) != expected:
            dest.unlink(missing_ok=True)
            raise NetError(f"Контрольна сума {f['filename']} не збігається")
        return dest

    def prepare(self, name: str, version: Optional[str], tag: str,
                local: Optional[List[Path]] = None) -> Tuple[PackageVersion, Dict[str, Any]]:
        """Повертає розпаковану версію та її метадані PyPI (якщо є)."""
        pv = PackageVersion(name=name, version=version)
        root = self.workdir / tag
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        pv.root = root
        release: Dict[str, Any] = {}
        if version is None:
            return pv, release
        if local:
            archives = list(local)
        else:
            release = self.pypi.release(name, version)
            files = choose_files(release.get("urls", []))
            if not files:
                raise NetError(f"Для {name}=={version} немає файлів у PyPI")
            archives = [self._download(name, version, f) for f in files]
            times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
            pv.upload_time = min(times) if times else None
        kinds = []
        for a in archives:
            kind = archive_kind(a)
            target = root / kind
            tmp = root / f".{kind}_tmp"
            safe_extract(a, tmp)
            src = _strip_single_root(tmp) if kind == "sdist" else tmp
            shutil.move(str(src), str(target))
            shutil.rmtree(tmp, ignore_errors=True)
            kinds.append(kind)
        pv.archives = archives
        pv.kind = "+".join(sorted(set(kinds)))
        info = release.get("info") or {}
        pv.requires = info.get("requires_dist") or read_requires(root)
        return pv, release
