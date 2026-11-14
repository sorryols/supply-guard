"""Етап 4. Аналіз залежностей (індикатори D1–D4, К4, перелік вразливостей V).

D1 — нова пряма залежність;
D2 — схожість назви на популярну бібліотеку (відстань Левенштейна);
D3 — нова або малоактивна залежність;
D4 — відомі вразливості (OSV);
К4 — бібліотека або залежність у базі шкідливих пакетів (OSV MAL-*, OpenSSF Malicious Packages).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .avt_meta import owners_from_project, release_times
from .cache import default_cache_dir
from .config import DATA_DIR
from .models import Context, Vulnerability
from .net import Http, NetError, OSV, PyPI


def levenshtein(a: str, b: str) -> int:
    """Відстань Левенштейна — мінімальна кількість вставок, видалень і замін."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def load_top_packages() -> List[str]:
    """Список популярних бібліотек PyPI (оновлюється командою update-data)."""
    cached = default_cache_dir() / "top_pypi.txt"
    path = cached if cached.exists() else DATA_DIR / "top_pypi.txt"
    names = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            names.append(canonicalize_name(ln))
    return names


def similar_popular(name: str, top: Iterable[str], max_dist: int) -> Optional[str]:
    n = canonicalize_name(name)
    top = list(top)
    if n in top:
        return None
    best = None
    for t in top:
        if abs(len(t) - len(n)) > max_dist or len(t) < 4:
            continue
        d = levenshtein(n, t)
        if 1 <= d <= max_dist and (best is None or d < best[1]):
            best = (t, d)
    # нормалізовані варіанти: python-, py-, -python, цифри замість літер
    if best is None:
        for pattern in (r"^(python|py)[-_]", r"[-_](python|py|lib|dev)$"):
            stripped = re.sub(pattern, "", n)
            if stripped != n and stripped in top:
                best = (stripped, 0)
                break
    return best[0] if best else None


def parse_requires(reqs: List[str]) -> Dict[str, str]:
    """Пряма (не extra) залежність → специфікатор версій."""
    out: Dict[str, str] = {}
    for r in reqs or []:
        try:
            req = Requirement(r)
        except InvalidRequirement:
            continue
        if req.marker is not None and "extra" in str(req.marker):
            continue
        out[canonicalize_name(req.name)] = str(req.specifier)
    return out


def _latest_matching(project: Dict[str, Any], spec: str) -> Optional[str]:
    try:
        ss = SpecifierSet(spec or "")
    except Exception:
        ss = SpecifierSet("")
    versions = []
    for v in (project.get("releases") or {}).keys():
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if not pv.is_prerelease and pv in ss:
            versions.append(pv)
    return str(max(versions)) if versions else (project.get("info") or {}).get("version")


def _osv_to_vuln(v: Dict[str, Any], package: str, version: Optional[str]) -> Vulnerability:
    sev = (v.get("database_specific") or {}).get("severity") or ""
    if not sev and v.get("severity"):
        sev = v["severity"][0].get("score", "")
    fixed = None
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed = ev["fixed"]
    aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
    vid = v.get("id", "?") + (f" ({', '.join(aliases)})" if aliases else "")
    return Vulnerability(id=vid, package=package, version=version, summary=(v.get("summary") or v.get("details", ""))[:200],
                         severity=str(sev), fixed=fixed, malicious=v.get("id", "").startswith("MAL-"))


def _ossf_base(ossf_dir: str) -> Path:
    d = Path(ossf_dir).expanduser() if ossf_dir else default_cache_dir() / "malicious-packages"
    return d / "osv" / "malicious" / "pypi"


def _affects(entry: Dict[str, Any], version: Optional[str]) -> bool:
    """Чи стосується запис OSV вказаної версії (None — будь-якої)."""
    for aff in entry.get("affected", []):
        versions = aff.get("versions") or []
        if version is None or version in versions:
            return True
        for rng in aff.get("ranges", []):
            events = rng.get("events", [])
            introduced = [e["introduced"] for e in events if "introduced" in e]
            fixed = [e["fixed"] for e in events if "fixed" in e]
            if "0" in introduced and not fixed:
                return True
    return False


def ossf_local_malicious(name: str, version: Optional[str], ossf_dir: str) -> List[str]:
    """Пошук у локальній копії репозиторію ossf/malicious-packages."""
    import json
    base = _ossf_base(ossf_dir)
    if not base.exists():
        return []
    n = canonicalize_name(name)
    cand = base / name
    dirs = [cand] if cand.is_dir() else [p for p in base.iterdir() if p.is_dir() and canonicalize_name(p.name) == n]
    found = []
    for d in dirs:
        for f in d.glob("*.json"):
            try:
                entry = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if _affects(entry, version):
                found.append(entry.get("id", f.stem))
    return found


def run(ctx: Context, http: Http, cfg: Dict[str, Any], offline: bool = False) -> None:
    w = cfg["weights"]
    dcfg = cfg["deps"]
    D1, D2, D3, D4 = (ctx.ind(c, w[c]) for c in ("D1", "D2", "D3", "D4"))
    K4 = ctx.ind("K4")
    pypi, osv = PyPI(http), OSV(http)
    top = load_top_packages()

    old = parse_requires(ctx.old.requires) if not ctx.is_new_dependency else {}
    new = parse_requires(ctx.new.requires)
    added = sorted(set(new) - set(old)) if not ctx.is_new_dependency else []
    ctx.meta["dependencies"] = {"old": old, "new": new, "added": added}

    # D2 для самої бібліотеки, якщо вона додається вперше
    if ctx.is_new_dependency:
        sim = similar_popular(ctx.name, top, dcfg["typo_max_distance"])
        if sim:
            D2.value = 1.0
            D2.add(f"Назва бібліотеки «{ctx.name}» схожа на популярну «{sim}»")
        D1.note = "Нова залежність проєкту: аналізується вся бібліотека"

    now = datetime.now(timezone.utc)
    for dep in added:
        D1.value = 1.0
        D1.add(f"Нова пряма залежність: {dep}{new[dep]}")
        sim = similar_popular(dep, top, dcfg["typo_max_distance"])
        if sim:
            D2.value = 1.0
            D2.add(f"Назва залежності «{dep}» схожа на популярну бібліотеку «{sim}»")
        if offline:
            continue
        try:
            proj = pypi.exists(dep)
        except NetError as e:
            ctx.notes.append(f"Не вдалося перевірити залежність {dep}: {e}")
            continue
        if proj is None:
            D3.value = 1.0
            D3.add(f"Залежність {dep} не існує в PyPI (можлива підміна залежностей)")
            continue
        rel = release_times(proj)
        first = rel[0][1] if rel else None
        owners = owners_from_project(proj)
        if first and (now - first).days < dcfg["new_package_days"]:
            D3.value = 1.0
            D3.add(f"Перший реліз залежності {dep} опубліковано {(now - first).days} днів тому")
        elif len(rel) <= dcfg["small_release_count"] and len(owners) <= 1:
            D3.value = 1.0
            D3.add(f"Залежність {dep} малоактивна: {len(rel)} релізів, власників: {len(owners) or 'невідомо'}")

    # Версії залежностей, що будуть встановлені (остання відповідна специфікатору)
    dep_versions: Dict[str, Optional[str]] = {}
    if not offline:
        for dep, spec in new.items():
            try:
                proj = pypi.exists(dep)
            except NetError:
                proj = None
            dep_versions[dep] = _latest_matching(proj, spec) if proj else None
    ctx.meta["dependency_versions"] = dep_versions

    # Відомі вразливості та шкідливі пакети (OSV, OpenSSF Malicious Packages)
    if offline:
        D4.evaluated = False
        D4.note = "Локальний режим: OSV не перевірявся"
    else:
        targets = [(ctx.name, ctx.new.version)] + [(d, v) for d, v in sorted(dep_versions.items()) if v]
        osv_ok = True
        for name, version in targets:
            try:
                vulns = osv.query(name, version)
            except NetError as e:
                osv_ok = False
                ctx.notes.append(f"OSV недоступний: {e}")
                break
            for v in vulns:
                ctx.vulnerabilities.append(_osv_to_vuln(v, name, version))
        if not osv_ok:
            D4.evaluated = False
            D4.note = "OSV недоступний"
        for v in ctx.vulnerabilities:
            if v.malicious:
                K4.value = 1.0
                K4.add(f"{v.package} {v.version or ''}: запис {v.id} у базі шкідливих пакетів OpenSSF/OSV")
            else:
                D4.value = 1.0
                D4.add((f"{v.package} {v.version or ''}: {v.id} {v.severity} "
                        f"{('виправлено у ' + v.fixed) if v.fixed else ''}").strip())
    # Локальна копія OpenSSF Malicious Packages
    local_targets = [(ctx.name, ctx.new.version)] + [(d, dep_versions.get(d)) for d in sorted(new)]
    for name, version in local_targets:
        ids = ossf_local_malicious(name, version, dcfg.get("ossf_dir", ""))
        if ids:
            K4.value = 1.0
            K4.add(f"{name} {version or ''}: {', '.join(ids[:3])} у локальній копії OpenSSF Malicious Packages")
