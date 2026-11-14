"""Етап 2. Аналіз авторів і метаданих (індикатори A1–A5, ступінь довіри τ).

A1 — зміна видавця або зникнення атестації (PEP 740, PyPI Integrity API);
A2 — новий власник або супровідник у реєстрі;
A3 — низька довіра до авторів змін, x = 1 − τ (формула 2.3);
A4 — аномальна періодичність релізів;
A5 — відсутність тегу версії в репозиторії.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .cache import Cache
from .models import Author, Context
from .net import GitHub, Http, NetError, PyPI

MAINTAINER_ASSOC = {"OWNER", "MEMBER", "COLLABORATOR"}
NEWCOMER_ASSOC = {"FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER"}

# Файли, що генеруються під час збирання і закономірно відсутні в репозиторії
GENERATED = {"PKG-INFO", "setup.cfg", "_version.py", "version.py", "_version.pyi"}
CODE_EXT = (".py", ".pth", ".sh", ".js", ".pyx")


def _parse_time(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------- A1
def _publishers(pypi: PyPI, name: str, version: str, release: Dict[str, Any]) -> Tuple[bool, Set[str]]:
    """Повертає (чи є атестації, множина видавців repository/workflow)."""
    pubs: Set[str] = set()
    any_att = False
    for f in release.get("urls", []):
        prov = pypi.provenance(name, version, f["filename"])
        if not prov:
            continue
        for bundle in prov.get("attestation_bundles", []):
            any_att = True
            p = bundle.get("publisher") or {}
            pubs.add(f"{p.get('kind', '?')}:{p.get('repository', '?')}:{p.get('workflow', '?')}")
    return any_att, pubs


def check_publisher(ctx: Context, pypi: PyPI, old_rel: Dict[str, Any], new_rel: Dict[str, Any], w: float) -> None:
    ind = ctx.ind("A1", w)
    if ctx.is_new_dependency or not old_rel or not new_rel:
        ind.evaluated = bool(new_rel) and not ctx.is_new_dependency
        ind.note = "Порівняння видавців можливе лише для двох версій з PyPI"
        return
    try:
        old_att, old_pubs = _publishers(pypi, ctx.name, ctx.old.version, old_rel)
        new_att, new_pubs = _publishers(pypi, ctx.name, ctx.new.version, new_rel)
    except NetError as e:
        ind.evaluated = False
        ind.note = f"Integrity API недоступний: {e}"
        return
    ctx.meta["publishers"] = {"old": sorted(old_pubs), "new": sorted(new_pubs)}
    if old_att and not new_att:
        ind.value = 1.0
        ind.add(f"Версія {ctx.old.version} мала атестацію походження, версія {ctx.new.version} — ні")
    elif old_att and new_att and old_pubs != new_pubs:
        ind.value = 1.0
        ind.add(f"Змінився видавець: {sorted(old_pubs)} → {sorted(new_pubs)}")
    elif not old_att and not new_att:
        ind.note = "Обидві версії опубліковано без атестацій"


# ---------------------------------------------------------------- A2
def owners_from_project(project: Dict[str, Any]) -> List[str]:
    roles = ((project.get("ownership") or {}).get("roles")) or []
    return sorted({r.get("user", "") for r in roles if r.get("user")})


def check_owners(ctx: Context, cache: Cache, project: Dict[str, Any], w: float) -> None:
    ind = ctx.ind("A2", w)
    owners = owners_from_project(project)
    ctx.meta["owners"] = owners
    history = cache.owners_history(ctx.name)
    if owners:
        cache.add_owners(ctx.name, owners)
    if not owners:
        ind.evaluated = False
        ind.note = "PyPI не повернув поле ownership"
        return
    if not history:
        ind.evaluated = False
        ind.note = "Перший знімок складу власників збережено; A2 оцінюється з наступного запуску"
        return
    previous = set(history[-1][1])
    added = sorted(set(owners) - previous)
    if added:
        ind.value = 1.0
        ind.add(f"Нові власники/супровідники в PyPI: {', '.join(added)} (раніше: {', '.join(sorted(previous))})")


# ---------------------------------------------------------------- A4
def release_times(project: Dict[str, Any]) -> List[Tuple[str, datetime]]:
    out = []
    for ver, files in (project.get("releases") or {}).items():
        times = [_parse_time(f.get("upload_time_iso_8601")) for f in files]
        times = [t for t in times if t]
        if times:
            out.append((ver, min(times)))
    return sorted(out, key=lambda x: x[1])


def check_periodicity(ctx: Context, project: Dict[str, Any], cfg: Dict[str, Any], w: float) -> None:
    ind = ctx.ind("A4", w)
    mcfg = cfg["metadata"]
    rel = release_times(project)
    idx = next((i for i, (v, _) in enumerate(rel) if v == ctx.new.version), None)
    if idx is None:
        ind.evaluated = False
        ind.note = "Немає дати публікації нової версії"
        return
    t_new = rel[idx][1]
    history = rel[:idx]
    if not history:
        ind.note = "Перший реліз бібліотеки"
        return
    pause = t_new - history[-1][1]
    intervals = [(b[1] - a[1]).total_seconds() / 86400 for a, b in zip(history, history[1:])]
    median = statistics.median(intervals) if intervals else 0.0
    pause_days = pause.total_seconds() / 86400
    if pause_days > mcfg["long_pause_days"] and pause_days > mcfg["pause_median_factor"] * max(median, 1e-9):
        ind.value = 1.0
        ind.add(f"Реліз після перерви {pause_days:.0f} днів (медіанний інтервал {median:.0f} днів, "
                f"попередня версія {history[-1][0]})")
    window = timedelta(hours=mcfg["burst_window_hours"])
    burst = [v for v, t in rel[: idx + 1] if t_new - window <= t <= t_new]
    if len(burst) >= mcfg["burst_count"]:
        # чи траплялися такі серії раніше
        hist_max = 0
        for i, (_, t0) in enumerate(history):
            hist_max = max(hist_max, sum(1 for _, t in history if t0 <= t <= t0 + window))
        if hist_max < mcfg["burst_count"]:
            ind.value = 1.0
            ind.add(f"За {mcfg['burst_window_hours']} год опубліковано {len(burst)} версій: {', '.join(burst)}")


# ---------------------------------------------------------------- A5, A3
def find_repo(project: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    info = project.get("info") or {}
    urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page"), info.get("download_url")]
    for key_pref in ("source", "repository", "code", "github", "homepage"):
        for k, v in (info.get("project_urls") or {}).items():
            if key_pref in k.lower() and GitHub.parse_repo(v):
                return GitHub.parse_repo(v)
    for u in urls:
        r = GitHub.parse_repo(u)
        if r:
            return r
    return None


def tag_candidates(name: str, version: str) -> List[str]:
    n = name.lower()
    return [version, f"v{version}", f"{n}-{version}", f"{n}-v{version}", f"release-{version}",
            f"{n.replace('-', '_')}-{version}", f"V{version}"]


def find_tag(gh: GitHub, owner: str, repo: str, name: str, version: str) -> Optional[str]:
    for cand in tag_candidates(name, version):
        d = gh.get(f"/repos/{owner}/{repo}/git/ref/tags/{cand}")
        if isinstance(d, dict) and not d.get("__404__"):
            return cand
    return None


def check_repository(ctx: Context, gh: GitHub, project: Dict[str, Any], cfg: Dict[str, Any], w5: float) -> None:
    ind = ctx.ind("A5", w5)
    repo = find_repo(project)
    ctx.repo["slug"] = f"{repo[0]}/{repo[1]}" if repo else None
    if not repo:
        ind.evaluated = False
        ind.note = "У метаданих немає посилання на репозиторій GitHub"
        ctx.repo["status"] = "missing"
        return
    owner, name = repo
    try:
        info = gh.get(f"/repos/{owner}/{name}")
        if info.get("__404__"):
            ind.evaluated = False
            ind.note = f"Репозиторій {owner}/{name} не знайдено"
            ctx.repo["status"] = "missing"
            return
        new_tag = find_tag(gh, owner, name, ctx.name, ctx.new.version)
        old_tag = None if ctx.is_new_dependency else find_tag(gh, owner, name, ctx.name, ctx.old.version)
    except NetError as e:
        ind.evaluated = False
        ind.note = f"GitHub API недоступний: {e}"
        ctx.repo["status"] = "unavailable"
        return
    ctx.repo.update({"status": "ok", "owner": owner, "name": name, "new_tag": new_tag, "old_tag": old_tag,
                     "default_branch": info.get("default_branch")})
    if not new_tag:
        ind.value = 1.0
        ind.add(f"У репозиторії {owner}/{name} немає тегу для версії {ctx.new.version} "
                f"(перевірено: {', '.join(tag_candidates(ctx.name, ctx.new.version))})")
    # дерево файлів на теґу — для індикатора S6
    if new_tag:
        try:
            tree = gh.get(f"/repos/{owner}/{name}/git/trees/{new_tag}?recursive=1")
            if not tree.get("__404__"):
                ctx.repo["files"] = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob"]
        except NetError as e:
            ctx.notes.append(f"Не вдалося отримати дерево репозиторію: {e}")


def _role_by_history(login: str, owners_l: Set[str], prior_commits: Optional[int], cfg: Dict[str, Any]) -> str:
    if login.lower() in owners_l:
        return "maintainer"
    if prior_commits is None:
        return "contributor"
    if prior_commits == 0:
        return "newcomer"
    if prior_commits >= cfg["trust"].get("maintainer_min_commits", 50):
        return "maintainer"
    return "contributor"


def collect_authors(ctx: Context, gh: GitHub, cfg: Dict[str, Any]) -> None:
    """Збір авторів змін між тегами v0 і v1 та визначення їх ролей."""
    tcfg = cfg["trust"]
    r = ctx.repo
    if r.get("status") != "ok":
        return
    if ctx.is_new_dependency or not r.get("old_tag") or not r.get("new_tag"):
        r["compare"] = "unavailable"
        return
    owner, name = r["owner"], r["name"]
    try:
        cmp_ = gh.get(f"/repos/{owner}/{name}/compare/{r['old_tag']}...{r['new_tag']}")
        if cmp_.get("__404__"):
            r["compare"] = "unavailable"
            return
        contributors = gh.get(f"/repos/{owner}/{name}/contributors?per_page=100&anon=0")
    except NetError as e:
        ctx.notes.append(f"Порівняння тегів недоступне: {e}")
        r["compare"] = "unavailable"
        return
    r["compare"] = "ok"
    total_by_login = {}
    if isinstance(contributors, list):
        total_by_login = {c["login"].lower(): c.get("contributions", 0) for c in contributors if c.get("login")}
    owners_l = {o.lower() for o in ctx.meta.get("owners", [])}
    has_token = "Authorization" in gh.headers

    agg: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"lines": 0, "commits": 0, "files": set(), "assoc": None})
    commits = cmp_.get("commits", [])[-tcfg["max_commits"]:]
    for c in commits:
        login = (c.get("author") or {}).get("login")
        key = login or f"email:{(c.get('commit', {}).get('author') or {}).get('email', '?')}"
        a = agg[key]
        a["login"] = login
        a["name"] = (c.get("commit", {}).get("author") or {}).get("name", key)
        a["commits"] += 1
        lines = 1
        if has_token:
            try:
                det = gh.get(f"/repos/{owner}/{name}/commits/{c['sha']}")
                lines = max(1, (det.get("stats") or {}).get("total", 1))
                for f in det.get("files", []):
                    a["files"].add(f.get("filename"))
                pulls = gh.get(f"/repos/{owner}/{name}/commits/{c['sha']}/pulls")
                if isinstance(pulls, list) and pulls:
                    a["assoc"] = pulls[0].get("author_association") or a["assoc"]
            except NetError:
                pass
        a["lines"] += lines

    for key, a in agg.items():
        login = a.get("login")
        if not login:
            role = "unknown"
        elif a["assoc"] in MAINTAINER_ASSOC or login.lower() in owners_l:
            role = "maintainer"
        elif a["assoc"] in NEWCOMER_ASSOC:
            role = "newcomer"
        elif a["assoc"] == "CONTRIBUTOR":
            role = "contributor"
        else:
            total = total_by_login.get(login.lower())
            prior = None if total is None else max(0, total - a["commits"])
            role = _role_by_history(login, owners_l, prior, cfg)
            if login.endswith("[bot]"):
                role = "contributor"
        ctx.authors.append(Author(login=login, name=a["name"], role=role, trust=tcfg[role],
                                  changed_lines=a["lines"], commits=a["commits"],
                                  files=sorted(x for x in a["files"] if x)[:20]))
    if not has_token:
        ctx.notes.append("GITHUB_TOKEN не задано: обсяг змін рахується в комітах, ролі — за історією внесків")


def finalize_trust(ctx: Context, cfg: Dict[str, Any], w: float) -> Optional[float]:
    """Формула (2.3): τ = Σ c_j·t_j / Σ c_j; індикатор A3 = 1 − τ."""
    ind = ctx.ind("A3", w)
    tcfg = cfg["trust"]
    if ctx.unmatched_lines > 0:
        ctx.authors.append(Author(login=None, name="(файли, відсутні в репозиторії)", role="unknown",
                                  trust=tcfg["unknown"], changed_lines=ctx.unmatched_lines))
    status = ctx.repo.get("status")
    if status == "unavailable":
        ind.evaluated = False
        ind.note = "Дані репозиторію недоступні — довіру до авторів не оцінено"
        return None
    if not ctx.authors:
        if status == "missing" or ctx.repo.get("compare") == "unavailable":
            policy = tcfg.get("missing_tag_policy", "zero")
            if policy == "zero" and not ctx.is_new_dependency:
                ctx.authors.append(Author(login=None, name="(автора змін неможливо встановити)", role="unknown",
                                          trust=tcfg["unknown"], changed_lines=max(1, len(ctx.changed_files))))
            else:
                ind.evaluated = False
                ind.note = "Немає даних для оцінки авторів змін"
                return None
        else:
            ind.note = "Змін коду між версіями не виявлено"
            return 1.0
    total = sum(a.changed_lines for a in ctx.authors)
    tau = sum(a.changed_lines * a.trust for a in ctx.authors) / total if total else 1.0
    ind.value = round(1 - tau, 4)
    for a in sorted(ctx.authors, key=lambda x: -x.changed_lines):
        ind.add(f"{a.login or a.name}: роль «{a.role}», t={a.trust}, змінено {a.changed_lines}, комітів {a.commits}")
        if a.role == "newcomer":
            files = f" (файли: {', '.join(a.files)})" if a.files else ""
            ctx.warnings.append(f"Новий учасник {a.login} вніс зміни до версії {ctx.new.version}{files}")
    return tau


def repo_file_matcher(ctx: Context):
    """Функція, що перевіряє наявність файлу пакета в репозиторії (для S6)."""
    files = ctx.repo.get("files")
    if not files:
        return None
    full = set(files)
    suffixes = set()
    for f in files:
        parts = f.split("/")
        for i in range(len(parts)):
            suffixes.add("/".join(parts[i:]))

    def present(rel: str) -> bool:
        base = rel.rsplit("/", 1)[-1]
        if base in GENERATED or ".dist-info/" in rel or ".egg-info/" in rel:
            return True
        if not rel.endswith(CODE_EXT):
            return True
        return rel in full or rel in suffixes

    return present


def run(ctx: Context, http: Http, cache: Cache, cfg: Dict[str, Any],
        project: Optional[Dict[str, Any]], old_rel: Dict[str, Any], new_rel: Dict[str, Any],
        offline: bool = False) -> None:
    w = cfg["weights"]
    if offline or not project:
        for code in ("A1", "A2", "A4", "A5"):
            i = ctx.ind(code, w[code])
            i.evaluated = False
            i.note = "Метадані реєстру недоступні (локальний режим)"
        ctx.repo["status"] = "unavailable"
        return
    pypi, gh = PyPI(http), GitHub(http)
    ctx.meta["project"] = {"name": project["info"].get("name"), "versions": len(project.get("releases", {}))}
    check_publisher(ctx, pypi, old_rel, new_rel, w["A1"])
    check_owners(ctx, cache, project, w["A2"])
    check_periodicity(ctx, project, cfg, w["A4"])
    check_repository(ctx, gh, project, cfg, w["A5"])
    collect_authors(ctx, gh, cfg)
