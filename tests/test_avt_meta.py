"""Блокові тести модуля avt_meta (A1–A5, ступінь довіри τ за формулою 2.3)."""

from datetime import datetime, timedelta, timezone

import pytest

from libsentinel import avt_meta
from libsentinel.cache import Cache
from libsentinel.models import Author, Context, PackageVersion


def ctx(old="1.0.0", new="1.1.0"):
    return Context(name="demo", old=PackageVersion("demo", old), new=PackageVersion("demo", new))


def project(times, owners=("alice",)):
    base = datetime(2020, 1, 1, tzinfo=timezone.utc)
    rel = {v: [{"upload_time_iso_8601": (base + timedelta(days=d)).isoformat()}] for v, d in times}
    return {"info": {"name": "demo", "project_urls": {"Source": "https://github.com/acme/demo"}},
            "releases": rel, "ownership": {"roles": [{"role": "Owner", "user": u} for u in owners]}}


def test_trust_formula_weighted_by_lines(cfg):
    c = ctx()
    c.repo["status"] = "ok"
    c.authors = [Author("alice", "Alice", "maintainer", 1.0, 90),
                 Author("bob", "Bob", "newcomer", 0.2, 10)]
    tau = avt_meta.finalize_trust(c, cfg, 0.4)
    # τ = (90·1 + 10·0.2) / 100 = 0.92
    assert tau == pytest.approx(0.92)
    assert c.indicators["A3"].value == pytest.approx(0.08)
    assert any("bob" in w for w in c.warnings), "для нового учасника має бути попередження"


def test_unmatched_lines_get_zero_trust(cfg):
    c = ctx()
    c.repo["status"] = "ok"
    c.authors = [Author("alice", "Alice", "maintainer", 1.0, 50)]
    c.unmatched_lines = 50
    tau = avt_meta.finalize_trust(c, cfg, 0.4)
    assert tau == pytest.approx(0.5)


def test_trust_not_evaluated_when_repo_unavailable(cfg):
    c = ctx()
    c.repo["status"] = "unavailable"
    assert avt_meta.finalize_trust(c, cfg, 0.4) is None
    assert c.indicators["A3"].evaluated is False


def test_periodicity_long_pause(cfg):
    c = ctx("1.2.0", "1.3.0")
    p = project([("1.0.0", 0), ("1.1.0", 30), ("1.2.0", 60), ("1.3.0", 60 + 800)])
    avt_meta.check_periodicity(c, p, cfg, 0.3)
    assert c.indicators["A4"].triggered


def test_periodicity_regular(cfg):
    c = ctx("1.2.0", "1.3.0")
    p = project([("1.0.0", 0), ("1.1.0", 30), ("1.2.0", 60), ("1.3.0", 90)])
    avt_meta.check_periodicity(c, p, cfg, 0.3)
    assert not c.indicators["A4"].triggered


def test_periodicity_burst(cfg):
    c = ctx("1.0.0", "1.0.3")
    base = [("0.1", 0), ("0.2", 60), ("1.0.0", 120)]
    p = project(base + [("1.0.1", 300), ("1.0.2", 300.1), ("1.0.3", 300.2)])
    avt_meta.check_periodicity(c, p, cfg, 0.3)
    assert c.indicators["A4"].triggered


def test_new_owner_a2(cfg):
    cache = Cache()
    c1 = ctx()
    avt_meta.check_owners(c1, cache, project([], owners=("alice",)), 0.4)
    assert c1.indicators["A2"].evaluated is False      # перший знімок
    c2 = ctx()
    avt_meta.check_owners(c2, cache, project([], owners=("alice", "mallory")), 0.4)
    assert c2.indicators["A2"].triggered
    assert "mallory" in c2.indicators["A2"].evidence[0].message


def test_find_repo_from_project_urls():
    assert avt_meta.find_repo(project([])) == ("acme", "demo")


def test_repo_file_matcher():
    c = ctx()
    c.repo["files"] = ["src/demo/__init__.py", "src/demo/core.py", "setup.py"]
    present = avt_meta.repo_file_matcher(c)
    assert present("demo/core.py")          # wheel-шлях без src/
    assert present("setup.py")
    assert present("PKG-INFO")              # згенерований файл
    assert not present("demo/evil.py")


class FakeGitHub:
    """Імітація GitHub API для перевірки визначення ролей авторів."""

    def __init__(self, with_token=True):
        self.headers = {"Authorization": "x"} if with_token else {}

    def get(self, path, allow_404=True):
        if "/compare/" in path:
            return {"commits": [
                {"sha": "a1", "author": {"login": "alice"}, "commit": {"author": {"name": "Alice"}}},
                {"sha": "b1", "author": {"login": "bob"}, "commit": {"author": {"name": "Bob"}}},
                {"sha": "c1", "author": {"login": "carol"}, "commit": {"author": {"name": "Carol"}}},
            ]}
        if path.endswith("/pulls"):
            assoc = {"a1": "OWNER", "b1": "FIRST_TIME_CONTRIBUTOR", "c1": "CONTRIBUTOR"}[path.split("/")[-2]]
            return [{"author_association": assoc, "user": {"login": "x"}}]
        if "/commits/" in path:
            return {"stats": {"total": 10}, "files": [{"filename": "demo/x.py"}]}
        if "/contributors" in path:
            return []
        return {"__404__": True}


def test_collect_authors_roles(cfg):
    c = ctx()
    c.repo.update({"status": "ok", "owner": "acme", "name": "demo", "old_tag": "v1.0.0", "new_tag": "v1.1.0"})
    avt_meta.collect_authors(c, FakeGitHub(), cfg)
    roles = {a.login: a.role for a in c.authors}
    assert roles == {"alice": "maintainer", "bob": "newcomer", "carol": "contributor"}
    tau = avt_meta.finalize_trust(c, cfg, 0.4)
    assert tau == pytest.approx((10 * 1.0 + 10 * 0.2 + 10 * 0.6) / 30)
