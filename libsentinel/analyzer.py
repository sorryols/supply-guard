"""Алгоритм аналізу безпеки бібліотек (підрозділ 2.4, рисунок 2.2)."""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import avt_meta, dast, deps, sast
from .cache import Cache
from .config import config_hash
from .fetch import Fetcher
from .models import EXIT_BLOCK, Context, Report
from .net import Http, NetError, PyPI
from .scoring import critical_triggered, danger_level, decide, need_dynamic, regular_triggered


class Analyzer:
    def __init__(self, cfg: Dict[str, Any], use_cache: bool = True):
        self.cfg = cfg
        self.cache = Cache(enabled=use_cache and cfg["cache"]["enabled"])
        self.http = Http(cfg, self.cache)

    def analyze(self, name: str, old_version: Optional[str], new_version: str,
                dast_mode: str = "auto", offline: bool = False,
                old_archives: Optional[List[Path]] = None, new_archives: Optional[List[Path]] = None,
                force: bool = False) -> Dict[str, Any]:
        local = bool(new_archives)
        from . import __version__
        key = f"{__version__}|{name.lower()}|{old_version}|{new_version}|{dast_mode}|{offline}|{config_hash(self.cfg)}"
        if not force and not local:
            hit = self.cache.get_result(key)
            if hit:
                hit["notes"] = list(hit.get("notes", [])) + ["Результат узято з кешу (--no-cache для повторного аналізу)"]
                return hit

        t0 = time.perf_counter()
        timings: Dict[str, float] = {}
        work = Path(tempfile.mkdtemp(prefix="libsentinel-"))
        try:
            # Етап 1. Отримання та підготовка даних
            t = time.perf_counter()
            fetcher = Fetcher(self.http, work, self.cache.dir / "archives")
            project = None
            try:
                if not offline:
                    project = PyPI(self.http).project(name)
                old, old_rel = fetcher.prepare(name, old_version, "old", old_archives)
                new, new_rel = fetcher.prepare(name, new_version, "new", new_archives)
            except NetError as e:
                # Бібліотеку або версію могли видалити з PyPI як шкідливу — перевіряємо базу OpenSSF
                mal = deps.ossf_local_malicious(name, new_version, self.cfg["deps"].get("ossf_dir", ""))
                if not mal:
                    raise
                return self._malicious_only(name, old_version, new_version, mal, str(e), time.perf_counter() - t0)
            ctx = Context(name=name, old=old, new=new)
            timings["fetch"] = time.perf_counter() - t

            # Етап 2. Аналіз авторів і метаданих
            t = time.perf_counter()
            avt_meta.run(ctx, self.http, self.cache, self.cfg, project, old_rel, new_rel, offline=offline or local)
            timings["avt_meta"] = time.perf_counter() - t

            # Етап 3. Аналіз різниці між версіями та статичний аналіз
            t = time.perf_counter()
            sast.run(ctx, self.cfg, avt_meta.repo_file_matcher(ctx))
            da = avt_meta.finalize_trust(ctx, self.cfg, 0.0)
            timings["sast"] = time.perf_counter() - t

            # Етап 4. Аналіз залежностей
            t = time.perf_counter()
            deps.run(ctx, self.http, self.cfg, offline=offline)
            timings["deps"] = time.perf_counter() - t

            # Перевірка критичних індикаторів
            inds = list(ctx.indicators.values())
            critical = critical_triggered(inds)
            ctx.meta["triggered_before_dast"] = [i.code for i in regular_triggered(inds)]

            # Етап 5. Динамічний аналіз (за умовою)
            dynamic_run = False
            if critical:
                ctx.notes.append("Спрацював критичний індикатор — динамічний аналіз не потрібен, оновлення блокується")
            elif dast_mode == "never" or not self.cfg["dast"]["enabled"]:
                ctx.notes.append("Динамічний аналіз вимкнено")
            else:
                need, reason = need_dynamic(ctx.indicators, self.cfg)
                if dast_mode == "always" or need:
                    ctx.notes.append(f"Динамічний аналіз запущено: {reason if need else 'режим --dast always'}")
                    t = time.perf_counter()
                    dynamic_run = dast.run(ctx, self.cfg)
                    timings["dast"] = time.perf_counter() - t
                else:
                    ctx.notes.append(f"Динамічний аналіз не потрібен: {reason}")

            # Етап 6. Остаточна оцінка, рішення та звіт
            if dynamic_run and self.cfg["dast"].get("clear_s1_if_clean", True):
                dyn = [ctx.indicators[c] for c in ("B1", "B2", "B3", "K5") if c in ctx.indicators]
                s1 = ctx.indicators.get("S1")
                install_ok = (ctx.meta.get("dast") or {}).get("install_rc") == 0
                if s1 and s1.triggered and install_ok and not any(i.triggered for i in dyn):
                    s1.value = 0.0
                    s1.note = "код встановлення виконано в пісочниці, шкідливої поведінки не виявлено"
                    ctx.notes.append("S1 знято: динамічний аналіз коду встановлення не виявив шкідливої поведінки")
            inds = list(ctx.indicators.values())
            critical = critical_triggered(inds)
            n = len(regular_triggered(inds))
            has_newcomer = any(a.role == "newcomer" for a in ctx.authors)
            decision, code = decide(bool(critical), n, has_newcomer)
            if decision == "warn":
                ctx.notes.append("Рішення щодо оновлення приймає розробник на підставі доказів у звіті")
            timings["total"] = time.perf_counter() - t0

            ordered = sorted(inds, key=lambda i: (not (i.critical and i.triggered), not i.triggered, i.code))
            report = Report(
                package=name, old_version=old_version, new_version=new_version,
                decision=decision, exit_code=code, triggered_count=n,
                author_trust=da, level=danger_level(bool(critical), n, self.cfg), indicators=ordered,
                vulnerabilities=ctx.vulnerabilities, authors=ctx.authors, warnings=ctx.warnings,
                notes=ctx.notes, dynamic_run=dynamic_run, timings=timings,
            )
            result = report.to_dict()
            result["meta"] = {k: v for k, v in ctx.meta.items() if k in ("diff", "dependencies", "triggered_before_dast", "dast", "publishers", "owners")}
            result["repository"] = {k: v for k, v in ctx.repo.items() if k != "files"}
            if not local:
                self.cache.put_result(key, result)
            return result
        finally:
            shutil.rmtree(work, ignore_errors=True)


    def _malicious_only(self, name, old, new, ids, reason, elapsed) -> Dict[str, Any]:
        from .models import EXIT_BLOCK, Indicator, Vulnerability
        k4 = Indicator(code="K4")
        k4.value = 1.0
        k4.add(f"{name} {new}: {', '.join(ids[:3])} у базі OpenSSF Malicious Packages")
        report = Report(package=name, old_version=old, new_version=new, decision="block", exit_code=EXIT_BLOCK,
                        triggered_count=0, author_trust=None, level="критичний", indicators=[k4],
                        vulnerabilities=[Vulnerability(id=i, package=name, version=new, malicious=True,
                                                       summary="Шкідлива бібліотека (OpenSSF)") for i in ids[:5]],
                        authors=[], warnings=[], notes=[f"Бібліотека недоступна в PyPI ({reason}) — "
                                                       f"ймовірно, видалена як шкідлива"],
                        dynamic_run=False, timings={"total": elapsed})
        return report.to_dict()


def error_result(name: str, old: Optional[str], new: str, message: str) -> Dict[str, Any]:
    from .models import EXIT_ERROR
    return {"package": name, "old_version": old, "new_version": new, "decision": "error",
            "exit_code": EXIT_ERROR, "error": message, "indicators": [], "vulnerabilities": [],
            "authors": [], "warnings": [], "notes": [message], "triggered_count": None,
            "danger_level": "невідомий", "dynamic_analysis": False, "timings_seconds": {}}
