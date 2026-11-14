"""Формування звіту: консоль (для журналу CI/CD), JSON і SARIF (GitHub Code Scanning)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .models import INDICATOR_NAMES

DECISION_UA = {"allow": "ДОПУСТИТИ", "warn": "ДОПУСТИТИ З ПОПЕРЕДЖЕННЯМ", "block": "ЗАБЛОКУВАТИ",
               "error": "ПОМИЛКА АНАЛІЗУ"}


class Colors:
    def __init__(self, enabled: bool):
        e = enabled
        self.R = "\033[31m" if e else ""
        self.G = "\033[32m" if e else ""
        self.Y = "\033[33m" if e else ""
        self.B = "\033[1m" if e else ""
        self.D = "\033[2m" if e else ""
        self.C = "\033[36m" if e else ""
        self.X = "\033[0m" if e else ""


def use_color(flag: Optional[bool]) -> bool:
    if flag is not None:
        return flag
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _fmt(x: Optional[float]) -> str:
    return "—" if x is None else f"{x:.2f}"


def render_console(r: Dict[str, Any], color: bool = True, verbose: bool = False) -> str:
    c = Colors(color)
    out: List[str] = []
    old = r.get("old_version") or "—"
    title = f"{r['package']}  {old} → {r['new_version']}"
    out.append(f"{c.B}{'═' * 70}{c.X}")
    out.append(f"{c.B} LibSentinel {__version__} · аналіз оновлення бібліотеки{c.X}")
    out.append(f"{c.B} {title}{c.X}")
    out.append(f"{c.B}{'═' * 70}{c.X}")
    if r.get("decision") == "error":
        out.append(f"{c.R}{c.B} Рішення: {DECISION_UA['error']}{c.X}  {r.get('error', '')}")
        return "\n".join(out)

    col = {"allow": c.G, "warn": c.Y, "block": c.R}.get(r["decision"], "")
    out.append(f" Рішення:                 {col}{c.B}{DECISION_UA[r['decision']]}{c.X} (код завершення {r['exit_code']})")
    out.append(f" Ймовірність аномалії Pa: {_fmt(r['anomaly_probability'])}")
    out.append(f" Довіра до оновлення D:   {_fmt(r['update_trust'])}")
    out.append(f" Довіра до авторів τ:     {_fmt(r['author_trust'])}")
    out.append(f" Рівень небезпеки:        {col}{r['danger_level']}{c.X}")
    out.append(f" Динамічний аналіз:       {'виконано' if r['dynamic_analysis'] else 'не виконувався'}")
    diff = (r.get("meta") or {}).get("diff")
    if diff:
        out.append(f" Змінено/додано файлів:   {diff['changed_or_added']}, видалено: {diff['removed']}")

    trig = [i for i in r["indicators"] if i["evaluated"] and i["value"] > 0]
    out.append("")
    out.append(f"{c.B} Індикатори, що спрацювали ({len(trig)}){c.X}")
    if not trig:
        out.append(f"   {c.G}немає{c.X}")
    for i in trig:
        mark = f"{c.R}[КРИТИЧНИЙ]{c.X} " if i["critical"] else ""
        contrib = "блокування" if i["critical"] else f"внесок {i['contribution']:.2f} (x={i['value']:.2f}, p={i['weight']})"
        out.append(f"  {c.B}{i['code']}{c.X} {mark}{i['name']} — {contrib}")
        limit = None if verbose else 3
        for e in i["evidence"][:limit]:
            loc = ""
            if e.get("file"):
                loc = f"{c.C}{e['file']}{':' + str(e['line']) if e.get('line') else ''}{c.X} "
            out.append(f"      • {loc}{e['message']}")
            if e.get("snippet"):
                out.append(f"        {c.D}{e['snippet']}{c.X}")
        if limit and len(i["evidence"]) > limit:
            out.append(f"      … ще {len(i['evidence']) - limit} (повний перелік у JSON або з --verbose)")

    if r.get("authors"):
        out.append("")
        out.append(f"{c.B} Автори змін{c.X}")
        for a in sorted(r["authors"], key=lambda x: -x["changed_lines"])[:10]:
            out.append(f"   {a.get('login') or a['name']:<30} роль: {a['role']:<12} t={a['trust']:<4} "
                       f"змін: {a['changed_lines']}")

    if r.get("warnings"):
        out.append("")
        out.append(f"{c.Y}{c.B} Попередження{c.X}")
        for w in r["warnings"]:
            out.append(f"   ! {w}")

    vulns = r.get("vulnerabilities") or []
    if vulns:
        out.append("")
        out.append(f"{c.B} Відомі вразливості та записи про шкідливі пакети ({len(vulns)}){c.X}")
        for v in vulns[:15]:
            mark = f"{c.R}ШКІДЛИВИЙ{c.X} " if v["malicious"] else ""
            fixed = f", виправлено у {v['fixed']}" if v.get("fixed") else ""
            out.append(f"   {mark}{v['package']} {v.get('version') or ''}: {v['id']} {v.get('severity', '')}{fixed}")
            if v.get("summary"):
                out.append(f"      {c.D}{v['summary'][:110]}{c.X}")

    not_eval = [i for i in r["indicators"] if not i["evaluated"]]
    if not_eval:
        out.append("")
        out.append(f"{c.D} Не оцінено: " + ", ".join(f"{i['code']} ({i['note']})" if i.get("note") else i["code"]
                                                   for i in not_eval) + c.X)
    if r.get("notes"):
        out.append("")
        out.append(f"{c.B} Примітки{c.X}")
        for n in r["notes"]:
            out.append(f"   – {n}")
    tm = r.get("timings_seconds") or {}
    if tm:
        out.append("")
        out.append(f"{c.D} Час, с: " + ", ".join(f"{k}={v:.2f}" for k, v in tm.items()) + c.X)
    return "\n".join(out)


def render_summary(results: List[Dict[str, Any]], color: bool = True) -> str:
    c = Colors(color)
    lines = ["", f"{c.B}Підсумок перевірки залежностей{c.X}",
             f" {'Бібліотека':<28}{'Версії':<26}{'Pa':>6}  Рішення"]
    for r in results:
        v = f"{r.get('old_version') or 'нова'} → {r['new_version']}"
        col = {"allow": c.G, "warn": c.Y, "block": c.R}.get(r["decision"], c.R)
        lines.append(f" {r['package']:<28}{v:<26}{_fmt(r.get('anomaly_probability')):>6}  "
                     f"{col}{DECISION_UA.get(r['decision'], r['decision'])}{c.X}")
    return "\n".join(lines)


def to_json(results: Any) -> str:
    return json.dumps(results, ensure_ascii=False, indent=2)


def to_sarif(results: List[Dict[str, Any]], requirements_file: Optional[str] = None,
             lines: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """SARIF 2.1.0 для завантаження у GitHub Code Scanning (вкладка Security)."""
    rules = [{"id": code, "name": code, "shortDescription": {"text": name},
              "fullDescription": {"text": f"LibSentinel: {name}"},
              "properties": {"tags": ["security", "supply-chain"]}}
             for code, name in INDICATOR_NAMES.items()]
    sarif_results = []
    for r in results:
        if r.get("decision") in ("allow", "error"):
            continue
        for i in r["indicators"]:
            if not (i["evaluated"] and i["value"] > 0):
                continue
            level = "error" if i["critical"] or r["decision"] == "block" else "warning"
            ev = "; ".join(
                (f"{e['file']}:{e.get('line', '')} " if e.get("file") else "") + e["message"]
                for e in i["evidence"][:3])
            msg = (f"{r['package']} {r.get('old_version') or ''} → {r['new_version']}: {i['name']}. {ev} "
                   f"[Pa={_fmt(r['anomaly_probability'])}, рішення: {DECISION_UA[r['decision']]}]")
            res: Dict[str, Any] = {"ruleId": i["code"], "level": level, "message": {"text": msg}}
            if requirements_file:
                ln = (lines or {}).get(r["package"].lower(), 1)
                res["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": requirements_file},
                    "region": {"startLine": max(1, ln)}}}]
            res["partialFingerprints"] = {"libsentinel": f"{r['package']}:{r['new_version']}:{i['code']}"}
            sarif_results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "LibSentinel", "version": __version__,
                                      "informationUri": "https://github.com/", "rules": rules}},
                  "results": sarif_results}],
    }
