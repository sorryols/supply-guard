"""Експериментальний стенд LibSentinel.

Проганяє засіб на вибірці оновлень з відомою міткою (0 — безпечне, 1 — шкідливе)
і обчислює показники якості для двох рівнів рішення засобу:
  • блокування (критичний індикатор) — точність, повнота, F1, частка хибних блокувань;
  • виявлення (блокування або передача на розгляд розробнику) — частка шкідливих
    оновлень, які не пройшли непоміченими, і частка безпечних, переданих на розгляд.
Також рахує, як часто спрацьовував кожен індикатор на шкідливих і безпечних зразках.

Приклади:
  python experiments/make_synthetic.py
  python experiments/run_experiment.py experiments/benign_real.csv experiments/synthetic/synthetic.csv
  python experiments/run_experiment.py data.csv --dast never
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from libsentinel.analyzer import Analyzer, error_result  # noqa: E402
from libsentinel.config import load_config  # noqa: E402


def load_rows(paths: List[str]) -> List[Dict[str, str]]:
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["_source"] = Path(p).name
                rows.append(r)
    return rows


def metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": round(precision, 4),
            "recall": round(recall, 4), "F1": round(f1, 4), "FPR": round(fpr, 4)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Експериментальна перевірка LibSentinel")
    ap.add_argument("datasets", nargs="+", help="CSV: name,old,new,label[,old_archive,new_archive,kind]")
    ap.add_argument("--config")
    ap.add_argument("--dast", choices=["auto", "always", "never"], default="auto")
    ap.add_argument("--limit", type=int, default=0, help="Обмежити кількість зразків з кожного CSV")
    ap.add_argument("--out", default="experiments/results")
    a = ap.parse_args()

    cfg = load_config(a.config)
    an = Analyzer(cfg, use_cache=True)
    rows = load_rows(a.datasets)
    if a.limit:
        by_src: Dict[str, int] = {}
        kept = []
        for r in rows:
            by_src[r["_source"]] = by_src.get(r["_source"], 0) + 1
            if by_src[r["_source"]] <= a.limit:
                kept.append(r)
        rows = kept
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    records = []
    print(f"Зразків: {len(rows)}; динамічний аналіз: {a.dast}\n")
    print(f"{'#':>3} {'Бібліотека':<22}{'Версії':<22}{'Мітка':>6}{'Ознак':>7}  {'Рішення':<8}{'DAST':>5}{'Час,с':>7}  Індикатори")
    for n, r in enumerate(rows, 1):
        old_a = [Path(x) for x in r["old_archive"].split(";")] if r.get("old_archive") else None
        new_a = [Path(x) for x in r["new_archive"].split(";")] if r.get("new_archive") else None
        # локальні архіви нової версії; стара версія (якщо задана без архіву) завантажується з PyPI
        offline = bool(new_a) and (not r.get("old") or bool(old_a))
        t0 = time.perf_counter()
        try:
            res = an.analyze(r["name"], r.get("old") or None, r["new"], dast_mode=a.dast,
                             offline=offline, old_archives=old_a, new_archives=new_a, force=True)
        except Exception as e:  # noqa: BLE001
            res = error_result(r["name"], r.get("old"), r["new"], str(e))
        dt = time.perf_counter() - t0
        trig = [i["code"] for i in res["indicators"] if i["evaluated"] and i["value"] > 0]
        crit = any(i["critical"] and i["value"] > 0 for i in res["indicators"])
        rec = {"name": r["name"], "old": r.get("old"), "new": r["new"], "label": int(r["label"]),
               "kind": r.get("kind", ""), "decision": res["decision"], "n": res.get("triggered_count"),
               "critical": crit, "dast": res.get("dynamic_analysis"), "time": round(dt, 3),
               "indicators": " ".join(trig), "source": r["_source"], "error": res.get("error", "")}
        records.append(rec)
        pa = "—" if rec["n"] is None else ("К" if crit else str(rec["n"]))
        print(f"{n:>3} {r['name'][:21]:<22}{(str(r.get('old') or '—') + '→' + r['new'])[:21]:<22}{rec['label']:>6}"
              f"{pa:>7}  {rec['decision']:<8}{'так' if rec['dast'] else 'ні':>5}{dt:>7.2f}  {rec['indicators']}"
              + (f"  ПОМИЛКА: {rec['error'][:80]}" if rec["error"] else ""))

    valid = [r for r in records if r["decision"] != "error"]
    y = [r["label"] for r in valid]
    m = {"block": metrics(y, [1 if r["decision"] == "block" else 0 for r in valid]),
         "detect": metrics(y, [1 if r["decision"] in ("block", "warn") else 0 for r in valid])}
    times = [r["time"] for r in valid]
    mal = [r for r in valid if r["label"] == 1]
    ben = [r for r in valid if r["label"] == 0]
    m.update({"samples": len(valid), "malicious": len(mal), "benign": len(ben),
              "errors": len(records) - len(valid),
              "decisions_malicious": {d: sum(1 for r in mal if r["decision"] == d) for d in ("block", "warn", "allow")},
              "decisions_benign": {d: sum(1 for r in ben if r["decision"] == d) for d in ("block", "warn", "allow")},
              "avg_time_s": round(statistics.mean(times), 3) if times else None,
              "median_time_s": round(statistics.median(times), 3) if times else None,
              "dast_share": round(sum(1 for r in valid if r["dast"]) / len(valid), 4) if valid else None,
              "dast_mode": a.dast})
    freq: Dict[str, Dict[str, int]] = {}
    for r in valid:
        for code in r["indicators"].split():
            freq.setdefault(code, {"malicious": 0, "benign": 0})
            freq[code]["malicious" if r["label"] == 1 else "benign"] += 1
    m["indicator_frequency"] = dict(sorted(freq.items()))
    by_kind: Dict[str, Dict[str, int]] = {}
    for r in valid:
        k = by_kind.setdefault(r["kind"] or r["source"], {"total": 0, "block": 0, "warn": 0, "allow": 0, "dast": 0})
        k["total"] += 1
        k[r["decision"]] += 1
        k["dast"] += 1 if r["dast"] else 0
    m["by_kind"] = by_kind

    b, d = m["block"], m["detect"]
    print("\nРішення засобу")
    print(f"  шкідливі ({len(mal)}): заблоковано {m['decisions_malicious']['block']}, "
          f"на розгляд {m['decisions_malicious']['warn']}, допущено {m['decisions_malicious']['allow']}")
    print(f"  безпечні ({len(ben)}): заблоковано {m['decisions_benign']['block']}, "
          f"на розгляд {m['decisions_benign']['warn']}, допущено {m['decisions_benign']['allow']}")
    print(f"  помилок аналізу: {m['errors']}")
    print("\nБлокування (критичні індикатори)")
    print(f"  TP={b['TP']} FP={b['FP']} FN={b['FN']} TN={b['TN']}")
    print(f"  Точність {b['precision']:.3f}, повнота {b['recall']:.3f}, F1 {b['F1']:.3f}, частка хибних блокувань {b['FPR']:.3f}")
    print("Виявлення (блокування або передача на розгляд)")
    print(f"  Повнота виявлення {d['recall']:.3f}, частка безпечних на розгляді {d['FPR']:.3f}")
    print(f"\nСередній час аналізу: {m['avg_time_s']} с (медіана {m['median_time_s']} с)")
    print(f"Частка оновлень з динамічним аналізом: {m['dast_share']}")
    print("\nЗа сценаріями (усього / заблоковано / на розгляд / допущено / з DAST)")
    for k, v in by_kind.items():
        print(f"  {k:<22} {v['total']:>4} {v['block']:>5} {v['warn']:>5} {v['allow']:>5} {v['dast']:>5}")
    print("\nЧастота спрацювання індикаторів (шкідливі / безпечні)")
    for code, v in m["indicator_frequency"].items():
        print(f"  {code:<3} {v['malicious']:>5} / {v['benign']}")

    with open(out / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        w.writerows(records)
    (out / "metrics.json").write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nРезультати збережено: {out / 'results.csv'}, {out / 'metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
