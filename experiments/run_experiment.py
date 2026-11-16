"""Експериментальний стенд LibSentinel.

Проганяє засіб на вибірці оновлень з відомою міткою (0 — безпечне, 1 — шкідливе)
і обчислює показники якості бінарної класифікації (підрозділ 1.4 роботи):
точність (precision), повноту (recall), F1, частку хибних спрацювань (FPR)
та середній час аналізу одного оновлення.

Опція --sweep підбирає поріг блокування θ2 за максимумом F1 (калібрування з розділу 2).

Приклади:
  python experiments/make_synthetic.py
  python experiments/run_experiment.py experiments/benign_real.csv experiments/synthetic/synthetic.csv
  python experiments/run_experiment.py data.csv --dast never --sweep
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
    ap.add_argument("--positive", choices=["block", "warn"], default="block",
                    help="Яке рішення вважати позитивним (виявленим шкідливим оновленням)")
    ap.add_argument("--sweep", action="store_true", help="Підбір порогу θ2 за максимумом F1")
    ap.add_argument("--out", default="experiments/results")
    a = ap.parse_args()

    cfg = load_config(a.config)
    an = Analyzer(cfg, use_cache=True)
    rows = load_rows(a.datasets)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    records = []
    print(f"Зразків: {len(rows)}; динамічний аналіз: {a.dast}\n")
    print(f"{'#':>3} {'Бібліотека':<22}{'Версії':<22}{'Мітка':>6}{'Pa':>7}  {'Рішення':<8}{'DAST':>5}{'Час,с':>7}  Індикатори")
    for n, r in enumerate(rows, 1):
        old_a = [Path(r["old_archive"])] if r.get("old_archive") else None
        new_a = [Path(r["new_archive"])] if r.get("new_archive") else None
        t0 = time.perf_counter()
        try:
            res = an.analyze(r["name"], r.get("old") or None, r["new"], dast_mode=a.dast,
                             offline=bool(new_a), old_archives=old_a, new_archives=new_a, force=True)
        except Exception as e:  # noqa: BLE001
            res = error_result(r["name"], r.get("old"), r["new"], str(e))
        dt = time.perf_counter() - t0
        trig = [i["code"] for i in res["indicators"] if i["evaluated"] and i["value"] > 0]
        crit = any(i["critical"] and i["value"] > 0 for i in res["indicators"])
        rec = {"name": r["name"], "old": r.get("old"), "new": r["new"], "label": int(r["label"]),
               "kind": r.get("kind", ""), "decision": res["decision"], "pa": res.get("anomaly_probability"),
               "critical": crit, "dast": res.get("dynamic_analysis"), "time": round(dt, 3),
               "indicators": " ".join(trig), "source": r["_source"], "error": res.get("error", "")}
        records.append(rec)
        pa = "—" if rec["pa"] is None else f"{rec['pa']:.2f}"
        print(f"{n:>3} {r['name'][:21]:<22}{(str(r.get('old') or '—') + '→' + r['new'])[:21]:<22}{rec['label']:>6}"
              f"{pa:>7}  {rec['decision']:<8}{'так' if rec['dast'] else 'ні':>5}{dt:>7.2f}  {rec['indicators']}"
              + (f"  ПОМИЛКА: {rec['error'][:80]}" if rec["error"] else ""))

    valid = [r for r in records if r["decision"] != "error"]
    pos = {"block": {"block"}, "warn": {"block", "warn"}}[a.positive]
    y = [r["label"] for r in valid]
    yp = [1 if r["decision"] in pos else 0 for r in valid]
    m = metrics(y, yp)
    times = [r["time"] for r in valid]
    m.update({"samples": len(valid), "errors": len(records) - len(valid),
              "avg_time_s": round(statistics.mean(times), 3) if times else None,
              "median_time_s": round(statistics.median(times), 3) if times else None,
              "dast_share": round(sum(1 for r in valid if r["dast"]) / len(valid), 4) if valid else None,
              "positive_decision": a.positive, "dast_mode": a.dast})

    print("\nПоказники ефективності")
    print(f"  TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} (помилок аналізу: {m['errors']})")
    print(f"  Точність (precision): {m['precision']:.3f}")
    print(f"  Повнота (recall):     {m['recall']:.3f}")
    print(f"  F1:                   {m['F1']:.3f}")
    print(f"  Частка хибних спрацювань (FPR): {m['FPR']:.3f}")
    print(f"  Середній час аналізу: {m['avg_time_s']} с (медіана {m['median_time_s']} с)")
    print(f"  Частка оновлень з динамічним аналізом: {m['dast_share']}")

    if a.sweep and valid:
        print("\nПідбір порогу блокування θ2 (рішення: критичний індикатор або Pa ≥ θ2)")
        best = None
        sweep = []
        for k in range(10, 100, 5):
            th = k / 100
            yp2 = [1 if r["critical"] or (r["pa"] or 0) >= th else 0 for r in valid]
            mm = metrics(y, yp2)
            sweep.append({"theta2": th, **mm})
            print(f"  θ2={th:.2f}  precision={mm['precision']:.3f} recall={mm['recall']:.3f} "
                  f"F1={mm['F1']:.3f} FPR={mm['FPR']:.3f}")
            if best is None or (mm["F1"], -mm["FPR"]) > (best["F1"], -best["FPR"]):
                best = {"theta2": th, **mm}
        print(f"  Найкращий поріг: θ2 = {best['theta2']:.2f} (F1 = {best['F1']:.3f}, FPR = {best['FPR']:.3f})")
        m["sweep"] = sweep
        m["best_theta2"] = best

    with open(out / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        w.writerows(records)
    (out / "metrics.json").write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nРезультати збережено: {out / 'results.csv'}, {out / 'metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
