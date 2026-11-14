"""Короткий підсумок для сторінки запуску GitHub Actions ($GITHUB_STEP_SUMMARY)."""

import json
import sys

DEC = {"allow": "✅ допустити", "warn": "⚠️ попередження", "block": "⛔ заблокувати", "error": "❗ помилка"}

data = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(data, dict):
    data = [data]
print("## LibSentinel — перевірка оновлень залежностей\n")
if not data:
    print("Змінених залежностей із закріпленими версіями не виявлено.")
    sys.exit(0)
print("| Бібліотека | Версії | Pa | Рівень | Рішення | Індикатори |")
print("|---|---|---|---|---|---|")
for r in data:
    pa = r.get("anomaly_probability")
    trig = ", ".join(i["code"] for i in r.get("indicators", []) if i.get("evaluated") and i.get("value", 0) > 0)
    print(f"| {r['package']} | {r.get('old_version') or 'нова'} → {r['new_version']} | "
          f"{'—' if pa is None else f'{pa:.2f}'} | {r.get('danger_level', '')} | "
          f"{DEC.get(r['decision'], r['decision'])} | {trig or '—'} |")
print("\nПовний звіт — в артефакті **libsentinel-report**, знахідки — у вкладці **Security → Code scanning**.")
