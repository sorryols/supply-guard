"""Правило прийняття рішення (підрозділ 2.1).

Індикатори не мають ваг і не дають числової оцінки: кожен лише фіксує, що ознака спрацювала.
  • спрацював критичний індикатор К1–К5            → заблокувати (код 2);
  • спрацював хоча б один звичайний індикатор      → передати розробнику на розгляд (код 1);
  • серед авторів змін є новий учасник              → передати розробнику на розгляд (код 1);
  • жоден індикатор не спрацював                     → допустити (код 0).
Динамічний аналіз запускається, якщо спрацювало щонайменше m звичайних індикаторів (m = 2).
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from .models import EXIT_ALLOW, EXIT_BLOCK, EXIT_WARN, Indicator


def critical_triggered(indicators: Iterable[Indicator]) -> List[Indicator]:
    return [i for i in indicators if i.critical and i.triggered]


def regular_triggered(indicators: Iterable[Indicator]) -> List[Indicator]:
    return [i for i in indicators if not i.critical and i.triggered]


def need_dynamic(indicators: Dict[str, Indicator], cfg: Dict) -> Tuple[bool, str]:
    """Умова запуску динамічного аналізу: спрацювало не менше m звичайних індикаторів."""
    m = int(cfg["rules"]["dast_min_indicators"])
    trig = regular_triggered(indicators.values())
    codes = ", ".join(i.code for i in trig) or "жодного"
    if len(trig) >= m:
        return True, f"спрацювало {len(trig)} індикатори(ів) ({codes}) ≥ m = {m}"
    return False, f"спрацювало {len(trig)} індикатор(ів) ({codes}) < m = {m}"


def danger_level(critical: bool, n: int, cfg: Dict) -> str:
    if critical:
        return "критичний"
    if n >= int(cfg["rules"]["high_level_indicators"]):
        return "високий"
    if n >= 1:
        return "середній"
    return "низький"


def decide(critical: bool, n: int, has_newcomer: bool) -> Tuple[str, int]:
    if critical:
        return "block", EXIT_BLOCK
    if n >= 1 or has_newcomer:
        return "warn", EXIT_WARN
    return "allow", EXIT_ALLOW
