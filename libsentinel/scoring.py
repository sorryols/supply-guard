"""Обчислення ймовірності аномалії та прийняття рішення (підрозділ 2.1).

Формула (2.4), модель «шумного АБО»:  Pa = 1 − Π (1 − p_k · x_k)
Правило рішення: блокування при спрацюванні критичного індикатора або Pa ≥ θ2;
попередження при θ1 ≤ Pa < θ2 або наявності нового учасника серед авторів змін.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from .models import EXIT_ALLOW, EXIT_BLOCK, EXIT_WARN, Indicator


def anomaly_probability(indicators: Iterable[Indicator]) -> float:
    prod = 1.0
    for ind in indicators:
        if ind.critical or not ind.evaluated:
            continue
        prod *= 1.0 - max(0.0, min(1.0, ind.weight * ind.value))
    return 1.0 - prod


def critical_triggered(indicators: Iterable[Indicator]) -> List[Indicator]:
    return [i for i in indicators if i.critical and i.triggered]


def need_dynamic(indicators: Dict[str, Indicator], pa: float, cfg: Dict) -> Tuple[bool, str]:
    """Умова запуску динамічного аналізу: Pa ≥ θd або S1 = 1."""
    theta_d = cfg["thresholds"]["dynamic"]
    s1 = indicators.get("S1")
    if s1 is not None and s1.triggered:
        return True, "змінено код, що виконується під час встановлення (S1 = 1)"
    if pa >= theta_d:
        return True, f"попередня ймовірність аномалії {pa:.2f} ≥ θd = {theta_d}"
    return False, f"Pa = {pa:.2f} < θd = {theta_d} і код встановлення не змінювався"


def danger_level(pa: float, critical: bool, cfg: Dict) -> str:
    th = cfg["thresholds"]
    if critical:
        return "критичний"
    if pa >= th["block"]:
        return "високий"
    if pa >= th["warn"]:
        return "середній"
    return "низький"


def decide(pa: float, critical: bool, has_newcomer: bool, cfg: Dict) -> Tuple[str, int]:
    th = cfg["thresholds"]
    if critical or pa >= th["block"]:
        return "block", EXIT_BLOCK
    if pa >= th["warn"] or has_newcomer:
        return "warn", EXIT_WARN
    return "allow", EXIT_ALLOW
