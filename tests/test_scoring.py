"""Блокові тести модуля scoring (формула 2.4 і правило прийняття рішення)."""

import pytest

from libsentinel.models import Indicator
from libsentinel.scoring import anomaly_probability, decide, danger_level, need_dynamic


def ind(code, value, weight=0.0, evaluated=True):
    return Indicator(code=code, value=value, weight=weight, evaluated=evaluated)


def test_noisy_or_single():
    assert anomaly_probability([ind("S1", 1, 0.4)]) == pytest.approx(0.4)


def test_noisy_or_two_indicators():
    # 1 − (1 − 0.4)(1 − 0.3) = 0.58
    assert anomaly_probability([ind("S1", 1, 0.4), ind("A4", 1, 0.3)]) == pytest.approx(0.58)


def test_noisy_or_bounded_by_one():
    many = [ind(f"S{i}", 1, 0.5) for i in range(1, 7)]
    pa = anomaly_probability(many)
    assert 0.98 < pa < 1.0


def test_continuous_indicator():
    # A3 = 1 − τ = 0.5, p = 0.4 → 0.2
    assert anomaly_probability([ind("A3", 0.5, 0.4)]) == pytest.approx(0.2)


def test_not_evaluated_and_critical_ignored_in_pa():
    assert anomaly_probability([ind("B1", 1, 0.7, evaluated=False), ind("K1", 1)]) == 0.0


@pytest.mark.parametrize("pa,crit,newcomer,expected", [
    (0.10, False, False, ("allow", 0)),
    (0.30, False, False, ("warn", 1)),
    (0.69, False, False, ("warn", 1)),
    (0.70, False, False, ("block", 2)),
    (0.05, True, False, ("block", 2)),
    (0.05, False, True, ("warn", 1)),
])
def test_decision_rule(cfg, pa, crit, newcomer, expected):
    assert decide(pa, crit, newcomer, cfg) == expected


def test_danger_level(cfg):
    assert danger_level(0.1, False, cfg) == "низький"
    assert danger_level(0.5, False, cfg) == "середній"
    assert danger_level(0.8, False, cfg) == "високий"
    assert danger_level(0.0, True, cfg) == "критичний"


def test_need_dynamic(cfg):
    assert need_dynamic({"S1": ind("S1", 1, 0.4)}, 0.0, cfg)[0] is True
    assert need_dynamic({}, 0.35, cfg)[0] is True
    assert need_dynamic({}, 0.10, cfg)[0] is False
