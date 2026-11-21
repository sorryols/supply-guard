"""Блокові тести модуля scoring (правило прийняття рішення без ваг)."""

from libsentinel.config import load_config
from libsentinel.models import Indicator
from libsentinel.scoring import (critical_triggered, danger_level, decide, need_dynamic,
                                 regular_triggered)

CFG = load_config(None)


def ind(code, value=1.0, evaluated=True):
    return Indicator(code=code, value=value, evaluated=evaluated)


def test_triggered_is_binary():
    assert ind("S2", 1).triggered
    assert ind("S5", 0.3).triggered          # будь-яке ненульове значення означає «спрацював»
    assert not ind("S2", 0).triggered


def test_not_evaluated_is_not_triggered():
    assert not ind("B1", 1, evaluated=False).triggered
    assert regular_triggered([ind("B1", 1, evaluated=False)]) == []


def test_critical_separated_from_regular():
    inds = [ind("K1"), ind("S2"), ind("A4", 0)]
    assert [i.code for i in critical_triggered(inds)] == ["K1"]
    assert [i.code for i in regular_triggered(inds)] == ["S2"]


def test_decide_critical_blocks():
    assert decide(True, 0, False) == ("block", 2)


def test_decide_any_indicator_goes_to_review():
    assert decide(False, 1, False) == ("warn", 1)
    assert decide(False, 5, False) == ("warn", 1)


def test_decide_newcomer_goes_to_review():
    assert decide(False, 0, True) == ("warn", 1)


def test_decide_clean_allows():
    assert decide(False, 0, False) == ("allow", 0)


def test_dast_needs_two_indicators():
    one = {"S1": ind("S1")}
    two = {"S1": ind("S1"), "S2": ind("S2")}
    assert need_dynamic(one, CFG)[0] is False
    assert need_dynamic(two, CFG)[0] is True


def test_dast_ignores_critical_and_not_evaluated():
    inds = {"K1": ind("K1"), "S2": ind("S2"), "B1": ind("B1", evaluated=False)}
    assert need_dynamic(inds, CFG)[0] is False


def test_danger_levels():
    assert danger_level(True, 0, CFG) == "критичний"
    assert danger_level(False, 3, CFG) == "високий"
    assert danger_level(False, 1, CFG) == "середній"
    assert danger_level(False, 0, CFG) == "низький"
