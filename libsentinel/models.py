"""Структури даних засобу: індикатори, контекст аналізу, звіт."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


# Назви індикаторів (таблиця 2.1 роботи)
INDICATOR_NAMES: Dict[str, str] = {
    "A1": "Зміна видавця або зникнення атестації",
    "A2": "Новий власник або супровідник",
    "A3": "Низька довіра до авторів змін",
    "A4": "Аномальна періодичність релізів",
    "A5": "Відсутність тегу версії в репозиторії",
    "S1": "Зміна коду, що виконується під час встановлення",
    "S2": "Нові небезпечні виклики",
    "S3": "Нові мережеві можливості",
    "S4": "Доступ до чутливих даних",
    "S5": "Рядки з високою ентропією",
    "S6": "Файли бібліотеки, відсутні в репозиторії",
    "D1": "Нова пряма залежність",
    "D2": "Схожість назви залежності на популярну",
    "D3": "Нова або малоактивна залежність",
    "D4": "Відомі вразливості",
    "B1": "Мережеві з'єднання з недозволеними хостами",
    "B2": "Запуск оболонки чи інших програм",
    "B3": "Запис за межами каталогу бібліотеки",
    "K1": "Виконання розкодованого коду",
    "K2": "Облікові дані та мережевий виклик в одному модулі",
    "K3": "Новий файл .pth з інструкцією import",
    "K4": "Бібліотека або залежність у базі шкідливих бібліотек",
    "K5": "Читання файлів-приманок",
}

CRITICAL_CODES = {"K1", "K2", "K3", "K4", "K5"}

# Коди завершення програми для CI/CD
EXIT_ALLOW = 0
EXIT_WARN = 1
EXIT_BLOCK = 2
EXIT_ERROR = 3


@dataclass
class Evidence:
    """Доказ спрацювання індикатора (підрозділ 2.3)."""

    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


NO_WEIGHTS: Dict[str, float] = defaultdict(float)


@dataclass
class Indicator:
    """Індикатор безпеки: ознака x_k ∈ {0, 1} (спрацював чи ні) і докази.

    Індикатори не дають числової оцінки: вони лише фіксують, що ознака спрацювала.
    Поле value зберігається для внутрішніх потреб (наприклад, інтенсивність ентропії),
    але рішення приймається лише за фактом спрацювання.
    """

    code: str
    value: float = 0.0
    weight: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    evaluated: bool = True
    note: Optional[str] = None

    @property
    def name(self) -> str:
        return INDICATOR_NAMES.get(self.code, self.code)

    @property
    def critical(self) -> bool:
        return self.code in CRITICAL_CODES

    @property
    def triggered(self) -> bool:
        return self.evaluated and self.value > 0

    def add(self, message: str, file: Optional[str] = None, line: Optional[int] = None,
            snippet: Optional[str] = None) -> None:
        self.evidence.append(Evidence(message, file, line, snippet))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "value": round(self.value, 4),
            "triggered": self.triggered,
            "critical": self.critical,
            "evaluated": self.evaluated,
            "note": self.note,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Author:
    """Автор змін між двома версіями."""

    login: Optional[str]
    name: str
    role: str  # maintainer | contributor | newcomer | unknown
    trust: float
    changed_lines: int
    commits: int = 0
    files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vulnerability:
    id: str
    package: str
    version: Optional[str]
    summary: str = ""
    severity: str = ""
    fixed: Optional[str] = None
    malicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PackageVersion:
    """Розпакована версія бібліотеки."""

    name: str
    version: Optional[str]
    root: Optional[Path] = None            # каталог з розпакованими файлами
    archives: List[Path] = field(default_factory=list)
    kind: str = ""                         # sdist | wheel | sdist+wheel
    requires: List[str] = field(default_factory=list)
    upload_time: Optional[str] = None


@dataclass
class Context:
    """Контекст аналізу одного оновлення (вхідні дані X, формула 2.1)."""

    name: str
    old: PackageVersion
    new: PackageVersion
    meta: Dict[str, Any] = field(default_factory=dict)        # M — метадані PyPI
    repo: Dict[str, Any] = field(default_factory=dict)        # G — дані репозиторію
    indicators: Dict[str, Indicator] = field(default_factory=dict)
    authors: List[Author] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    unmatched_lines: int = 0                                 # рядки у файлах, відсутніх у репозиторії
    changed_files: List[str] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)

    @property
    def is_new_dependency(self) -> bool:
        return self.old.version is None

    def ind(self, code: str, weight: float = 0.0) -> Indicator:
        if code not in self.indicators:
            self.indicators[code] = Indicator(code=code, weight=weight)
        return self.indicators[code]


@dataclass
class Report:
    """Звіт Z = (d, Da, L, F, V) (формула 2.2)."""

    package: str
    old_version: Optional[str]
    new_version: str
    decision: str          # allow | warn | block
    exit_code: int
    triggered_count: int   # кількість звичайних індикаторів, що спрацювали
    author_trust: Optional[float]   # Da — ступінь довіри до авторів змін
    level: str             # низький | середній | високий | критичний
    indicators: List[Indicator]
    vulnerabilities: List[Vulnerability]
    authors: List[Author]
    warnings: List[str]
    notes: List[str]
    dynamic_run: bool
    timings: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "decision": self.decision,
            "exit_code": self.exit_code,
            "triggered_count": self.triggered_count,
            "author_trust": None if self.author_trust is None else round(self.author_trust, 4),
            "danger_level": self.level,
            "dynamic_analysis": self.dynamic_run,
            "indicators": [i.to_dict() for i in self.indicators],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "authors": [a.to_dict() for a in self.authors],
            "warnings": self.warnings,
            "notes": self.notes,
            "timings_seconds": {k: round(v, 3) for k, v in self.timings.items()},
        }
