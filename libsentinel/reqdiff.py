"""Режим перевірки файлу залежностей: порівняння старого і нового requirements.txt."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


@dataclass
class Pin:
    name: str
    version: Optional[str]
    line: int
    raw: str


@dataclass
class Change:
    name: str
    old: Optional[str]     # None — нова залежність
    new: str
    line: int


def parse_requirements(text: str, base_dir: Optional[Path] = None, _depth: int = 0) -> Dict[str, Pin]:
    pins: Dict[str, Pin] = {}
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")) and base_dir and _depth < 5:
            inc = base_dir / line.split(None, 1)[1].strip()
            if inc.exists():
                pins.update(parse_requirements(inc.read_text(encoding="utf-8"), inc.parent, _depth + 1))
            continue
        if line.startswith("-") or "://" in line:
            continue
        line = re.sub(r"\s*\\$", "", line)
        line = line.split(" --hash", 1)[0]
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        version = None
        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "==="):
            version = specs[0].version
        pins[canonicalize_name(req.name)] = Pin(req.name, version, i, raw)
    return pins


def git_show(ref: str, path: str) -> str:
    p = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    if p.returncode != 0:
        # файлу могло не бути в базовій гілці
        if "does not exist" in p.stderr or "exists on disk, but not in" in p.stderr:
            return ""
        raise RuntimeError(f"git show {ref}:{path}: {p.stderr.strip()}")
    return p.stdout


def diff_requirements(old_text: str, new_text: str, base_dir: Optional[Path] = None
                      ) -> Tuple[List[Change], List[str]]:
    old = parse_requirements(old_text, base_dir)
    new = parse_requirements(new_text, base_dir)
    changes: List[Change] = []
    skipped: List[str] = []
    for key, pin in sorted(new.items()):
        if pin.version is None:
            if key not in old or old[key].raw.strip() != pin.raw.strip():
                skipped.append(f"{pin.name}: версію не закріплено через ==, аналіз пропущено")
            continue
        prev = old.get(key)
        if prev is None:
            changes.append(Change(pin.name, None, pin.version, pin.line))
        elif prev.version != pin.version:
            changes.append(Change(pin.name, prev.version, pin.version, pin.line))
    return changes, skipped
