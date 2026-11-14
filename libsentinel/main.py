"""Інтерфейс командного рядка LibSentinel.

Приклади:
  libsentinel analyze requests --from 2.31.0 --to 2.32.3
  libsentinel analyze somepkg==1.0.0                      # нова залежність
  libsentinel requirements --git-base origin/main --file requirements.txt --sarif out.sarif
  libsentinel doctor
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .analyzer import Analyzer, error_result
from .cache import Cache, default_cache_dir
from .config import load_config
from .models import EXIT_ERROR
from .net import NetError
from .report import render_console, render_summary, to_json, to_sarif, use_color
from .reqdiff import diff_requirements, git_show


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="Файл конфігурації YAML (ваги, пороги, рівні довіри)")
    p.add_argument("--json", metavar="FILE", help="Зберегти повний звіт у JSON")
    p.add_argument("--sarif", metavar="FILE", help="Зберегти звіт у SARIF (GitHub Code Scanning)")
    p.add_argument("--dast", choices=["auto", "always", "never"], default="auto",
                   help="Динамічний аналіз: auto — за умовою методу (типово), always, never")
    p.add_argument("--offline", action="store_true", help="Не звертатися до PyPI/GitHub/OSV (лише локальні архіви)")
    p.add_argument("--no-cache", action="store_true", help="Не використовувати кеш результатів")
    p.add_argument("--no-color", action="store_true", help="Вивід без кольорів")
    p.add_argument("-v", "--verbose", action="store_true", help="Показати всі докази")
    p.add_argument("-q", "--quiet", action="store_true", help="Лише підсумковий рядок")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="libsentinel",
                                 description="Аналіз безпеки оновлень бібліотек з відкритим кодом (PyPI)")
    ap.add_argument("--version", action="version", version=f"LibSentinel {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Аналіз оновлення однієї бібліотеки")
    a.add_argument("package", help="Назва бібліотеки або назва==версія для нової залежності")
    a.add_argument("--from", dest="old", help="Поточна версія v0 (не вказується для нової залежності)")
    a.add_argument("--to", dest="new", help="Нова версія v1")
    a.add_argument("--old-archive", nargs="+", type=Path, help="Локальні архіви поточної версії")
    a.add_argument("--new-archive", nargs="+", type=Path, help="Локальні архіви нової версії")
    _common(a)

    r = sub.add_parser("requirements", help="Перевірка змін у файлі залежностей")
    r.add_argument("--file", default="requirements.txt", help="Файл залежностей (нова версія)")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--old", help="Старий файл залежностей")
    g.add_argument("--git-base", help="Git-посилання на базову версію (наприклад origin/main)")
    r.add_argument("--fail-on", choices=["block", "warn"], default="block",
                   help="Коли повертати ненульовий код у CI: block (типово) або warn")
    _common(r)

    sub.add_parser("sandbox-build", help="Зібрати Docker-образ пісочниці для динамічного аналізу")
    sub.add_parser("update-data", help="Оновити список популярних бібліотек і базу OpenSSF Malicious Packages")
    sub.add_parser("doctor", help="Перевірити середовище (Docker, мережа, токен GitHub)")
    sub.add_parser("cache-clear", help="Очистити кеш")
    return ap


def _write_outputs(args, results: List[Dict[str, Any]], req_file=None, lines=None) -> None:
    if args.json:
        Path(args.json).write_text(to_json(results if len(results) != 1 or req_file else results[0]), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(results, req_file, lines), ensure_ascii=False, indent=2),
                                    encoding="utf-8")


def cmd_analyze(args, cfg) -> int:
    pkg, old, new = args.package, args.old, args.new
    if "==" in pkg:
        pkg, new = pkg.split("==", 1)
    if not new:
        print("Вкажіть нову версію: --to ВЕРСІЯ або назва==версія", file=sys.stderr)
        return EXIT_ERROR
    an = Analyzer(cfg, use_cache=not args.no_cache)
    try:
        res = an.analyze(pkg, old, new, dast_mode=args.dast, offline=args.offline,
                         old_archives=args.old_archive, new_archives=args.new_archive, force=args.no_cache)
    except (NetError, OSError, ValueError) as e:
        res = error_result(pkg, old, new, str(e))
    color = use_color(False if args.no_color else None)
    if args.quiet:
        print(render_summary([res], color))
    else:
        print(render_console(res, color, args.verbose))
    _write_outputs(args, [res])
    return int(res["exit_code"])


def cmd_requirements(args, cfg) -> int:
    new_path = Path(args.file)
    if not new_path.exists():
        print(f"Файл {new_path} не знайдено", file=sys.stderr)
        return EXIT_ERROR
    new_text = new_path.read_text(encoding="utf-8")
    try:
        old_text = Path(args.old).read_text(encoding="utf-8") if args.old else git_show(args.git_base, args.file)
    except (OSError, RuntimeError) as e:
        print(f"Не вдалося отримати попередню версію файлу: {e}", file=sys.stderr)
        return EXIT_ERROR
    changes, skipped = diff_requirements(old_text, new_text, new_path.parent)
    color = use_color(False if args.no_color else None)
    for s in skipped:
        print(f"  – {s}")
    if not changes:
        print("Змінених залежностей із закріпленими версіями не виявлено.")
        _write_outputs(args, [], str(new_path), {})
        return 0
    print(f"Виявлено змінених залежностей: {len(changes)}")
    an = Analyzer(cfg, use_cache=not args.no_cache)
    results = []
    lines = {}
    for ch in changes:
        lines[ch.name.lower()] = ch.line
        try:
            res = an.analyze(ch.name, ch.old, ch.new, dast_mode=args.dast, offline=args.offline,
                             force=args.no_cache)
        except (NetError, OSError, ValueError) as e:
            res = error_result(ch.name, ch.old, ch.new, str(e))
        results.append(res)
        if not args.quiet:
            print(render_console(res, color, args.verbose))
            print()
    print(render_summary(results, color))
    _write_outputs(args, results, str(new_path), lines)
    codes = [r["exit_code"] for r in results]
    if any(c == 2 for c in codes):
        return 2
    if any(c == EXIT_ERROR for c in codes):
        return EXIT_ERROR
    if args.fail_on == "warn" and any(c == 1 for c in codes):
        return 1
    return 0


def cmd_sandbox_build(cfg) -> int:
    from .dast import build_image, docker_available
    ok, msg = docker_available()
    if not ok:
        print(msg, file=sys.stderr)
        return EXIT_ERROR
    print(f"Збирання образу {cfg['dast']['image']} …")
    ok, log = build_image(cfg["dast"]["image"])
    print(log)
    print("Готово" if ok else "Помилка збирання образу")
    return 0 if ok else EXIT_ERROR


def cmd_update_data(cfg) -> int:
    import requests
    d = default_cache_dir()
    rc = 0
    try:
        r = requests.get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json", timeout=30)
        r.raise_for_status()
        names = [row["project"] for row in r.json()["rows"]][:5000]
        (d / "top_pypi.txt").write_text("\n".join(names), encoding="utf-8")
        print(f"Список популярних бібліотек оновлено: {len(names)} назв")
    except Exception as e:  # noqa: BLE001
        print(f"Не вдалося оновити список популярних бібліотек: {e}")
        rc = 1
    target = Path(cfg["deps"].get("ossf_dir") or d / "malicious-packages").expanduser()
    if not shutil.which("git"):
        print("git не встановлено — базу OpenSSF Malicious Packages не завантажено")
        return 1
    if (target / ".git").exists():
        p = subprocess.run(["git", "-C", str(target), "pull", "--depth", "1"], capture_output=True, text=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        p = subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                            "https://github.com/ossf/malicious-packages.git", str(target)], capture_output=True, text=True)
        if p.returncode == 0:
            p = subprocess.run(["git", "-C", str(target), "sparse-checkout", "set", "osv/malicious/pypi"],
                               capture_output=True, text=True)
    if p.returncode == 0:
        n = len(list((target / "osv" / "malicious" / "pypi").glob("*")))
        print(f"База OpenSSF Malicious Packages (PyPI) оновлена: {n} пакетів у {target}")
    else:
        print(f"Помилка git: {p.stderr.strip()}")
        rc = 1
    return rc


def cmd_doctor(cfg) -> int:
    import requests
    from .dast import docker_available, image_exists
    ok_all = True

    def line(ok, what, detail=""):
        nonlocal ok_all
        ok_all &= ok
        print(f"  [{'OK' if ok else '!!'}] {what}{(' — ' + detail) if detail else ''}")

    print(f"LibSentinel {__version__}, Python {sys.version.split()[0]}")
    for name, url in [("PyPI", "https://pypi.org/pypi/pip/json"), ("GitHub API", "https://api.github.com/rate_limit"),
                      ("OSV", "https://api.osv.dev/v1/vulns/GHSA-9wx4-h78v-vm56")]:
        try:
            code = requests.get(url, timeout=10).status_code
            line(code == 200, name, f"HTTP {code}")
        except Exception as e:  # noqa: BLE001
            line(False, name, str(e)[:80])
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    line(bool(tok), "GITHUB_TOKEN", "задано" if tok else "не задано: ліміт 60 запитів/год, менш точна оцінка авторів")
    dok, msg = docker_available()
    line(dok, "Docker", msg)
    if dok:
        img = cfg["dast"]["image"]
        line(image_exists(img), f"Образ пісочниці {img}", "" if image_exists(img) else "виконайте: libsentinel sandbox-build")
    ossf = Path(cfg["deps"].get("ossf_dir") or default_cache_dir() / "malicious-packages") / "osv" / "malicious" / "pypi"
    line(ossf.exists(), "Локальна база OpenSSF Malicious Packages", "" if ossf.exists() else "виконайте: libsentinel update-data")
    return 0 if ok_all else 1


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(getattr(args, "config", None))
    if args.cmd == "analyze":
        return cmd_analyze(args, cfg)
    if args.cmd == "requirements":
        return cmd_requirements(args, cfg)
    if args.cmd == "sandbox-build":
        return cmd_sandbox_build(cfg)
    if args.cmd == "update-data":
        return cmd_update_data(cfg)
    if args.cmd == "doctor":
        return cmd_doctor(cfg)
    if args.cmd == "cache-clear":
        Cache().clear()
        print("Кеш очищено")
        return 0
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
