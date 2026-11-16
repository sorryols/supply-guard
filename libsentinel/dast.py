"""Етап 5. Динамічний аналіз в ізольованому контейнері Docker.

Нова версія бібліотеки встановлюється та імпортується в контейнері без мережі,
без привілеїв і з обмеженням часу. Системні виклики фіксуються strace.

B1 — мережеві з'єднання з недозволеними хостами;
B2 — запуск оболонки чи інших програм;
B3 — запис за межами каталогу бібліотеки;
К5 — читання файлів-приманок.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Context

SANDBOX_DIR = Path(__file__).resolve().parent / "sandbox"

RE_LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
RE_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
RE_INET = re.compile(r'sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)')
RE_INET6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"')

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "busybox"}

# Внутрішні програми компілятора C/C++, які запускаються під час збирання розширень
TOOLCHAIN = re.compile(r"^((x86_64|aarch64)-linux-gnu-)?(gcc|g\+\+|cc|c\+\+|cpp|ld|ld\.bfd|ld\.gold|as|ar|"
                       r"strip|cc1|cc1plus|collect2|lto-wrapper|lto1)(-\d+)?$")


def is_toolchain(path: str, name: str) -> bool:
    return bool(TOOLCHAIN.match(name)) or path.startswith(("/usr/lib/gcc/", "/usr/libexec/gcc/"))


@dataclass
class TraceEvent:
    pid: int
    call: str
    args: str
    ret: str
    phase: str

    @property
    def ok(self) -> bool:
        return self.ret != "?" and not self.ret.startswith("-")

    def first_str(self) -> Optional[str]:
        m = RE_STR.search(self.args)
        return m.group(1) if m else None


RE_PID = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(.*)$")


def parse_trace(text: str, phase: str) -> List[TraceEvent]:
    """Розбір журналу strace з урахуванням перерваних викликів (<unfinished ...>)."""
    events = []
    pending: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        m = RE_PID.match(line)
        if not m:
            continue
        pid, rest = m.group(1), m.group(2)
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")].rstrip()
            continue
        r = re.match(r"^<\.\.\. \w+ resumed>\s*(.*)$", rest)
        if r:
            rest = pending.pop(pid, "") + r.group(1)
        m2 = RE_LINE.match(f"{pid} {rest}")
        if m2:
            events.append(TraceEvent(int(m2.group(1)), m2.group(2), m2.group(3), m2.group(4), phase))
    return events


@dataclass
class DastFindings:
    connections: List[Tuple[str, str, str]] = field(default_factory=list)   # (host, port, phase)
    programs: List[Tuple[str, str, str]] = field(default_factory=list)      # (name, cmdline, phase)
    writes: List[Tuple[str, str]] = field(default_factory=list)             # (path, phase)
    honeypot_reads: List[Tuple[str, str]] = field(default_factory=list)     # (path, phase)


def analyze_events(events: List[TraceEvent], info: Dict[str, Any], cfg: Dict[str, Any]) -> DastFindings:
    dcfg = cfg["dast"]
    allowed_prog = set(dcfg["allowed_programs"])
    allowed_hosts = set(dcfg["allowed_hosts"])
    honeypots = set(info.get("honeypots", []))
    home = info.get("home", "/home/sandbox")
    venv = info.get("venv", "/tmp/venv")
    allowed_write = ("/tmp/", "/out/", "/dev/", "/proc/", venv + "/", f"{home}/.cache/")
    f = DastFindings()
    seen = set()
    for e in events:
        if e.call == "execve":
            path = e.first_str() or ""
            name = path.rsplit("/", 1)[-1]
            base = re.sub(r"[-\d.]+$", "", name)  # python3.12 -> python, gcc-12 -> gcc
            if not name or path.startswith(venv) or name in allowed_prog or base in allowed_prog \
                    or is_toolchain(path, name):
                continue
            argv = RE_STR.findall(e.args.split("]", 1)[0]) if "[" in e.args else []
            key = ("exec", name)
            if key not in seen and (e.ok or name in SHELLS or name in ("curl", "wget", "nc", "ncat")):
                seen.add(key)
                f.programs.append((name, " ".join(argv[:6])[:200], e.phase))
        elif e.call == "connect":
            for rx in (RE_INET, RE_INET6):
                m = rx.search(e.args)
                if m:
                    port, host = m.group(1), m.group(2)
                    if host not in allowed_hosts and ("conn", host, port) not in seen:
                        seen.add(("conn", host, port))
                        f.connections.append((host, port, e.phase))
        elif e.call in ("openat", "open", "creat"):
            path = e.first_str() or ""
            if path in honeypots and e.ok:
                if ("hp", path) not in seen:
                    seen.add(("hp", path))
                    f.honeypot_reads.append((path, e.phase))
                continue
            is_write = e.call == "creat" or re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC", e.args)
            if is_write and path.startswith("/") and not path.startswith(allowed_write) and e.ok:
                if ("w", path) not in seen:
                    seen.add(("w", path))
                    f.writes.append((path, e.phase))
        elif e.call in ("rename", "renameat", "renameat2", "unlink", "unlinkat", "mkdir", "mkdirat"):
            strs = RE_STR.findall(e.args)
            path = strs[-1] if strs else ""
            if path.startswith("/") and not path.startswith(allowed_write) and e.ok and ("w", path) not in seen:
                seen.add(("w", path))
                f.writes.append((path, e.phase))
    return f


def docker_available() -> Tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "Docker не встановлено"
    try:
        p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"Docker недоступний: {e}"
    if p.returncode != 0:
        return False, "Docker-демон недоступний (перевірте, що користувач у групі docker)"
    return True, p.stdout.strip()


def image_exists(image: str) -> bool:
    p = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
    return p.returncode == 0


def build_image(image: str) -> Tuple[bool, str]:
    p = subprocess.run(["docker", "build", "-t", image, str(SANDBOX_DIR)], capture_output=True, text=True)
    return p.returncode == 0, (p.stdout + p.stderr)[-2000:]


def pick_archive(archives: List[Path]) -> Optional[Path]:
    """Перевага — sdist, оскільки лише він виконує код збирання."""
    sd = [a for a in archives if not a.name.endswith(".whl")]
    return (sd or archives or [None])[0]


def run_container(archive: Path, cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], str, str]:
    dcfg = cfg["dast"]
    out = Path(tempfile.mkdtemp(prefix="libsentinel-dast-"))
    out.chmod(0o777)
    pkgdir = Path(tempfile.mkdtemp(prefix="libsentinel-pkg-"))
    shutil.copy2(archive, pkgdir / archive.name)
    pkgdir.chmod(0o755)
    (pkgdir / archive.name).chmod(0o644)
    cmd = ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", str(dcfg["pids_limit"]),
           "--memory", str(dcfg["memory"]), "--read-only",
           "--tmpfs", "/tmp:rw,exec,size=1g,mode=1777", "--tmpfs", "/home/sandbox:rw,exec,size=256m,uid=1000,gid=1000",
           "-v", f"{pkgdir}:/pkg:ro", "-v", f"{out}:/out:rw"]
    if dcfg.get("runtime"):
        cmd += ["--runtime", dcfg["runtime"]]
    timeout = int(dcfg["timeout_seconds"])
    cmd += [dcfg["image"], f"/pkg/{archive.name}", str(timeout - 20)]
    info: Dict[str, Any] = {}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        if p.returncode != 0:
            info["container_error"] = (p.stderr or p.stdout).strip().splitlines()[-1:] or [f"код {p.returncode}"]
    except subprocess.TimeoutExpired:
        info["container_timeout"] = True
        info["install_timeout"] = True
    rf = out / "result.json"
    if rf.exists():
        info.update(json.loads(rf.read_text()))
    install = (out / "install.trace").read_text(errors="replace") if (out / "install.trace").exists() else ""
    imp = (out / "import.trace").read_text(errors="replace") if (out / "import.trace").exists() else ""
    shutil.rmtree(out, ignore_errors=True)
    shutil.rmtree(pkgdir, ignore_errors=True)
    return info, install, imp


def apply_findings(ctx: Context, f: DastFindings, info: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    w = cfg["weights"]
    B1, B2, B3, K5 = ctx.ind("B1", w["B1"]), ctx.ind("B2", w["B2"]), ctx.ind("B3", w["B3"]), ctx.ind("K5")
    phase_ua = {"install": "встановлення", "import": "імпорт"}
    for host, port, ph in f.connections[:10]:
        B1.value = 1.0
        B1.add(f"connect() до {host}:{port} (фаза: {phase_ua.get(ph, ph)})")
    for name, argv, ph in f.programs[:10]:
        B2.value = 1.0
        B2.add(f"execve({name}) {argv} (фаза: {phase_ua.get(ph, ph)})")
    for path, ph in f.writes[:10]:
        B3.value = 1.0
        B3.add(f"Запис у {path} (фаза: {phase_ua.get(ph, ph)})")
    for path, ph in f.honeypot_reads:
        K5.value = 1.0
        K5.add(f"Прочитано файл-приманку {path} (фаза: {phase_ua.get(ph, ph)})")
    if info.get("install_timeout") or info.get("container_timeout") or info.get("import_timeout"):
        ctx.notes.append("Динамічний аналіз: перевищено ліміт часу (код міг навмисно затримувати виконання)")
    if info.get("install_rc") not in (0, None):
        ctx.notes.append(f"Динамічний аналіз: встановлення завершилося з кодом {info.get('install_rc')}")


def run(ctx: Context, cfg: Dict[str, Any]) -> bool:
    """Повертає True, якщо динамічний аналіз виконано."""
    w = cfg["weights"]
    for code in ("B1", "B2", "B3"):
        ctx.ind(code, w[code])
    ctx.ind("K5")
    ok, msg = docker_available()
    if not ok:
        for code in ("B1", "B2", "B3", "K5"):
            ctx.indicators[code].evaluated = False
            ctx.indicators[code].note = msg
        ctx.notes.append(f"Динамічний аналіз пропущено: {msg}")
        return False
    image = cfg["dast"]["image"]
    if not image_exists(image):
        built, log = build_image(image)
        if not built:
            for code in ("B1", "B2", "B3", "K5"):
                ctx.indicators[code].evaluated = False
            ctx.notes.append(f"Не вдалося зібрати образ пісочниці {image}: {log[-300:]}")
            return False
    archive = pick_archive(ctx.new.archives)
    if archive is None:
        ctx.notes.append("Динамічний аналіз пропущено: немає архіву нової версії")
        return False
    info, install_tr, import_tr = run_container(archive, cfg)
    if "install_rc" not in info and not info.get("install_timeout"):
        for code in ("B1", "B2", "B3", "K5"):
            ctx.indicators[code].evaluated = False
            ctx.indicators[code].note = "пісочниця не повернула результат"
        ctx.notes.append("Динамічний аналіз не вдався: контейнер не повернув результат "
                         f"({info.get('container_error', 'перевірте libsentinel doctor')})")
        return False
    events = parse_trace(install_tr, "install") + parse_trace(import_tr, "import")
    ctx.meta["dast"] = {"archive": archive.name, "events": len(events), "modules": info.get("modules", []),
                        "install_rc": info.get("install_rc")}
    findings = analyze_events(events, info, cfg)
    apply_findings(ctx, findings, info, cfg)
    return True
