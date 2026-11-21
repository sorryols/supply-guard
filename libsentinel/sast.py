"""Етап 3. Аналіз різниці між версіями та статичний аналіз змін.

S1 — зміна коду, що виконується під час встановлення;
S2 — нові небезпечні виклики (eval, exec, compile, subprocess, os.system, динамічний імпорт);
S3 — нові мережеві можливості в коді встановлення або імпорту;
S4 — доступ до чутливих даних (токени, ключі, облікові дані);
S5 — рядки з високою ентропією;
S6 — файли бібліотеки, відсутні в репозиторії;
К1 — виконання розкодованого коду; К2 — облікові дані та мережевий виклик в одному модулі;
К3 — новий файл .pth з інструкцією import.
Код бібліотеки НЕ виконується — лише розбирається модулем ast.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from .models import Context, NO_WEIGHTS

# --- категорії можливостей коду -----------------------------------------
NETWORK_CALLS = {
    "socket.socket", "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname",
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve",
    "urllib.urlopen", "urllib2.urlopen",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL", "telnetlib.Telnet",
}
NETWORK_PREFIXES = ("requests.", "httpx.", "aiohttp.", "urllib3.", "pycurl.", "websocket.", "dns.resolver.")

PROCESS_CALLS = {
    "os.system", "os.popen", "os.execv", "os.execve", "os.execl", "os.execle", "os.execlp", "os.execvp",
    "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnve", "os.posix_spawn", "os.startfile",
    "pty.spawn", "commands.getoutput", "commands.getstatusoutput",
}
PROCESS_PREFIXES = ("subprocess.",)

DYNEXEC_CALLS = {"eval", "exec", "compile", "__import__", "importlib.import_module", "marshal.loads",
                 "builtins.exec", "builtins.eval"}
EXEC_CALLS = {"eval", "exec", "builtins.exec", "builtins.eval", "compile"}

DECODE_CALLS = {
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.urlsafe_b64decode", "base64.decodebytes", "codecs.decode", "zlib.decompress", "gzip.decompress",
    "bz2.decompress", "lzma.decompress", "bytes.fromhex", "binascii.unhexlify", "binascii.a2b_base64",
    "marshal.loads",
}

SENSITIVE_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|"
                           r"AWS_|GITHUB|GH_|NPM_|PYPI|TWINE|AZURE_|GOOGLE_APPLICATION|DOCKER_AUTH)", re.I)
SENSITIVE_PATHS = [".ssh", "id_rsa", "id_ed25519", ".aws", ".pypirc", ".npmrc", ".netrc", ".git-credentials",
                   ".docker/config.json", ".kube/config", ".gnupg", "/etc/shadow", "/etc/passwd",
                   "Login Data", "Local State", "wallet.dat", ".bash_history", ".config/gh/hosts.yml"]

INSTALL_FILES = re.compile(r"^(setup\.py|[^/]*build[^/]*\.py|setup_[^/]*\.py)$")


def is_install_file(form: str, rel: str) -> bool:
    return form == "sdist" and INSTALL_FILES.match(rel) is not None


# Каталоги sdist, що не встановлюються і не імпортуються (приклади, тести, документація)
NON_INSTALLED = re.compile(r"^(src/)?(examples?|tests?|testing|docs?|benchmarks?|bench|\.github|ci|tools|"
                           r"demos?|samples?|notebooks?)/")
# Код, що виконується під час `import бібліотека`: __init__.py бібліотеки верхнього рівня або модуль верхнього рівня
IMPORT_ENTRY = re.compile(r"^(src/)?([^/]+/__init__\.py|[^/]+\.py)$")


def is_generated_metadata(text: str) -> bool:
    """Файл, згенерований системою збирання (setuptools-scm, hatch-vcs): лише присвоєння констант.

    Такі файли (_version.py, _dist_ver.py тощо) закономірно відсутні в репозиторії.
    """
    if len(text) > 2000:
        return False
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue                                       # docstring
        if isinstance(node, ast.ImportFrom) and node.module in ("__future__", "typing"):
            continue
        if isinstance(node, ast.Import) and all(a.name == "typing" for a in node.names):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None or all(isinstance(n, (ast.Constant, ast.Tuple, ast.List, ast.Name, ast.Load,
                                                   ast.UnaryOp, ast.USub)) for n in ast.walk(value)):
                continue
        if isinstance(node, ast.If):                       # if TYPE_CHECKING: ...
            continue
        return False
    return True


def is_non_installed(form: str, rel: str) -> bool:
    return form == "sdist" and NON_INSTALLED.match(rel) is not None


def is_import_entry(rel: str) -> bool:
    return IMPORT_ENTRY.match(rel) is not None and not INSTALL_FILES.match(rel)


@dataclass
class Hit:
    kind: str
    line: int
    snippet: str
    import_time: bool = False


@dataclass
class FileFacts:
    hits: List[Hit] = field(default_factory=list)
    strings: List[Tuple[int, str]] = field(default_factory=list)
    decode_exec: List[Hit] = field(default_factory=list)
    parse_error: Optional[str] = None

    def kinds(self) -> Set[str]:
        return {h.kind for h in self.hits}

    def by_kind(self, prefix: str) -> List[Hit]:
        return [h for h in self.hits if h.kind == prefix or h.kind.startswith(prefix + ":")]


# --- розбір коду ---------------------------------------------------------
class _Visitor(ast.NodeVisitor):
    def __init__(self, src_lines: List[str]):
        self.lines = src_lines
        self.alias: Dict[str, str] = {}
        self.facts = FileFacts()
        self.depth = 0          # глибина вкладеності у функції
        self.decoded_names: Set[str] = set()

    # ---- допоміжне
    def _snip(self, node: ast.AST) -> str:
        ln = getattr(node, "lineno", 0)
        if 0 < ln <= len(self.lines):
            return self.lines[ln - 1].strip()[:160]
        return ""

    def _hit(self, kind: str, node: ast.AST) -> None:
        self.facts.hits.append(Hit(kind, getattr(node, "lineno", 0), self._snip(node), self.depth == 0))

    def resolve(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            # __import__('base64').b64decode
            fn = self.resolve(node.func)
            if fn in ("__import__", "importlib.import_module") and node.args and \
                    isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
        return None

    # ---- імпорти
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.alias[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            self.alias[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    # ---- функції: код усередині не виконується під час імпорту
    def _func(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func
    visit_Lambda = _func

    def visit_If(self, node: ast.If) -> None:
        # блок if __name__ == "__main__" не виконується під час імпорту
        t = node.test
        if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__":
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1
            return
        self.generic_visit(node)

    # ---- присвоєння результату розкодування
    def visit_Assign(self, node: ast.Assign) -> None:
        if self._contains_decode(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.decoded_names.add(t.id)
        self.generic_visit(node)

    def _contains_decode(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = self.resolve(sub.func) or ""
                if fn in DECODE_CALLS or fn.endswith(".decompress") or fn.endswith("b64decode"):
                    return True
                if isinstance(sub.func, ast.Attribute) and sub.func.attr in ("decode",) and sub.args and \
                        isinstance(sub.args[0], ast.Constant) and str(sub.args[0].value).lower() in ("base64", "hex", "rot13", "rot_13", "zlib"):
                    return True
            if isinstance(sub, ast.Name) and sub.id in self.decoded_names:
                return True
        return False

    # ---- виклики
    def visit_Call(self, node: ast.Call) -> None:
        fn = self.resolve(node.func) or ""
        if fn in NETWORK_CALLS or fn.startswith(NETWORK_PREFIXES):
            self._hit("network", node)
        if fn in PROCESS_CALLS or fn.startswith(PROCESS_PREFIXES):
            self._hit("process", node)
        if fn in DYNEXEC_CALLS:
            self._hit("dynexec", node)
        if fn in DECODE_CALLS:
            self._hit("decode", node)
        if fn in EXEC_CALLS and any(self._contains_decode(a) for a in node.args):
            self.facts.decode_exec.append(Hit("decode_exec", node.lineno, self._snip(node), self.depth == 0))
        # доступ до змінних середовища
        if fn in ("os.getenv", "os.environ.get", "os.environ.pop", "os.environ.setdefault") and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and SENSITIVE_ENV.search(a0.value):
                self._hit(f"sensitive:env:{a0.value}", node)
        if fn in ("os.environ.items", "os.environ.copy", "os.environ.values") or \
                (fn == "dict" and node.args and self.resolve(node.args[0]) == "os.environ"):
            self._hit("sensitive:env:*", node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.resolve(node.value) == "os.environ":
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and SENSITIVE_ENV.search(key.value):
                self._hit(f"sensitive:env:{key.value}", node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            s = node.value
            self.facts.strings.append((getattr(node, "lineno", 0), s))
            for p in SENSITIVE_PATHS:
                if p in s and len(s) < 300:
                    self._hit(f"sensitive:path:{p}", node)
                    break


def analyze_source(src: str) -> FileFacts:
    lines = src.splitlines()
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError) as e:
        f = FileFacts(parse_error=str(e))
        # для нерозібраного файлу збираємо довгі рядки для оцінки ентропії
        for i, ln in enumerate(lines, 1):
            for tok in re.findall(r"[A-Za-z0-9+/=_\-]{40,}", ln):
                f.strings.append((i, tok))
        return f
    v = _Visitor(lines)
    v.visit(tree)
    return v.facts


def shannon_entropy(s: str) -> float:
    """Ентропія Шеннона рядка (біт на символ)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


# --- робота з файлами бібліотеки ---------------------------------------------
def list_files(root: Optional[Path]) -> Dict[str, Path]:
    """Ключ — «форма/відносний шлях», наприклад sdist/pkg/__init__.py."""
    out: Dict[str, Path] = {}
    if not root or not root.exists():
        return out
    for form in ("sdist", "wheel"):
        base = root / form
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file():
                out[f"{form}/{p.relative_to(base).as_posix()}"] = p
    return out


def _read(p: Path, limit: int = 2_000_000) -> str:
    try:
        data = p.read_bytes()[:limit]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _rel(key: str) -> str:
    return key.split("/", 1)[1]


def _changed_lines(old: str, new: str) -> int:
    if not old:
        return len(new.splitlines())
    sm = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal")


def _pth_imports(text: str) -> List[Tuple[int, str]]:
    return [(i, ln.strip()) for i, ln in enumerate(text.splitlines(), 1)
            if ln.startswith(("import ", "import\t"))]


def _build_system(text: str) -> str:
    """Вміст секцій [build-system] і [tool.*.cmdclass]/hooks з pyproject.toml для порівняння."""
    keep, out = False, []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("["):
            keep = s.startswith("[build-system") or "hooks" in s or "cmdclass" in s
        if keep:
            out.append(s)
    return "\n".join(out)


def run(ctx: Context, cfg: Dict, present_in_repo: Optional[Callable[[str], bool]] = None) -> None:
    w = NO_WEIGHTS  # у методі індикатори не мають ваг
    scfg = cfg["sast"]
    for code in ("S1", "S2", "S3", "S4", "S5", "S6"):
        ctx.ind(code, w[code])
    for code in ("K1", "K2", "K3"):
        ctx.ind(code)

    old_files = list_files(ctx.old.root)
    new_files = list_files(ctx.new.root)

    # Дедуплікація: файл wheel, ідентичний файлу sdist, аналізується один раз
    sdist_hashes = {_digest(p) for k, p in new_files.items() if k.startswith("sdist/") and k.endswith(".py")}

    changed: List[str] = []
    for key, p in new_files.items():
        if key.startswith("wheel/") and key.endswith(".py") and _digest(p) in sdist_hashes:
            continue
        if key not in old_files or _digest(old_files[key]) != _digest(p):
            changed.append(key)
    removed = [k for k in old_files if k not in new_files]
    ctx.changed_files = changed
    ctx.meta["diff"] = {"changed_or_added": len(changed), "removed": len(removed),
                        "files_old": len(old_files), "files_new": len(new_files)}

    # Можливості всієї попередньої версії (для порівняння з новими файлами)
    old_facts: Dict[str, FileFacts] = {}
    old_all_kinds: Set[str] = set()
    for k, p in old_files.items():
        if k.endswith(".py"):
            f = analyze_source(_read(p))
            old_facts[_rel(k)] = f
            old_all_kinds |= f.kinds()

    S1, S2, S3, S4, S5, S6 = (ctx.indicators[c] for c in ("S1", "S2", "S3", "S4", "S5", "S6"))
    K1, K2, K3 = (ctx.indicators[c] for c in ("K1", "K2", "K3"))

    for key in sorted(changed):
        p = new_files[key]
        rel = _rel(key)
        form = key.split("/", 1)[0]
        text = _read(p)
        old_text = _read(old_files[key]) if key in old_files else ""
        nlines = _changed_lines(old_text, text)

        # S6 — файл коду відсутній у репозиторії (крім згенерованих файлів з номером версії)
        if present_in_repo is not None and not present_in_repo(rel) and not is_generated_metadata(text):
            S6.value = 1.0
            S6.add("Файл є в бібліотеці, але відсутній у репозиторії на теґу версії", file=key)
            ctx.unmatched_lines += nlines

        # К3 — новий .pth з import
        if rel.endswith(".pth"):
            imports = _pth_imports(text)
            old_imports = _pth_imports(old_text)
            if imports and imports != old_imports:
                K3.value = 1.0
                for ln, s in imports[:3]:
                    K3.add("Рядок .pth виконується під час кожного запуску інтерпретатора", key, ln, s)
            continue

        # S1 — код встановлення
        is_install = is_install_file(form, rel)
        if form == "sdist" and rel == "pyproject.toml":
            if _build_system(text) != _build_system(old_text):
                if not ctx.is_new_dependency:
                    S1.value = 1.0
                    S1.add("Змінено налаштування системи збирання в pyproject.toml", key)
            continue

        if not rel.endswith(".py"):
            continue

        facts = analyze_source(text)
        if is_non_installed(form, rel):
            # приклади, тести й документація не встановлюються — некритичні ознаки не враховуються
            facts.hits = []
            facts.strings = []
        elif ctx.is_new_dependency and not is_install_file(form, rel):
            # для нової залежності враховується лише код, що виконується під час `import бібліотека`
            facts.hits = [h for h in facts.hits if h.import_time] if is_import_entry(rel) else []
        if facts.parse_error:
            ctx.notes.append(f"Файл {key} не вдалося розібрати як код Python ({facts.parse_error}); "
                             f"перевірено лише ентропію")
        prev = old_facts.get(rel)
        prev_kinds = prev.kinds() if prev else old_all_kinds
        new_kinds = facts.kinds() - prev_kinds

        if is_install:
            risky = [h for h in facts.hits if h.kind in ("network", "process", "dynexec", "decode")
                     or h.kind.startswith("sensitive")]
            if not ctx.is_new_dependency or risky:
                S1.value = 1.0
                msg = "Змінено код, що виконується під час встановлення" if not ctx.is_new_dependency \
                    else "Код встановлення нової залежності містить небезпечні можливості"
                S1.add(f"{msg} (змінено рядків: {nlines})", key)

        # S2 — нові небезпечні виклики
        for kind in ("process", "dynexec"):
            if kind in new_kinds:
                S2.value = 1.0
                for h in facts.by_kind(kind)[:3]:
                    S2.add(f"Нова можливість «{kind}»", key, h.line, h.snippet)

        # S3 — нові мережеві можливості в коді встановлення або імпорту
        if "network" in new_kinds:
            hits = [h for h in facts.by_kind("network") if h.import_time or is_install]
            if hits:
                S3.value = 1.0
                for h in hits[:3]:
                    S3.add("Мережевий виклик у коді, що виконується під час встановлення/імпорту", key, h.line, h.snippet)

        # S4 — доступ до чутливих даних
        new_sensitive = [h for h in facts.hits if h.kind.startswith("sensitive") and h.kind in new_kinds]
        if new_sensitive:
            S4.value = 1.0
            for h in new_sensitive[:3]:
                S4.add(f"Доступ до чутливих даних ({h.kind.split(':', 1)[1]})", key, h.line, h.snippet)

        # К1 — виконання розкодованого коду
        for h in facts.decode_exec:
            K1.value = 1.0
            K1.add("Виконання результату розкодування", key, h.line, h.snippet)

        # К2 — облікові дані + мережа в одному модулі
        if new_sensitive and facts.by_kind("network"):
            K2.value = 1.0
            n = facts.by_kind("network")[0]
            K2.add(f"Модуль читає чутливі дані (рядок {new_sensitive[0].line}) і виконує мережевий виклик",
                   key, n.line, n.snippet)

        # S5 — рядки з високою ентропією
        old_strings = {s for _, s in prev.strings} if prev else set()
        for ln, s in facts.strings:
            if len(s) < scfg["entropy_min_length"] or s in old_strings:
                continue
            if sum(ch.isspace() for ch in s) > len(s) * 0.02:
                # текст природною мовою (docstring, повідомлення) — не закодоване навантаження
                continue
            h = shannon_entropy(s)
            x = (h - scfg["entropy_low"]) / (scfg["entropy_high"] - scfg["entropy_low"])
            x = max(0.0, min(1.0, x))
            if x > 0:
                if x > S5.value:
                    S5.value = round(x, 3)
                if len(S5.evidence) < 3:
                    S5.add(f"Рядок довжиною {len(s)} з ентропією {h:.2f} біт/символ", key, ln, s[:60] + "…")
