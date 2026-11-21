"""Скрипт, що виконується ВСЕРЕДИНІ ізольованого контейнера.

1. Створює файли-приманки з фіктивними обліковими даними та змінні середовища з фіктивними токенами.
2. Встановлює бібліотеку у віртуальне середовище під трасуванням strace (фаза встановлення).
3. Імпортує модулі верхнього рівня під трасуванням strace (фаза імпорту).
4. Записує результати в /out для аналізу на хості.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path("/out")
HOME = Path.home()
VENV = Path("/tmp/venv")
TRACE = ["strace", "-f", "-qq", "-s", "300",
         "-e", "trace=execve,connect,openat,open,creat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat"]

HONEYPOTS = {
    ".aws/credentials": "[default]\naws_access_key_id = AKIAFAKEFAKEFAKE0000\naws_secret_access_key = fake/fake/fake\n",
    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktZm9yLWxpYnNlbnRpbmVs\n-----END OPENSSH PRIVATE KEY-----\n",
    ".pypirc": "[pypi]\nusername = __token__\npassword = pypi-FAKE-TOKEN-LIBSENTINEL\n",
    ".npmrc": "//registry.npmjs.org/:_authToken=npm_FAKEFAKEFAKEFAKE\n",
    ".git-credentials": "https://user:ghp_FAKEFAKEFAKEFAKEFAKE@github.com\n",
    ".docker/config.json": '{"auths": {"https://index.docker.io/v1/": {"auth": "ZmFrZTpmYWtl"}}}\n',
    ".config/gh/hosts.yml": "github.com:\n    oauth_token: gho_FAKEFAKEFAKE\n",
    ".kube/config": "apiVersion: v1\nkind: Config\nusers: [{name: fake, user: {token: fake}}]\n",
}
BAIT_ENV = {
    "GITHUB_TOKEN": "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
    "NPM_TOKEN": "npm_FAKEFAKEFAKEFAKEFAKEFAKE",
    "PYPI_TOKEN": "pypi-FAKE-LIBSENTINEL",
    "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKE0000",
    "AWS_SECRET_ACCESS_KEY": "fake/fake/fake/fake",
}


def plant_honeypots():
    paths = []
    for rel, content in HONEYPOTS.items():
        p = HOME / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        paths.append(str(p))
    return paths


def top_level_modules(site: Path):
    mods = set()
    for dist in site.glob("*.dist-info"):
        if dist.name.startswith(("pip-", "setuptools-", "wheel-")):
            continue
        tl = dist / "top_level.txt"
        if tl.exists():
            mods.update(x.strip() for x in tl.read_text().splitlines() if x.strip())
            continue
        rec = dist / "RECORD"
        if rec.exists():
            for line in rec.read_text().splitlines():
                path = line.split(",", 1)[0]
                first = path.split("/", 1)[0]
                if first.endswith((".dist-info", ".data")) or first.endswith(".pth") or first == "..":
                    continue
                if first.endswith(".py"):
                    mods.add(first[:-3])
                elif "/" in path:
                    mods.add(first)
    return sorted(m for m in mods if m.isidentifier())


def main():
    archive = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    result = {"archive": archive, "home": str(HOME), "venv": str(VENV)}
    result["honeypots"] = plant_honeypots()
    env = dict(os.environ, **BAIT_ENV, PIP_NO_INPUT="1", PIP_DISABLE_PIP_VERSION_CHECK="1")

    r = subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(VENV)], capture_output=True)
    if r.returncode != 0:
        # ensurepip може бути відсутнім — тоді pip береться із системних site-packages
        subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", "--without-pip", str(VENV)],
                       check=True)
    vpy = str(VENV / "bin" / "python")
    site = next((VENV / "lib").glob("python*/site-packages"))
    result["site_packages"] = str(site)

    # Фаза встановлення
    cmd = TRACE + ["-o", str(OUT / "install.trace"), vpy, "-m", "pip", "install", "--no-index", "--no-deps",
                   "--no-build-isolation", "--no-cache-dir", archive]
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
        result["install_rc"] = p.returncode
        result["install_log"] = (p.stdout + p.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        result["install_rc"] = None
        result["install_timeout"] = True

    # Фаза імпорту
    mods = top_level_modules(site)
    result["modules"] = mods
    if mods:
        code = "import importlib,sys\nfor m in %r:\n    try:\n        importlib.import_module(m)\n" \
               "    except BaseException as e:\n        print('IMPORT_ERROR', m, type(e).__name__, e)\n" % mods
        cmd = TRACE + ["-o", str(OUT / "import.trace"), vpy, "-c", code]
        try:
            p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=max(30, timeout // 2),
                               cwd="/tmp")
            result["import_log"] = (p.stdout + p.stderr)[-4000:]
        except subprocess.TimeoutExpired:
            result["import_timeout"] = True
    (OUT / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
