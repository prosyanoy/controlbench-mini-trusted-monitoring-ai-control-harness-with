"""Python-side tests of the C++ sandbox: limits, escapes and fork bombs are contained."""

import os
import time

import pytest

from controlbench.sandbox import JobSpec


def landlock(sandbox) -> bool:
    return sandbox.features()["landlock_abi"] >= 1


def test_runs_python_and_captures_output(sandbox):
    r = sandbox.run_python("import sys\nprint(input().upper())\nprint('err', file=sys.stderr)\n", stdin="hi\n")
    assert r.status == "ok" and r.stdout == "HI\n" and r.stderr == "err\n"
    assert r.seccomp


def test_nonzero_exit(sandbox):
    r = sandbox.run_python("raise SystemExit(7)")
    assert (r.status, r.exit_code) == ("nonzero_exit", 7)


def test_unicode_and_binary_output_roundtrip(sandbox):
    r = sandbox.run_python("import sys\nsys.stdout.buffer.write('héllo ✓'.encode() + b'\\xff')\n")
    assert r.stdout.startswith("héllo ✓")


def test_wall_clock_timeout(sandbox):
    t0 = time.time()
    r = sandbox.run_python("import time\ntime.sleep(30)", wall_ms=400)
    assert r.status == "timeout" and time.time() - t0 < 5


def test_cpu_limit(sandbox):
    r = sandbox.run_python("while True: pass", cpu_seconds=0.3, wall_ms=10000)
    assert r.status == "cpu_limit"


def test_memory_limit(sandbox):
    r = sandbox.run_python("x = bytearray(1024 * 1024 * 1024)\nprint('allocated')", memory_mb=200)
    assert r.status == "memory_limit" and "allocated" not in r.stdout


def test_output_flood(sandbox):
    r = sandbox.run_python("while True: print('x' * 1000)", max_output_bytes=50_000, cpu_seconds=10)
    assert r.status == "output_limit" and r.stdout_truncated and len(r.stdout) <= 50_000


FORK_BOMBS = {
    "os.fork loop": "import os\nwhile True:\n    os.fork()\n",
    "fork in children": "import os\nfor _ in range(100):\n    if os.fork() == 0:\n        while True: os.fork()\n",
    "subprocess": "import subprocess\nwhile True:\n    subprocess.Popen(['/bin/sleep', '60'])\n",
    "multiprocessing": "import multiprocessing as mp\nps = [mp.Process(target=print) for _ in range(50)]\n[p.start() for p in ps]\n",
    "os.system": "import os\nos.system('/bin/sleep 61')\n",
}


@pytest.mark.parametrize("name", FORK_BOMBS)
def test_fork_bombs_are_contained(sandbox, name):
    r = sandbox.run_python(FORK_BOMBS[name], wall_ms=3000)
    assert r.status == "sandbox_violation", (name, r)
    time.sleep(0.2)
    leftovers = [p for p in os.listdir("/proc") if p.isdigit() and _cmdline(p).startswith("/bin/sleep\x006")]
    assert not leftovers


def _cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            return f.read()
    except OSError:
        return ""


ESCAPES = {
    "tcp socket": "import socket\nsocket.create_connection(('127.0.0.1', 9), timeout=1)\n",
    "unix socket": "import socket\nsocket.socket(socket.AF_UNIX).connect('/run/systemd/private')\n",
    "dns lookup": "import socket\nsocket.getaddrinfo('example.com', 80)\nprint('resolved')\n",
    "signal parent": "import os\nos.kill(os.getppid(), 9)\n",
    "signal everyone": "import os\nos.kill(-1, 9)\n",
    "ptrace": "import ctypes\nctypes.CDLL(None).ptrace(16, 1, 0, 0)\n",
    "chroot": "import ctypes\nctypes.CDLL(None, use_errno=True).chroot(b'/')\n",
    "mount": "import ctypes\nctypes.CDLL(None).mount(b'none', b'/tmp', b'tmpfs', 0, None)\n",
    "unshare": "import ctypes\nctypes.CDLL(None).unshare(0x10000000)\n",
    "io_uring": "import ctypes\nctypes.CDLL(None).syscall(425, 8, 0)\n",
    "bpf": "import ctypes\nctypes.CDLL(None).syscall(321, 0, 0, 0)\n",
}


@pytest.mark.parametrize("name", ESCAPES)
def test_escape_attempts_are_killed(sandbox, name):
    r = sandbox.run_python(ESCAPES[name])
    assert r.status == "sandbox_violation", (name, r)
    assert "resolved" not in r.stdout


def test_cannot_write_outside_workdir(sandbox, tmp_path):
    if not landlock(sandbox):
        pytest.skip("Landlock unavailable")
    target = tmp_path / "pwned"
    code = (f"try:\n    open({str(target)!r}, 'w').write('x')\n    print('wrote')\n"
            "except OSError:\n    print('denied')\n")
    r = sandbox.run_python(code)
    assert r.stdout.strip() == "denied" and not target.exists()


def test_cannot_read_user_files(sandbox, tmp_path):
    if not landlock(sandbox):
        pytest.skip("Landlock unavailable")
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET-123")
    code = (f"try:\n    print(open({str(secret)!r}).read())\nexcept OSError:\n    print('denied')\n"
            "import os\ntry:\n    print(os.listdir(os.path.expanduser('~/..')))\nexcept OSError:\n    print('denied')\n")
    r = sandbox.run_python(code)
    assert "SECRET" not in r.stdout and r.stdout.count("denied") == 2


def test_workdir_is_private_and_removed(sandbox):
    r = sandbox.run_python("import os\nopen('note.txt','w').write('x')\nprint(os.getcwd())\n")
    assert not os.path.exists(r.stdout.strip())


def test_environment_does_not_leak(sandbox, monkeypatch):
    monkeypatch.setenv("CB_SUPER_SECRET", "leak")
    r = sandbox.run_python("import os\nprint(sorted(os.environ))")
    assert "CB_SUPER_SECRET" not in r.stdout


def test_batch_is_parallel_and_ordered(sandbox):
    if sandbox.workers < 2:
        pytest.skip("needs >= 2 workers")
    jobs = [sandbox.python_job(f"import time\ntime.sleep(0.4)\nprint({i})", id=str(i)) for i in range(2 * sandbox.workers)]
    t0 = time.time()
    results = sandbox.run_batch(jobs)
    elapsed = time.time() - t0
    assert [r.stdout.strip() for r in results] == [str(i) for i in range(len(jobs))]
    assert elapsed < 0.4 * len(jobs) * 0.8  # clearly faster than serial


def test_one_bad_job_does_not_affect_others(sandbox):
    jobs = [sandbox.python_job("print('a')"), sandbox.python_job("import os\nos.fork()"),
            sandbox.python_job("print('c')")]
    assert [r.status for r in sandbox.run_batch(jobs)] == ["ok", "sandbox_violation", "ok"]


def test_rejects_unsafe_file_paths_and_relative_binary(sandbox):
    r = sandbox.run_batch([JobSpec(argv=["/bin/true"], files={"../x": "1"})])[0]
    assert r.status == "setup_error"
    r = sandbox.run_batch([JobSpec(argv=["true"])])[0]
    assert r.status == "setup_error"


def test_demo_snippets_are_all_contained(sandbox):
    from controlbench.cli import MALICIOUS_SNIPPETS
    jobs = [sandbox.python_job(code, id=name, cpu_seconds=1.0, wall_ms=3000, memory_mb=256)
            for name, code in MALICIOUS_SNIPPETS]
    for job, res in zip(jobs, sandbox.run_batch(jobs)):
        assert res.status != "ok", job.id
        assert "wrote /tmp/cb_pwned" not in res.stdout and "allocated" not in res.stdout
    assert not os.path.exists("/tmp/cb_pwned")
