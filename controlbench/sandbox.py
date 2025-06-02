"""Python client for the C++ ``cb_sandbox`` executor (subprocess + JSON)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent


class SandboxUnavailable(RuntimeError):
    """The ``cb_sandbox`` binary could not be found or run."""


@dataclass
class JobSpec:
    argv: Sequence[str]
    id: str = ""
    files: dict[str, str] = field(default_factory=dict)
    stdin: str = ""
    env: dict[str, str] = field(default_factory=dict)
    cpu_seconds: float = 2.0
    wall_ms: int = 5000
    memory_mb: int = 512
    max_output_bytes: int = 1 << 20
    max_workdir_bytes: int = 16 << 20
    allow_threads: bool = False
    seccomp: bool = True
    landlock: bool = True
    require_landlock: bool = False
    extra_ro_paths: Sequence[str] = ()

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "argv": list(self.argv),
            "stdin": self.stdin,
            "env": dict(self.env),
            "files": dict(self.files),
            "limits": {
                "cpu_seconds": self.cpu_seconds,
                "wall_ms": self.wall_ms,
                "memory_mb": self.memory_mb,
                "max_output_bytes": self.max_output_bytes,
                "max_workdir_bytes": self.max_workdir_bytes,
            },
            "policy": {
                "seccomp": self.seccomp,
                "landlock": self.landlock,
                "require_landlock": self.require_landlock,
                "allow_threads": self.allow_threads,
                "extra_ro_paths": list(self.extra_ro_paths),
            },
        }


@dataclass
class JobResult:
    id: str
    status: str
    exit_code: int
    signal: int
    stdout: str
    stderr: str
    wall_ms: int
    cpu_ms: int
    max_rss_kb: int
    seccomp: bool
    landlock: bool
    detail: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @classmethod
    def from_json(cls, d: dict) -> "JobResult":
        return cls(
            id=d["id"], status=d["status"], exit_code=d["exit_code"], signal=d["signal"],
            stdout=d["stdout"], stderr=d["stderr"], wall_ms=d["wall_ms"], cpu_ms=d["cpu_ms"],
            max_rss_kb=d["max_rss_kb"], seccomp=d["seccomp"], landlock=d["landlock"],
            detail=d["detail"], stdout_truncated=d.get("stdout_truncated", False),
            stderr_truncated=d.get("stderr_truncated", False),
        )


def find_binary() -> Path:
    env = os.environ.get("CONTROLBENCH_SANDBOX_BIN")
    candidates = [Path(env)] if env else []
    candidates += [REPO_ROOT / "build" / "cb_sandbox", REPO_ROOT / "build" / "sandbox" / "cb_sandbox"]
    which = shutil.which("cb_sandbox")
    if which:
        candidates.append(Path(which))
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    raise SandboxUnavailable(
        "cb_sandbox binary not found. Build it with `make build` "
        "(or set CONTROLBENCH_SANDBOX_BIN)."
    )


def python_interpreter() -> tuple[str, list[str]]:
    """Absolute interpreter path for sandboxed Python plus extra read-only roots.

    Virtualenv interpreters are symlinks into the base installation; the sandbox
    only needs to see the real installation.
    """
    exe = os.path.realpath(sys.executable)
    roots = {os.path.realpath(sys.base_prefix), os.path.dirname(os.path.dirname(exe))}
    standard = ("/usr", "/lib", "/bin", "/opt")
    extra = sorted(r for r in roots if r != "/" and not any(r == s or r.startswith(s + "/") for s in standard))
    return exe, extra


class Sandbox:
    """Runs batches of jobs through the C++ worker pool."""

    def __init__(self, binary: str | os.PathLike | None = None, workers: int | None = None,
                 base_dir: str | None = None):
        self.binary = Path(binary) if binary else find_binary()
        env_workers = os.environ.get("CONTROLBENCH_WORKERS")
        self.workers = workers or (int(env_workers) if env_workers else (os.cpu_count() or 2))
        self.base_dir = base_dir
        self._python, self._python_ro = python_interpreter()

    # -- low level ---------------------------------------------------------
    def run_batch(self, jobs: Sequence[JobSpec], timeout: float | None = None) -> list[JobResult]:
        if not jobs:
            return []
        payload = {"jobs": []}
        for i, job in enumerate(jobs):
            d = job.to_json()
            d["id"] = job.id or str(i)
            payload["jobs"].append(d)
        cmd = [str(self.binary), "--workers", str(self.workers)]
        if self.base_dir:
            cmd += ["--base-dir", self.base_dir]
        total_wall = sum(j.wall_ms for j in jobs) / 1000.0
        timeout = timeout or (30 + total_wall / max(1, self.workers) * 2 + 1)
        try:
            proc = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except FileNotFoundError as e:  # pragma: no cover - guarded by find_binary
            raise SandboxUnavailable(str(e)) from e
        if proc.returncode != 0:
            raise RuntimeError(f"cb_sandbox failed ({proc.returncode}): {proc.stderr.strip()}")
        return [JobResult.from_json(d) for d in json.loads(proc.stdout)]

    def features(self) -> dict:
        proc = subprocess.run([str(self.binary), "--features"], capture_output=True, text=True, check=True)
        return json.loads(proc.stdout)

    # -- python conveniences ----------------------------------------------
    def python_job(self, code: str, *, files: dict[str, str] | None = None, stdin: str = "",
                   id: str = "", **kwargs) -> JobSpec:
        all_files = {"main.py": code}
        all_files.update(files or {})
        kwargs.setdefault("extra_ro_paths", self._python_ro)
        return JobSpec(argv=[self._python, "-I", "-S", "-B", "main.py"], files=all_files,
                       stdin=stdin, id=id, **kwargs)

    def run_python(self, code: str, **kwargs) -> JobResult:
        return self.run_batch([self.python_job(code, **kwargs)])[0]

    def run_python_batch(self, codes: Iterable[str], **kwargs) -> list[JobResult]:
        return self.run_batch([self.python_job(c, id=str(i), **kwargs) for i, c in enumerate(codes)])
