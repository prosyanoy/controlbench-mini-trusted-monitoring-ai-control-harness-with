import shutil
import subprocess
from pathlib import Path

import pytest

from controlbench.sandbox import REPO_ROOT, Sandbox, SandboxUnavailable, find_binary


def _build() -> None:
    cmake = shutil.which("cmake")
    if not cmake:
        raise SandboxUnavailable("cmake not found; run `make build` first")
    build = REPO_ROOT / "build"
    subprocess.run([cmake, "-S", str(REPO_ROOT / "sandbox"), "-B", str(build), "-DCB_BUILD_TESTS=OFF",
                    "-DCMAKE_BUILD_TYPE=Release"], check=True, capture_output=True)
    subprocess.run([cmake, "--build", str(build), "-j"], check=True, capture_output=True)


@pytest.fixture(scope="session")
def sandbox() -> Sandbox:
    try:
        find_binary()
    except SandboxUnavailable:
        _build()
    return Sandbox()


@pytest.fixture(scope="session")
def evaluator(sandbox):
    from controlbench.evaluate import Evaluator
    return Evaluator(sandbox)
