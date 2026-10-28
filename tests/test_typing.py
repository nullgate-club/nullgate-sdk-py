import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


def test_mismatched_params_untyped_discovery_filters_and_raw_protections_are_rejected(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--strict",
            "--no-error-summary",
            "--show-error-codes",
            "--no-incremental",
            "--cache-dir",
            str(tmp_path / "typing-cache"),
            "tests/typing/invalid.py",
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    codes = Counter(re.findall(r"\[([a-z-]+)\]$", result.stdout, re.MULTILINE))
    assert codes == {"arg-type": 9, "call-overload": 2}, result.stdout + result.stderr
