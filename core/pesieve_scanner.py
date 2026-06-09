"""
pesieve_scanner.py - pe-sieve process memory scanner wrapper.

pe-sieve (by hasherezade) scans a running process for:
  - Injected shellcode (non-PE executable memory regions)
  - Process hollowing / PE injection
  - Module stomping
  - IAT / inline hooks
  - Reflective DLL injection

Usage:
    scanner = PeSieveScanner(output_dir=Path("dumps/"))
    if scanner.available:
        result = scanner.scan_pid(pid=1234)

pe-sieve download: https://github.com/hasherezade/pe-sieve/releases
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


_SEARCH_DIRS: list[Path] = [
    Path(r"C:\Tools\pe-sieve"),
    Path(r"C:\Tools"),
    Path(r"C:\Tools\SysinternalsSuite"),
    Path(r"C:\Analysis"),
]

_PESIEVE_NAMES: list[str] = ["pe-sieve64.exe", "pe-sieve.exe", "pesieve64.exe", "pesieve.exe"]


def find_pesieve() -> Path | None:
    """Locate the pe-sieve executable.

    Search order:
    1. Each name on the system PATH.
    2. Known tool directories.
    """
    for name in _PESIEVE_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)

    for directory in _SEARCH_DIRS:
        for name in _PESIEVE_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate

    return None


class PeSieveScanner:
    """Wrapper around pe-sieve for scanning a target process.

    Parameters
    ----------
    output_dir:
        Directory where pe-sieve will write dump files and the JSON report.
    pesieve_path:
        Explicit path to pe-sieve.exe. If None, find_pesieve() is called.
    """

    def __init__(
        self,
        output_dir: Path,
        pesieve_path: Path | None = None,
    ) -> None:
        self.output_dir   = Path(output_dir)
        self.pesieve_path = pesieve_path or find_pesieve()
        self.available    = self.pesieve_path is not None and self.pesieve_path.is_file()

    # ------------------------------------------------------------------

    def scan_pid(
        self,
        pid: int,
        *,
        dump_mode: int = 1,
        shellcode: bool = True,
        hooks: bool = True,
        quiet: bool = True,
    ) -> dict:
        """Run pe-sieve against a single PID and return parsed JSON results.

        Parameters
        ----------
        pid:
            Target process ID.
        dump_mode:
            pe-sieve /dmode flag.
            0 = no dump, 1 = PE dump (default), 3 = shellcode + PE.
        shellcode:
            Enable shellcode detection (/shellc).
        hooks:
            Enable hook detection (/hooks).
        quiet:
            Suppress pe-sieve console output (/quiet).

        Returns
        -------
        dict
            Parsed JSON from pe-sieve, or {"error": ..., "pid": pid} on failure.
        """
        if not self.available:
            return {"error": "pe-sieve를 찾을 수 없음 — PATH 또는 C:\\Tools 에 설치 필요", "pid": pid}

        self.output_dir.mkdir(parents=True, exist_ok=True)
        pid_out = self.output_dir / str(pid)
        pid_out.mkdir(parents=True, exist_ok=True)

        cmd: list[str] = [
            str(self.pesieve_path),
            "/pid", str(pid),
            "/dir", str(pid_out),
            "/dmode", str(dump_mode),
            "/json",
        ]
        if shellcode:
            cmd += ["/shellc", "1"]
        if hooks:
            cmd += ["/hooks"]
        if quiet:
            cmd += ["/quiet"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {"error": "pe-sieve 타임아웃 (120s)", "pid": pid}
        except Exception as exc:
            return {"error": f"pe-sieve 실행 오류: {exc}", "pid": pid}

        # pe-sieve writes the JSON report as <pid>.json inside the output dir
        json_path = pid_out / f"{pid}.json"
        if not json_path.exists():
            # Some versions write directly to the parent dir
            json_path = self.output_dir / f"{pid}.json"

        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
                data["dump_dir"] = str(pid_out)
                return data
            except Exception as exc:
                return {"error": f"JSON 파싱 실패: {exc}", "pid": pid,
                        "dump_dir": str(pid_out)}

        # Fallback: try to parse stdout
        stdout = result.stdout.strip()
        if stdout:
            try:
                data = json.loads(stdout)
                data["dump_dir"] = str(pid_out)
                return data
            except Exception:
                pass

        return {
            "error": "pe-sieve 출력 파싱 실패",
            "pid": pid,
            "stdout": result.stdout[:2000],
            "stderr": result.stderr[:500],
            "dump_dir": str(pid_out),
        }

    def list_dumps(self, pid: int) -> list[Path]:
        """Return all dumped files for a given PID."""
        pid_dir = self.output_dir / str(pid)
        if not pid_dir.exists():
            return []
        return [p for p in pid_dir.iterdir() if p.is_file() and p.suffix != ".json"]
