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
    Path(r"C:\Users\BUILD_SVC\Desktop\Tools"),  # 분석 VM
    Path(r"C:\Tools\pe-sieve"),
    Path(r"C:\Tools"),
    Path(r"C:\Analysis"),
    Path(r"C:\analysis"),
    Path(r"C:\Users\Public\Tools"),
    Path(r"C:\ProgramData\chocolatey\bin"),   # choco install
    Path(r"C:\flare-tools"),                  # FLARE-VM
    Path(r"C:\FLARE"),
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

        # pe-sieve는 /dir 아래에 "<pid>_<procname>\" 서브디렉터리를 자동 생성한다.
        # 미리 서브디렉터리를 만들면 안 됨 — pe-sieve가 직접 생성함.
        cmd: list[str] = [
            str(self.pesieve_path),
            "/pid",   str(pid),
            "/dir",   str(self.output_dir),
            "/dmode", str(dump_mode),
            "/json",  # stdout으로 JSON 출력
        ]
        # /shellc, /hooks 는 단독 플래그 (값 없음)
        if shellcode:
            cmd.append("/shellc")
        if hooks:
            cmd.append("/hooks")
        if quiet:
            cmd.append("/quiet")

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

        # 1순위: stdout JSON (pe-sieve /json 플래그의 기본 출력 경로)
        stdout = result.stdout.strip()
        if stdout:
            # pe-sieve 는 스캔 진행 텍스트 + JSON 을 섞어서 출력할 수 있음
            # → 마지막으로 등장하는 '{' 부터 파싱 시도
            brace = stdout.rfind("{")
            if brace != -1:
                try:
                    data = json.loads(stdout[brace:])
                    data["dump_dir"] = self._find_dump_dir(pid)
                    return data
                except Exception:
                    pass

        # 2순위: 파일 폴백 — "<output_dir>/<pid>*.json" 패턴으로 탐색
        candidates = sorted(
            self.output_dir.glob(f"{pid}*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            try:
                data = json.loads(candidates[0].read_text(encoding="utf-8", errors="replace"))
                data["dump_dir"] = self._find_dump_dir(pid)
                return data
            except Exception as exc:
                return {"error": f"JSON 파싱 실패: {exc}", "pid": pid,
                        "dump_dir": self._find_dump_dir(pid)}

        return {
            "error": "pe-sieve 출력 파싱 실패 — JSON을 찾을 수 없음",
            "pid":    pid,
            "stdout": stdout[:2000],
            "stderr": result.stderr[:500],
            "returncode": result.returncode,
            "dump_dir": self._find_dump_dir(pid),
        }

    def _find_dump_dir(self, pid: int) -> str:
        """pe-sieve가 생성한 '<pid>_<procname>' 서브디렉터리를 탐색."""
        matches = [
            d for d in self.output_dir.iterdir()
            if d.is_dir() and d.name.startswith(f"{pid}_")
        ]
        if matches:
            return str(matches[0])
        # 프로세스 이름 없이 숫자만으로 된 디렉터리 폴백
        plain = self.output_dir / str(pid)
        return str(plain) if plain.exists() else str(self.output_dir)

    def list_dumps(self, pid: int) -> list[Path]:
        """Return all dumped files for a given PID."""
        dump_dir = Path(self._find_dump_dir(pid))
        if not dump_dir.exists():
            return []
        return [p for p in dump_dir.iterdir() if p.is_file() and p.suffix != ".json"]
