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


def find_pesieve(config_path: str | None = None) -> Path | None:
    """Locate the pe-sieve executable.

    Search order:
    1. config_path (config.json 의 tools.pe_sieve).
    2. Each name on the system PATH.
    3. Known tool directories.
    """
    if config_path:
        p = Path(config_path)
        if p.is_file():
            return p

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
        *,
        config_path: str | None = None,
    ) -> None:
        self.output_dir   = Path(output_dir)
        self.pesieve_path = pesieve_path or find_pesieve(config_path)
        self.available    = self.pesieve_path is not None and self.pesieve_path.is_file()

    # ------------------------------------------------------------------

    def scan_pid(
        self,
        pid: int,
        *,
        dump_mode: int = 1,
        shellcode: int = 1,   # 0=비활성, 1=패턴, 2=통계, 3=패턴+통계
        hooks: int = 0,       # pe-sieve 이 버전에서 /hooks 미지원 — 무시됨
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
            Shellcode detection mode (/shellc <mode>).
            0=disabled, 1=patterns, 2=stats, 3=patterns+stats.
        hooks:
            Accepted for API compatibility but /hooks is not supported by
            this pe-sieve version — parameter is silently ignored.
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
            "/json",
        ]
        # /shellc 는 모드 값 필수:  1=패턴, 2=통계, 3=패턴+통계
        # /hooks  는 이 버전 pe-sieve 에서 지원하지 않으므로 추가하지 않음
        if shellcode:
            cmd += ["/shellc", str(int(shellcode))]
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

        # 실패 원인을 단계별로 누적합니다
        _diag: list[str] = []

        # returncode 가 비정상이면 먼저 기록 (0 = 정상, 1 = 의심 프로세스 발견, 2+ = 오류)
        if result.returncode >= 2:
            _diag.append(f"pe-sieve 종료코드 {result.returncode}")

        # 1순위: stdout JSON ───────────────────────────────────────────
        # pe-sieve 진행 텍스트 뒤에 JSON 이 붙어 오는 경우를 위해 첫 번째 "{" 부터 파싱
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if not stdout:
            _diag.append("stdout 없음" + (f" (stderr: {stderr[:120]})" if stderr else ""))
        else:
            brace = stdout.find("{")
            if brace == -1:
                preview = stdout[:120].replace("\n", " ")
                _diag.append(f"stdout에 JSON 없음 — 출력: {preview!r}")
            else:
                try:
                    data = json.loads(stdout[brace:])
                    # pe-sieve 버전에 따라 JSON에 pid 가 없거나 0 일 수 있음.
                    # scan_pid(pid=...) 로 호출한 PID 를 항상 주입.
                    data["pid"]     = pid
                    data["dump_dir"] = self._find_dump_dir(pid)
                    return data
                except Exception as e:
                    preview = stdout[brace:brace + 80].replace("\n", " ")
                    _diag.append(f"stdout JSON 파싱 오류: {e} — 내용: {preview!r}")

        # 2순위: 파일 폴백 ─────────────────────────────────────────────
        # pe-sieve 버전에 따라 JSON 저장 위치가 다름:
        #   구버전: <output_dir>/<pid>_<name>.json          (루트)
        #   신버전: <output_dir>/<pid>_<name>/<pid>_<name>.json  (서브디렉터리)
        # → rglob 으로 재귀 탐색
        candidates = sorted(
            self.output_dir.rglob(f"{pid}*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        # 파일 이름에 PID 가 없는 경우: dump 서브디렉터리 내 *.json
        if not candidates:
            dump_dir = Path(self._find_dump_dir(pid))
            if dump_dir.exists():
                candidates = sorted(
                    dump_dir.glob("*.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
        if candidates:
            try:
                data = json.loads(candidates[0].read_text(encoding="utf-8", errors="replace"))
                data["pid"]      = pid          # 항상 요청한 PID 로 고정
                data["dump_dir"] = self._find_dump_dir(pid)
                return data
            except Exception as exc:
                _diag.append(f"파일 {candidates[0].name} JSON 파싱 오류: {exc}")
                return {"error": " / ".join(_diag), "pid": pid,
                        "dump_dir": self._find_dump_dir(pid)}
        else:
            _diag.append(f"JSON 파일 없음 (탐색 경로: {self.output_dir})")

        return {
            "error": " / ".join(_diag) if _diag else "pe-sieve 출력 없음",
            "pid":    pid,
            "dump_dir": self._find_dump_dir(pid),
        }

    def _find_dump_dir(self, pid: int) -> str:
        """pe-sieve 버전별 dump 서브디렉터리 명명 규칙을 모두 탐색.

        알려진 패턴:
          구버전: "<pid>_<procname>"   예) 476_notepad.exe
          신버전: "process_<pid>"      예) process_476
        """
        if not self.output_dir.exists():
            return str(self.output_dir)
        for d in self.output_dir.iterdir():
            if not d.is_dir():
                continue
            n = d.name
            if n.startswith(f"{pid}_") or n == f"process_{pid}":
                return str(d)
        # 숫자만으로 된 디렉터리 폴백
        plain = self.output_dir / str(pid)
        return str(plain) if plain.exists() else str(self.output_dir)

    def list_dumps(self, pid: int) -> list[Path]:
        """Return all dumped files for a given PID."""
        dump_dir = Path(self._find_dump_dir(pid))
        if not dump_dir.exists():
            return []
        return [p for p in dump_dir.iterdir() if p.is_file() and p.suffix != ".json"]
