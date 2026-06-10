"""
hollows_hunter.py - hollows-hunter wrapper for full-system process scan.

hollows-hunter (by hasherezade) runs pe-sieve against every running process
and aggregates results into a single JSON report.

Useful for post-execution snapshots:
  1. Run malware.
  2. Wait for execution.
  3. Call HollowsHunter.scan_all() to find any injected processes.

hollows-hunter download: https://github.com/hasherezade/hollows_hunter/releases
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


_SEARCH_DIRS: list[Path] = [
    Path(r"C:\Users\BUILD_SVC\Desktop\Tools"),  # 분석 VM
    Path(r"C:\Tools\hollows_hunter"),
    Path(r"C:\Tools"),
    Path(r"C:\Analysis"),
    Path(r"C:\analysis"),
    Path(r"C:\Users\Public\Tools"),
    Path(r"C:\ProgramData\chocolatey\bin"),
    Path(r"C:\flare-tools"),
    Path(r"C:\FLARE"),
]

_HH_NAMES: list[str] = [
    "hollows_hunter64.exe",
    "hollows_hunter.exe",
    "hollows-hunter64.exe",
    "hollows-hunter.exe",
]


def find_hollows_hunter(config_path: str | None = None) -> Path | None:
    """Locate the hollows-hunter executable.

    Search order:
    1. config_path (config.json 의 tools.hollows_hunter).
    2. Each name on the system PATH.
    3. Known tool directories.
    """
    if config_path:
        p = Path(config_path)
        if p.is_file():
            return p

    for name in _HH_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)

    for directory in _SEARCH_DIRS:
        for name in _HH_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate

    return None


class HollowsHunter:
    """Wrapper around hollows-hunter for full-system process memory scanning.

    Parameters
    ----------
    output_dir:
        Directory where hollows-hunter writes dump files and JSON report.
    hh_path:
        Explicit path to hollows_hunter.exe. If None, find_hollows_hunter() is called.
    """

    def __init__(
        self,
        output_dir: Path,
        hh_path: Path | None = None,
        *,
        config_path: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.hh_path    = hh_path or find_hollows_hunter(config_path)
        self.available  = self.hh_path is not None and self.hh_path.is_file()

    # ------------------------------------------------------------------

    def scan_all(
        self,
        *,
        dump_mode: int = 1,
        shellcode: int = 1,   # 0=비활성, 1=패턴, 2=통계, 3=패턴+통계
        hooks: bool = True,   # hollows-hunter /hooks 는 값 없는 토글 플래그
        pname_filter: str | None = None,
    ) -> dict:
        """Scan all running processes with hollows-hunter.

        Parameters
        ----------
        dump_mode:
            /dmode flag passed through to pe-sieve.
            1 = PE dump (default), 3 = shellcode + PE.
        shellcode:
            Shellcode detection mode (/shellc <mode>).
            0=disabled, 1=patterns, 2=stats, 3=patterns+stats.
        hooks:
            Enable inline hook / in-memory patch detection (/hooks toggle).
            hollows-hunter treats this as a boolean switch (no mode value).
        pname_filter:
            If set, only scan processes whose name contains this string
            (hollows-hunter /pname flag). Useful to focus on a known target.

        Returns
        -------
        dict
            Parsed hollows-hunter JSON summary, or {"error": ...} on failure.
        """
        if not self.available:
            return {
                "error": (
                    "hollows-hunter를 찾을 수 없음 — "
                    "PATH 또는 C:\\Tools 에 설치 필요"
                )
            }

        self.output_dir.mkdir(parents=True, exist_ok=True)

        cmd: list[str] = [
            str(self.hh_path),
            "/dir",   str(self.output_dir),
            "/dmode", str(dump_mode),
            "/json",
        ]
        # /shellc 는 모드 값 필수:  1=패턴, 2=통계, 3=패턴+통계
        # /hooks  는 값 없는 토글 플래그 (bool)
        if shellcode:
            cmd += ["/shellc", str(int(shellcode))]
        if hooks:
            cmd.append("/hooks")
        if pname_filter:
            cmd += ["/pname", pname_filter]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            return {"error": "hollows-hunter 타임아웃 (300s)"}
        except Exception as exc:
            return {"error": f"hollows-hunter 실행 오류: {exc}"}

        # 실패 원인을 단계별로 누적합니다
        _diag: list[str] = []

        if result.returncode >= 2:
            _diag.append(f"hollows-hunter 종료코드 {result.returncode}")

        # 1순위: stdout JSON ───────────────────────────────────────────
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if not stdout:
            _diag.append("stdout 없음" + (f" (stderr: {stderr[:120]})" if stderr else ""))
        else:
            brace = stdout.find("{")
            if brace == -1:
                # 3순위: 평문 출력 ("Total scanned: N, Suspicious: N")
                import re as _re
                ts = _re.search(r"Total scanned[:\s]+(\d+)", stdout, _re.IGNORECASE)
                ss = _re.search(r"Suspicious[:\s]+(\d+)",    stdout, _re.IGNORECASE)
                if ts:
                    return {
                        "total_scanned": int(ts.group(1)),
                        "suspicious":    int(ss.group(1)) if ss else 0,
                        "processes":     [],
                        "dump_dir":      str(self.output_dir),
                    }
                preview = stdout[:120].replace("\n", " ")
                _diag.append(f"stdout에 JSON 없음 — 출력: {preview!r}")
            else:
                try:
                    data = json.loads(stdout[brace:])
                    data["dump_dir"] = str(self.output_dir)
                    return data
                except Exception as e:
                    preview = stdout[brace:brace + 80].replace("\n", " ")
                    _diag.append(f"stdout JSON 파싱 오류: {e} — 내용: {preview!r}")

        # 2순위: 파일 폴백 — 가장 최근 .json 파일 ─────────────────────
        json_candidates = sorted(
            self.output_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if json_candidates:
            try:
                data = json.loads(json_candidates[0].read_text(encoding="utf-8", errors="replace"))
                data["dump_dir"] = str(self.output_dir)
                return data
            except Exception as exc:
                _diag.append(f"파일 {json_candidates[0].name} JSON 파싱 오류: {exc}")
                return {"error": " / ".join(_diag), "dump_dir": str(self.output_dir)}
        else:
            _diag.append(f"JSON 파일 없음 (탐색 경로: {self.output_dir})")

        return {
            "error": " / ".join(_diag) if _diag else "hollows-hunter 출력 없음",
            "dump_dir": str(self.output_dir),
        }

    def list_dumps(self) -> list[Path]:
        """Return all dumped (non-JSON) files in the output directory."""
        if not self.output_dir.exists():
            return []
        return [
            p for p in self.output_dir.rglob("*")
            if p.is_file() and p.suffix != ".json"
        ]
