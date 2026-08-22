"""
procmon.py - Process Monitor (ProcMon) controller for dynamic malware analysis.

Provides utilities to locate a ProcMon installation, start/stop capture sessions,
and export captured logs to CSV for downstream parsing.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path


# Fallback directories to search when ProcMon is not on PATH
_SEARCH_DIRS: list[Path] = [
    Path(r"C:\Tools\SysinternalsSuite"),
    Path(r"C:\Program Files\Sysinternals"),
    Path(r"C:\Sysinternals"),
]

_PROCMON_NAMES: list[str] = ["Procmon.exe", "Procmon64.exe"]


def find_procmon() -> Path | None:
    """Locate the ProcMon executable.

    Search order:
    1. Each name (Procmon.exe, Procmon64.exe) on the system PATH.
    2. Known installation directories under each name.

    Returns the resolved Path if found, otherwise None.
    """
    # 1. Check PATH first
    for name in _PROCMON_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)

    # 2. Check well-known install directories
    for directory in _SEARCH_DIRS:
        for name in _PROCMON_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate

    return None


class ProcMonController:
    """Control a ProcMon capture session.

    Parameters
    ----------
    output_dir:
        Directory where captured files (.pml / .csv) will be written.
    procmon_path:
        Explicit path to Procmon.exe.  If *None* ``find_procmon()`` is called
        automatically.
    """

    def __init__(self, output_dir: Path, procmon_path: Path | None = None) -> None:
        self.output_dir = Path(output_dir)
        self.procmon_path: Path | None = procmon_path or find_procmon()
        self.available: bool = self.procmon_path is not None and self.procmon_path.is_file()

        self.pml_path: Path = self.output_dir / "procmon.pml"
        self.csv_path: Path = self.output_dir / "procmon.csv"

        self._proc: subprocess.Popen | None = None
        self.export_error: str = ""   # export_csv() 실패 원인 (호출부가 확인)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start a ProcMon capture session.

        Launches ProcMon in quiet/minimised mode and waits 2 seconds for it to
        initialise.

        Returns
        -------
        bool
            *True* on apparent success, *False* if ProcMon is unavailable or
            an exception occurs.
        """
        if not self.available:
            return False
        try:
            self._proc = subprocess.Popen(
                [
                    str(self.procmon_path),
                    "/AcceptEula",
                    "/Quiet",
                    "/Minimized",
                    "/BackingFile",
                    str(self.pml_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            return True
        except Exception:
            return False

    def stop(self) -> bool:
        """Stop the active ProcMon capture session.

        Sends the ``/Terminate`` flag to ProcMon and waits 1 second.  If the
        graceful termination command itself fails (e.g. the child process is
        already gone), the internally-tracked ``_proc`` handle is killed as a
        fallback.

        Returns
        -------
        bool
            *True* on success or if nothing was running, *False* on unexpected
            failure.
        """
        if not self.available:
            return False
        try:
            subprocess.run(
                [str(self.procmon_path), "/Terminate"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            time.sleep(1)
            return True
        except Exception:
            # Fallback: forcibly kill the Popen handle we launched
            if self._proc is not None:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            return False

    def export_timeout_for(self, pml_bytes: int) -> int:
        """PML 크기에 맞춘 CSV 변환 타임아웃(초).

        수백만 이벤트짜리 로그는 변환에 수 분이 걸린다. 고정 60초로는
        대용량 캡처에서 반드시 실패하므로 크기에 비례해 늘린다.
        기준: 100MB 당 약 120초, 최소 300초 · 최대 1800초.
        """
        mb = max(pml_bytes, 0) / (1024 * 1024)
        return int(min(max(300, 120 * (mb / 100) + 120), 1800))

    def export_csv(self, timeout: int | None = None) -> bool:
        """Export the captured .pml log to CSV.

        Opens the backing file via ProcMon and instructs it to save a CSV
        representation.

        타임아웃은 PML 크기에 따라 자동 산정된다(``timeout`` 으로 상한 지정 가능).
        실패 원인은 :attr:`export_error` 에 남는다 — 호출부가 반드시 확인할 것.
        변환이 중간에 끊기면 ProcMon 이 잘린 CSV 를 남기므로, 호출부가
        ``csv_path.exists()`` 만 보고 성공으로 오인하지 않도록 사전에 삭제한다.

        Returns
        -------
        bool
            *True* if a non-empty CSV was produced, *False* otherwise.
        """
        self.export_error = ""
        if not self.available:
            self.export_error = "ProcMon 실행 파일을 찾을 수 없음"
            return False
        if not self.pml_path.exists():
            self.export_error = f"PML 로그 없음: {self.pml_path}"
            return False

        pml_size = self.pml_path.stat().st_size
        if pml_size == 0:
            self.export_error = "PML 로그가 비어 있음 (캡처가 시작되지 않았을 수 있음)"
            return False

        # 이전 실행이나 중단된 변환이 남긴 CSV 제거 —
        # 남아 있으면 변환 실패를 '이벤트 0건'으로 오인하게 된다.
        try:
            if self.csv_path.exists():
                self.csv_path.unlink()
        except Exception:
            pass

        tmo = timeout or self.export_timeout_for(pml_size)
        try:
            result = subprocess.run(
                [
                    str(self.procmon_path),
                    "/AcceptEula",
                    "/OpenLog",
                    str(self.pml_path),
                    "/SaveAs",
                    str(self.csv_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=tmo,
            )
        except subprocess.TimeoutExpired:
            self.export_error = (
                f"CSV 변환 타임아웃 ({tmo}초, PML {pml_size / 1024 / 1024:.0f}MB). "
                f"--timeout 을 줄여 캡처량을 낮추거나 ProcMon 필터를 좁히세요."
            )
            # 잘린 CSV 는 0건으로 오인되므로 제거
            try:
                if self.csv_path.exists():
                    self.csv_path.unlink()
            except Exception:
                pass
            return False
        except Exception as exc:
            self.export_error = f"CSV 변환 실행 실패: {exc}"
            return False

        if result.returncode != 0:
            self.export_error = f"ProcMon 종료 코드 {result.returncode}"
            return False
        if not self.csv_path.exists():
            self.export_error = "변환은 끝났으나 CSV 파일이 생성되지 않음"
            return False
        if self.csv_path.stat().st_size < 200:      # 헤더만 있는 수준
            self.export_error = (
                f"CSV 가 비어 있음 ({self.csv_path.stat().st_size}바이트) — "
                f"ProcMon 필터가 모든 이벤트를 걸렀을 수 있습니다."
            )
            return False
        return True
