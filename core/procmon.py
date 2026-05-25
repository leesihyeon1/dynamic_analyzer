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

    def export_csv(self) -> bool:
        """Export the captured .pml log to CSV.

        Opens the backing file via ProcMon and instructs it to save a CSV
        representation.  Blocks for up to 60 seconds.

        Returns
        -------
        bool
            *True* if the CSV was produced, *False* otherwise.
        """
        if not self.available:
            return False
        if not self.pml_path.exists():
            return False
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
                timeout=60,
            )
            return result.returncode == 0
        except Exception:
            return False
