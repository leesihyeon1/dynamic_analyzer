"""
tshark_capture.py - tshark packet-capture controller for dynamic malware analysis.

Provides utilities to locate a tshark installation, discover the best capture
interface, and manage a background tshark capture process.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


# Well-known tshark installation paths (checked when not found on PATH)
_TSHARK_CANDIDATES: list[Path] = [
    Path(r"C:\Program Files\Wireshark\tshark.exe"),
    Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
]

# Strings that identify loopback-style interfaces we want to skip
_LOOPBACK_MARKERS: tuple[str, ...] = ("loopback", "npcap loopback", "\\device\\npcap_loopback")


def find_tshark() -> Path | None:
    """Locate the tshark executable.

    Search order:
    1. ``tshark.exe`` on the system PATH.
    2. Known Wireshark installation directories.

    Returns the resolved Path if found, otherwise None.
    """
    found = shutil.which("tshark.exe") or shutil.which("tshark")
    if found:
        return Path(found)

    for candidate in _TSHARK_CANDIDATES:
        if candidate.is_file():
            return candidate

    return None


def get_capture_interface(tshark_path: Path) -> str:
    """Return the first non-loopback interface number reported by ``tshark -D``.

    Parses each line of the form ``<num>. <name> (<description>)`` and returns
    the numeric prefix of the first line that does *not* contain loopback
    markers.  Falls back to ``"1"`` if parsing fails or no suitable interface
    is found.

    Parameters
    ----------
    tshark_path:
        Path to the tshark executable.

    Returns
    -------
    str
        Interface number string suitable for passing to ``tshark -i``.
    """
    try:
        result = subprocess.run(
            [str(tshark_path), "-D"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Expected format: "1. \Device\NPF_{GUID} (Ethernet 0)"
            parts = line.split(".", 1)
            if len(parts) < 2:
                continue
            iface_num = parts[0].strip()
            iface_desc = parts[1].lower()
            if any(marker in iface_desc for marker in _LOOPBACK_MARKERS):
                continue
            if iface_num.isdigit():
                return iface_num
    except Exception:
        pass
    return "1"


class TsharkCapture:
    """Control a tshark packet-capture session.

    Parameters
    ----------
    output_dir:
        Directory where the PCAP file will be written.
    tshark_path:
        Explicit path to tshark.exe.  If *None* ``find_tshark()`` is called
        automatically.
    interface:
        Interface number/name to capture on.  If *None*, ``get_capture_interface``
        is used to pick the first non-loopback interface.
    """

    def __init__(
        self,
        output_dir: Path,
        tshark_path: Path | None = None,
        interface: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.tshark_path: Path | None = tshark_path or find_tshark()
        self.available: bool = (
            self.tshark_path is not None and self.tshark_path.is_file()
        )

        self.pcap_path: Path = self.output_dir / "capture.pcap"

        self._interface: str = interface or (
            get_capture_interface(self.tshark_path) if self.available else "1"
        )
        self._proc: subprocess.Popen | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, timeout_sec: int) -> bool:
        """Start a background tshark capture.

        tshark is configured to auto-stop after ``timeout_sec + 5`` seconds so
        it will not run indefinitely if ``stop()`` is never called.

        Parameters
        ----------
        timeout_sec:
            Expected analysis duration.  tshark auto-stops at ``timeout_sec + 5``.

        Returns
        -------
        bool
            *True* if the process was launched successfully, *False* otherwise.
        """
        if not self.available:
            return False
        try:
            auto_stop = timeout_sec + 5
            self._proc = subprocess.Popen(
                [
                    str(self.tshark_path),
                    "-i", self._interface,
                    "-w", str(self.pcap_path),
                    "-a", f"duration:{auto_stop}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            return False

    def stop(self) -> bool:
        """Stop the running tshark process.

        Attempts a graceful ``terminate()`` first, waits up to 2 seconds, then
        forcibly kills the process if it has not exited.

        Returns
        -------
        bool
            *True* if the process was stopped (or was not running), *False* on
            unexpected failure.
        """
        if self._proc is None:
            return True
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
            return True
        except Exception:
            return False
