"""
tshark_capture.py - tshark packet-capture controller for dynamic malware analysis.

Provides utilities to locate a tshark installation, discover the best capture
interface, and manage a background tshark capture process.

인터페이스 자동 선택 순서
  1. 기본 경로(0.0.0.0/0)를 가진 어댑터의 GUID ↔ ``\\Device\\NPF_{GUID}`` 일치
  2. IPv4 주소가 있고 연결(up)된 어댑터 이름 ↔ ``tshark -D`` 설명 일치
  3. 첫 번째 NPF(비 루프백) 인터페이스
  4. "1"
extcap 인터페이스(etwdump, ciscodump, sshdump, randpkt, udpdump …)는 제외한다.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


# Well-known tshark installation paths (checked when not found on PATH)
_TSHARK_CANDIDATES: list[Path] = [
    Path(r"C:\Program Files\Wireshark\tshark.exe"),
    Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
]

# Strings that identify loopback-style interfaces we want to skip
_LOOPBACK_MARKERS: tuple[str, ...] = ("loopback", "npcap loopback", "\\device\\npcap_loopback")

# "<번호>. <이름> (<설명>)"
_IFACE_LINE_RE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")
_GUID_RE = re.compile(r"\{([0-9A-Fa-f\-]{36})\}")

# 기본 경로 어댑터 GUID 조회 (PowerShell, NetTCPIP 모듈)
_DEFAULT_ROUTE_PS = (
    "$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
    "Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; "
    "if ($r) { (Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue).InterfaceGuid }"
)


@dataclass
class CaptureInterface:
    number: str
    name: str = ""
    description: str = ""
    reason: str = ""

    @property
    def label(self) -> str:
        desc = self.description or self.name
        return f"{self.number}. {desc}" + (f" — {self.reason}" if self.reason else "")


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


def _list_interfaces(tshark_path: Path) -> list[tuple[str, str, str]]:
    """``tshark -D`` → [(번호, 장치 이름, 설명)]."""
    result = subprocess.run(
        [str(tshark_path), "-D"],
        capture_output=True, text=True, timeout=15,
        encoding="utf-8", errors="replace",
    )
    out = []
    for line in (result.stdout or "").splitlines():
        m = _IFACE_LINE_RE.match(line)
        if m:
            out.append((m.group(1), m.group(2), (m.group(3) or "").strip()))
    return out


def _is_npf(name: str) -> bool:
    return name.lower().startswith("\\device\\npf_")


def _is_loopback(name: str, desc: str) -> bool:
    text = f"{name} {desc}".lower()
    return any(marker in text for marker in _LOOPBACK_MARKERS)


def _default_route_guid(timeout: int = 8) -> str:
    """기본 경로 어댑터의 GUID (소문자, 괄호 없음). 실패 시 빈 문자열."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _DEFAULT_ROUTE_PS],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    m = _GUID_RE.search(r.stdout or "")
    return m.group(1).lower() if m else ""


def _active_ipv4_adapters() -> set[str]:
    """IPv4 주소(루프백·169.254 제외)가 있고 up 상태인 어댑터 이름 (소문자)."""
    try:
        import psutil
        import socket
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return set()
    names = set()
    for name, lst in addrs.items():
        st = stats.get(name)
        if st is not None and not st.isup:
            continue
        for a in lst:
            if a.family == socket.AF_INET and a.address and not (
                    a.address.startswith("127.") or a.address.startswith("169.254.")):
                names.add(name.lower())
                break
    return names


def select_capture_interface(tshark_path: Path) -> CaptureInterface:
    """캡처 인터페이스를 고르고 선택 근거를 함께 반환한다 (실패해도 예외 없음)."""
    try:
        ifaces = _list_interfaces(tshark_path)
    except Exception:
        ifaces = []
    npf = [(n, name, desc) for n, name, desc in ifaces
           if _is_npf(name) and not _is_loopback(name, desc)]
    if not npf:
        # NPF 표기가 없는 환경(비 Windows 등): 루프백·extcap 이 아닌 첫 항목
        npf = [(n, name, desc) for n, name, desc in ifaces
               if not _is_loopback(name, desc) and "\\" in name]
    if not npf:
        return CaptureInterface("1", reason="자동 선택 실패 — 기본값 1")

    guid = _default_route_guid()
    if guid:
        for n, name, desc in npf:
            m = _GUID_RE.search(name)
            if m and m.group(1).lower() == guid:
                return CaptureInterface(n, name, desc, "기본 경로 어댑터")

    active = _active_ipv4_adapters()
    if active:
        for n, name, desc in npf:
            if desc and desc.lower() in active:
                return CaptureInterface(n, name, desc, "IPv4 주소가 있는 활성 어댑터")

    n, name, desc = npf[0]
    return CaptureInterface(n, name, desc, "첫 번째 NPF 인터페이스 (기본 경로 확인 불가)")


def get_capture_interface(tshark_path: Path) -> str:
    """캡처할 인터페이스 번호를 반환한다 (``tshark -i`` 인자).

    기본 경로 어댑터 → IPv4 활성 어댑터 → 첫 번째 NPF 인터페이스 순으로 고르며
    extcap·루프백은 제외한다. 실패하면 ``"1"``.
    """
    try:
        return select_capture_interface(tshark_path).number
    except Exception:
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
        Interface number/name to capture on.  If *None*, ``select_capture_interface``
        is used (default-route adapter first).  선택 결과는 ``interface_label`` 에 남는다.
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

        if interface:
            self._interface = str(interface)
            self.interface_label = f"{interface} (사용자 지정)"
        elif self.available:
            sel = select_capture_interface(self.tshark_path)
            self._interface = sel.number
            self.interface_label = sel.label
        else:
            self._interface = "1"
            self.interface_label = "1"
        self._proc: subprocess.Popen | None = None
        self.last_error: str = ""

    @property
    def interface(self) -> str:
        return self._interface

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self, timeout_sec: int | None = None) -> bool:
        """Start a background tshark capture.

        Parameters
        ----------
        timeout_sec:
            양수면 tshark 가 ``timeout_sec + 5`` 초 뒤 스스로 멈춘다 (안전장치).
            None 또는 0 이면 자동 종료 없이 ``stop()`` 호출까지 계속 캡처한다.

        Returns
        -------
        bool
            *True* if the process was launched successfully, *False* otherwise.
        """
        if not self.available:
            return False
        cmd = [str(self.tshark_path), "-i", self._interface, "-w", str(self.pcap_path)]
        if timeout_sec:
            cmd += ["-a", f"duration:{int(timeout_sec) + 5}"]
        kwargs = {}
        if os.name == "nt":
            # Ctrl+Break 를 tshark 에만 보내 정상 종료(파일 마무리)시키기 위해 별도 그룹
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs,
            )
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self, timeout: float = 10.0) -> bool:
        """캡처를 멈추고 캡처 파일이 디스크에 다 쓰일 때까지 기다린다.

        1) Windows: CTRL_BREAK_EVENT (그 외: SIGINT) 로 정상 종료 요청
        2) ``timeout`` 초 안에 끝나지 않으면 terminate → kill
        3) 캡처 파일 크기가 안정될 때까지(최대 5초) 대기

        Returns
        -------
        bool
            *True* if the process was stopped (or was not running), *False* on
            unexpected failure.
        """
        if self._proc is None:
            return True
        proc = self._proc
        ok = True
        try:
            if proc.poll() is None:
                try:
                    if os.name == "nt":
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        proc.send_signal(signal.SIGINT)
                except Exception:
                    pass
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
        except Exception as exc:
            self.last_error = str(exc)
            ok = False
        finally:
            self._proc = None
        self._wait_for_file()
        return ok

    def _wait_for_file(self, max_wait: float = 5.0, interval: float = 0.5) -> None:
        """dumpcap 자식 프로세스가 파일을 마무리할 시간을 준다 (크기 안정 확인)."""
        deadline = time.monotonic() + max_wait
        last = -1
        while time.monotonic() < deadline:
            try:
                size = self.pcap_path.stat().st_size
            except OSError:
                size = -1
            if size == last and size > 0:
                return
            last = size
            time.sleep(interval)
