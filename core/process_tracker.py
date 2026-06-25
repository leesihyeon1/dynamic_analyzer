"""
process_tracker.py - Process tree tracking and optional Process Hacker launcher
for dynamic malware analysis.

Uses psutil to capture lightweight process snapshots before and after malware
execution, then diffs them to surface newly-spawned and terminated processes.
Optionally launches Process Hacker / System Informer as a live visual aid for
the analyst.

분석 도구 노이즈 필터링
-----------------------
``diff_process_snapshots`` 는 ProcMon·SystemInformer 등 분석 환경 자체 프로세스를
``new_processes`` 목록에서 자동으로 제외합니다.
제외 기준: :data:`_ANALYSIS_TOOL_PROC_NAMES` 참고.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import psutil


# ---------------------------------------------------------------------------
# Analysis tool process names — excluded from new_processes diff output
# (lowercased for case-insensitive comparison)
# ---------------------------------------------------------------------------
_ANALYSIS_TOOL_PROC_NAMES: frozenset[str] = frozenset({
    # Process monitors / explorers
    "systeminformer.exe",
    "processhacker.exe",
    "procmon.exe",
    "procmon64.exe",
    "procexp.exe",
    "procexp64.exe",
    "zoomit.exe",
    "zoomit64.exe",
    # Network capture
    "tshark.exe",
    "dumpcap.exe",
    "wireshark.exe",
    "etwdump.exe",       # Wireshark ETW extcap (child of tshark)
    # Memory / injection scanners
    "hollows_hunter.exe",
    "pe-sieve64.exe",
    "pe-sieve32.exe",
    "pe-sieve.exe",
    "pesieve64.exe",
    "pesieve.exe",
    # Fakenet / network simulation
    "fakenet.exe",
    "fakenet-ng.exe",
})

# ---------------------------------------------------------------------------
# 브라우저 서브프로세스 분류 — 부모 PID + --type 플래그 기반
# ---------------------------------------------------------------------------

_BROWSER_PROC_NAMES: frozenset[str] = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "vivaldi.exe",
})

# 부모와 무관하게 항상 인프라 (Google Updater / Elevation Service 계열)
_BROWSER_ALWAYS_INFRA: frozenset[str] = frozenset({
    "updater.exe",
    "elevation_service.exe",
    "googleupdater.exe",
})

# --type= 값 기준 안전한 인프라 서브프로세스
_BROWSER_INFRA_TYPES: frozenset[str] = frozenset({
    "--type=gpu-process",        # GPU 가속
    "--type=crashpad-handler",   # 크래시 리포터
    "--type=broker",             # 샌드박스 브로커
    "--type=renderer",           # 페이지 렌더러 (네트워크는 network 서비스가 담당)
})

# --type=utility 서브타입 중 안전한 것
_BROWSER_SAFE_UTILITY: frozenset[str] = frozenset({
    "audio.mojom", "video_capture", "storage.mojom",
    "print_compositor", "data_decoder", "sharing.mojom",
    "proxy_resolver", "content_decryption_module", "on_device_model",
    "mirroring", "profiling",
})


def classify_browser_subproc(p: "ProcessSnapshot", pid_to_name: dict) -> str:
    """브라우저 인프라 서브프로세스인지 판별한다.

    Returns
    -------
    "BROWSER_INFRA"
        GPU·Renderer·Crashpad 등 항상 노이즈인 서브프로세스 → 리포트에서 기본 접힘.
    ""
        악성 체인 또는 판단 불가 → 정상 표시.

    판단 기준
    ---------
    - 부모가 브라우저가 아니면 → 악성코드가 직접 실행 → 유지
    - --type 없으면 → 주 브라우저 프로세스 → 유지
    - --type=network, --type=extension → C2·악성 확장 가능성 → 유지
    - --type=gpu/renderer/crashpad/broker → 인프라
    - --type=utility + 알 수 없는 서브타입 → 악성 확장 가능성 → 유지
    """
    name = p.name.lower()

    if name in _BROWSER_ALWAYS_INFRA:
        return "BROWSER_INFRA"

    if name not in _BROWSER_PROC_NAMES:
        return ""

    # 부모가 브라우저가 아니면 악성코드가 직접 실행한 것 → 반드시 유지
    parent_name = pid_to_name.get(p.ppid, "").lower()
    if parent_name not in _BROWSER_PROC_NAMES:
        return ""

    cmd = " ".join(p.cmdline or []).lower()

    # --type 플래그 없음 → 주 브라우저 인스턴스 → 유지
    if "--type=" not in cmd:
        return ""

    if any(t in cmd for t in _BROWSER_INFRA_TYPES):
        return "BROWSER_INFRA"

    if "--type=utility" in cmd:
        if any(s in cmd for s in _BROWSER_SAFE_UTILITY):
            return "BROWSER_INFRA"
        return ""  # 알 수 없는 utility 서브타입 → 악성 확장 가능성 → 유지

    # --type=network, --type=extension, 기타 미지 → 유지
    return ""


# ---------------------------------------------------------------------------
# Process Hacker / System Informer search paths
# ---------------------------------------------------------------------------
_PH_NAMES: list[str] = ["processhacker.exe", "SystemInformer.exe"]

_PH_SEARCH_DIRS: list[Path] = [
    Path(r"C:\Tools\processhacker"),
    Path(r"C:\Program Files\Process Hacker 2"),
    Path(r"C:\Tools\systeminformer"),
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProcessSnapshot:
    """Lightweight snapshot of a single running process.

    Attributes
    ----------
    pid:
        Process identifier.
    ppid:
        Parent process identifier.
    name:
        Executable base name (e.g. ``"chrome.exe"``).
    exe:
        Full path to the executable, or empty string if inaccessible.
    cmdline:
        Command-line arguments (may be empty if access is denied).
    create_time:
        Unix timestamp of when the process was created.
    """

    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: list[str] = field(default_factory=list)
    create_time: float = 0.0
    note: str     = ""  # 보완 사유 (예: "pe-sieve 탐지 / 스냅샷 수집 전 종료")
    category: str = ""  # "BROWSER_INFRA" = 브라우저 인프라 서브프로세스 (기본 접힘)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def find_process_hacker() -> Path | None:
    """Locate Process Hacker or System Informer.

    Search order:
    1. Each executable name on the system PATH.
    2. Well-known installation directories under each name.

    Returns the resolved Path if found, otherwise *None*.
    """
    for name in _PH_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)

    for directory in _PH_SEARCH_DIRS:
        for name in _PH_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate

    return None


def take_process_snapshot() -> dict[int, ProcessSnapshot]:
    """Capture a snapshot of all currently running processes.

    Iterates over all processes via psutil, gracefully skipping any that raise
    ``AccessDenied`` or ``NoSuchProcess`` during enumeration.

    Returns
    -------
    dict[int, ProcessSnapshot]
        Mapping of PID → :class:`ProcessSnapshot`.
    """
    snapshot: dict[int, ProcessSnapshot] = {}
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "create_time"]

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info  # type: ignore[attr-defined]
            snapshot[info["pid"]] = ProcessSnapshot(
                pid=info["pid"] or 0,
                ppid=info["ppid"] or 0,
                name=info["name"] or "",
                exe=info["exe"] or "",
                cmdline=info["cmdline"] or [],
                create_time=info["create_time"] or 0.0,
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception:
            continue

    return snapshot


def diff_process_snapshots(
    before: dict[int, ProcessSnapshot],
    after: dict[int, ProcessSnapshot],
) -> dict[str, list[ProcessSnapshot]]:
    """Compute the delta between two process snapshots.

    Parameters
    ----------
    before:
        Snapshot taken before the analysis period.
    after:
        Snapshot taken after the analysis period.

    Returns
    -------
    dict with two keys:

    ``"new_processes"``
        Processes present in *after* but not in *before*.

    ``"terminated_processes"``
        Processes present in *before* but not in *after*.
    """
    before_pids = set(before.keys())
    after_pids = set(after.keys())

    # 분석 도구 프로세스는 new_processes 목록에서 제외
    new_processes = [
        after[pid]
        for pid in (after_pids - before_pids)
        if after[pid].name.lower() not in _ANALYSIS_TOOL_PROC_NAMES
    ]
    terminated_processes = [before[pid] for pid in (before_pids - after_pids)]

    return {
        "new_processes": new_processes,
        "terminated_processes": terminated_processes,
    }


def launch_process_hacker(ph_path: Path) -> subprocess.Popen | None:
    """Launch Process Hacker (or System Informer) as a detached GUI process.

    Intended to give the analyst a live view of process activity during malware
    execution.  The returned handle can be used to terminate the viewer when
    the analysis session ends, but the process is otherwise independent.

    Parameters
    ----------
    ph_path:
        Path to the Process Hacker executable.

    Returns
    -------
    subprocess.Popen | None
        The launched process handle, or *None* if *ph_path* does not exist or
        the launch fails.
    """
    if ph_path is None or not Path(ph_path).is_file():
        return None
    try:
        proc = subprocess.Popen(
            [str(ph_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # Detach from the current console so it stays alive independently
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        return proc
    except Exception:
        return None


def build_process_tree(snapshots: dict[int, ProcessSnapshot]) -> dict[int, list[int]]:
    """Build a parent-to-children mapping from a process snapshot.

    Parameters
    ----------
    snapshots:
        A dict of PID → :class:`ProcessSnapshot` (e.g. from
        :func:`take_process_snapshot`).

    Returns
    -------
    dict[int, list[int]]
        Mapping of PID → list of child PIDs.  Only PIDs that appear as parents
        of at least one other process are included as keys (though the caller
        may safely use ``.get(pid, [])`` for any PID).
    """
    tree: dict[int, list[int]] = {}
    for pid, snap in snapshots.items():
        ppid = snap.ppid
        if ppid not in tree:
            tree[ppid] = []
        tree[ppid].append(pid)
    return tree
