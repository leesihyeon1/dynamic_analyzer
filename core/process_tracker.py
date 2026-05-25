"""
process_tracker.py - Process tree tracking and optional Process Hacker launcher
for dynamic malware analysis.

Uses psutil to capture lightweight process snapshots before and after malware
execution, then diffs them to surface newly-spawned and terminated processes.
Optionally launches Process Hacker / System Informer as a live visual aid for
the analyst.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import psutil


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

    new_processes = [after[pid] for pid in (after_pids - before_pids)]
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
