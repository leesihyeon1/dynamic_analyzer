"""Parse ProcMon CSV exports into structured ProcMonEvent objects."""

from __future__ import annotations

import csv
import os as _os
import re
import shlex as _shlex
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class EventCategory(str, Enum):
    FILE     = "File"
    REGISTRY = "Registry"
    PROCESS  = "Process"
    NETWORK  = "Network"
    OTHER    = "Other"


@dataclass
class ProcMonEvent:
    """A single event row from a ProcMon CSV export."""

    time_str:  str
    process:   str
    pid:       int
    operation: str
    path:      str
    result:    str
    detail:    str
    category:  EventCategory


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_FILE_OPS: frozenset[str] = frozenset(
    {
        "ReadFile",
        "WriteFile",
        "CreateFile",
        "DeleteFile",
        "SetEndOfFile",
        "RenameFile",
    }
)

_PROCESS_OPS: frozenset[str] = frozenset(
    {
        "Process Create",
        "Process Exit",
        "Load Image",
        "Thread Create",
    }
)

_NETWORK_PREFIXES: tuple[str, ...] = ("TCP", "UDP")


def _categorize(operation: str) -> EventCategory:
    """Return the EventCategory that best describes *operation*.

    Classification order:
        1. File operations (exact match against known set)
        2. Registry operations (prefix "Reg")
        3. Process operations (exact match against known set)
        4. Network operations (prefix "TCP" or "UDP")
        5. Other
    """
    if operation in _FILE_OPS:
        return EventCategory.FILE
    if operation.startswith("Reg"):
        return EventCategory.REGISTRY
    if operation in _PROCESS_OPS:
        return EventCategory.PROCESS
    if operation.startswith(_NETWORK_PREFIXES):
        return EventCategory.NETWORK
    return EventCategory.OTHER


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_csv(
    csv_path: Path,
    pid_filter: Optional[set[int]] = None,
) -> list[ProcMonEvent]:
    """Parse a ProcMon CSV file and return a list of :class:`ProcMonEvent`.

    Parameters
    ----------
    csv_path:
        Path to the CSV file exported from ProcMon.
    pid_filter:
        When provided, only events whose PID is in this set are returned.

    Returns
    -------
    list[ProcMonEvent]
        Parsed events.  Returns an empty list on any error (file not found,
        malformed rows, etc.).
    """
    try:
        csv_path = Path(csv_path)
        if not csv_path.exists():
            return []

        events: list[ProcMonEvent] = []

        with csv_path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.reader(fh)

            # Skip header row
            try:
                next(reader)
            except StopIteration:
                return []

            for row in reader:
                try:
                    if len(row) < 7:
                        continue

                    time_str, process, pid_str, operation, path, result, detail = (
                        row[0],
                        row[1],
                        row[2],
                        row[3],
                        row[4],
                        row[5],
                        row[6],
                    )

                    # Skip noise results early
                    if result in ("BUFFER OVERFLOW", "FAST IO DISALLOWED"):
                        continue

                    try:
                        pid = int(pid_str)
                    except (ValueError, TypeError):
                        pid = 0

                    if pid_filter is not None and pid not in pid_filter:
                        continue

                    category = _categorize(operation)

                    events.append(
                        ProcMonEvent(
                            time_str=time_str,
                            process=process,
                            pid=pid,
                            operation=operation,
                            path=path,
                            result=result,
                            detail=detail,
                            category=category,
                        )
                    )
                except Exception:
                    # Skip malformed rows without aborting the whole parse
                    continue

        return events

    except FileNotFoundError:
        return []
    except Exception:
        return []


_CHILD_PID_RE = re.compile(r"\bPID:\s*(\d+)", re.IGNORECASE)

# Detail 필드의 "Command line: <값>" 추출 — Environment:/Current directory: 직전에서 종료
_CMD_LINE_RE = re.compile(
    r"Command\s+line:\s*(.*?)(?=,\s*(?:Environment|Current\s+directory)|$)",
    re.IGNORECASE,
)


@dataclass
class ChildProcInfo:
    """Process Create 이벤트에서 추출한 자식 프로세스 정보."""

    child_pid:  int
    parent_pid: int
    name:       str        # Path 필드의 basename
    exe:        str        # Path 필드 원본 (full path)
    cmdline:    list[str]  # Detail 의 Command line 파싱 결과


def get_child_proc_infos(
    events:      list[ProcMonEvent],
    parent_pids: set[int] | None = None,
) -> list[ChildProcInfo]:
    """Process Create 이벤트에서 자식 프로세스 전체 정보를 추출합니다.

    Parameters
    ----------
    events:
        parse_csv() 가 반환한 이벤트 목록.
    parent_pids:
        대상 부모 PID 집합. None 이면 전체 이벤트를 검색합니다.

    Returns
    -------
    list[ChildProcInfo]
        자식 PID 기준 중복 제거된 목록.  child_pid 오름차순 정렬.
    """
    seen:    set[int]            = set()
    results: list[ChildProcInfo] = []

    for ev in events:
        if ev.operation != "Process Create":
            continue
        if parent_pids is not None and ev.pid not in parent_pids:
            continue

        m_pid = _CHILD_PID_RE.search(ev.detail or "")
        if not m_pid:
            continue
        try:
            child_pid = int(m_pid.group(1))
        except ValueError:
            continue
        if child_pid in seen:
            continue
        seen.add(child_pid)

        exe  = ev.path or ""
        name = _os.path.basename(exe) if exe else f"pid{child_pid}"

        cmdline: list[str] = []
        m_cmd = _CMD_LINE_RE.search(ev.detail or "")
        if m_cmd:
            raw = m_cmd.group(1).strip().strip('"')
            try:
                cmdline = _shlex.split(raw)
            except ValueError:
                cmdline = [raw] if raw else []

        results.append(ChildProcInfo(
            child_pid  = child_pid,
            parent_pid = ev.pid,
            name       = name,
            exe        = exe,
            cmdline    = cmdline,
        ))

    results.sort(key=lambda c: c.child_pid)
    return results


def get_child_pids(events: list[ProcMonEvent], parent_pid: int) -> set[int]:
    """Return the set of child PIDs spawned by *parent_pid*.

    Searches for "Process Create" events whose PID matches *parent_pid* and
    extracts the child PID from the Detail field (format: ``"PID: 1234, ..."``).

    Parameters
    ----------
    events:
        Events previously returned by :func:`parse_csv`.
    parent_pid:
        The PID of the process whose children we want.

    Returns
    -------
    set[int]
        Child PIDs found.  Empty set if none.
    """
    children: set[int] = set()
    for event in events:
        if event.operation == "Process Create" and event.pid == parent_pid:
            match = _CHILD_PID_RE.search(event.detail)
            if match:
                try:
                    children.add(int(match.group(1)))
                except ValueError:
                    pass
    return children
