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

_WIN_TOKEN_RE = re.compile(r'"([^"]*)"|(\S+)')


def split_windows_cmdline(raw: str) -> list[str]:
    r"""Windows 명령줄을 토큰으로 나눈다 — 백슬래시를 이스케이프로 보지 않는다.

    shlex(POSIX 모드)는 ``C:\Windows\System32`` 의 백슬래시를 먹어
    ``C:WindowsSystem32`` 로 만든다. 경로가 깨지면 리포트·AI 프롬프트·IOC 가
    전부 오염되므로 따옴표만 해석하는 단순 분리기를 쓴다.
    """
    raw = (raw or "").strip()
    out: list[str] = []
    for m in _WIN_TOKEN_RE.finditer(raw):
        out.append(m.group(1) if m.group(1) is not None else m.group(2))
    return [t for t in out if t != ""]


# 샘플 경로가 명령줄에 있어도 호스트로 보지 않는 프로세스 (분석기 자신)
_NOT_SAMPLE_HOST: frozenset[str] = frozenset({
    "python.exe", "pythonw.exe", "py.exe", "capa.exe", "yara.exe", "yara64.exe",
    "procmon.exe", "procmon64.exe", "tshark.exe", "dumpcap.exe",
    "hollows_hunter.exe", "pe-sieve64.exe", "pe-sieve32.exe", "pe-sieve.exe",
    "systeminformer.exe", "processhacker.exe", "conhost.exe",
})


def find_sample_host(events: "list[ProcMonEvent]", sample_path: str) -> "ChildProcInfo | None":
    """ShellExecute 로 연 샘플(.js/.docx/.hta 등)의 호스트 프로세스를 찾는다.

    문서·스크립트는 연관 앱(wscript.exe, WINWORD.EXE, mshta.exe …)이 대신 실행하므로
    실행 시점에는 PID 를 알 수 없다. ProcMon Process Create 이벤트 중
    **명령줄에 샘플 경로가 들어 있는 가장 이른 프로세스**가 호스트다.
    이것을 못 찾으면 샘플 계보(lineage)가 비어 관련도 등급이 전부 "의심"으로 뭉개진다.
    """
    if not sample_path:
        return None
    full = sample_path.lower()
    base = _os.path.basename(sample_path).lower()
    fallback = None
    for ev in events:
        if ev.operation != "Process Create":
            continue
        detail = ev.detail or ""
        m_pid = _CHILD_PID_RE.search(detail)
        m_cmd = _CMD_LINE_RE.search(detail)
        if not m_pid or not m_cmd:
            continue
        exe  = ev.path or ""
        name = _os.path.basename(exe).lower()
        if name in _NOT_SAMPLE_HOST:
            continue
        cmd_l = m_cmd.group(1).lower()
        if full not in cmd_l and base not in cmd_l:
            continue
        info = ChildProcInfo(
            child_pid=int(m_pid.group(1)), parent_pid=ev.pid,
            name=_os.path.basename(exe) or f"pid{m_pid.group(1)}",
            exe=exe, cmdline=split_windows_cmdline(m_cmd.group(1)),
        )
        if full in cmd_l:
            return info            # 전체 경로 일치 — 확정
        fallback = fallback or info  # 파일명만 일치 — 더 나은 후보가 없을 때만
    return fallback


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
            cmdline = split_windows_cmdline(m_cmd.group(1))

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
