"""Parse ProcMon CSV exports into structured ProcMonEvent objects."""

from __future__ import annotations

import csv
import re
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
