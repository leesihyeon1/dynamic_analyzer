"""Filter Windows system noise from ProcMon event lists.

Running a Windows malware sandbox produces thousands of events from OS
processes and well-known system paths that are unrelated to the sample
under analysis.  This module strips the most common sources of noise so
downstream classifiers can focus on meaningful activity.
"""

from __future__ import annotations

import re
from typing import Optional

from parsers.procmon_csv import ProcMonEvent, EventCategory


# ---------------------------------------------------------------------------
# Noise configuration
# ---------------------------------------------------------------------------

# Processes to ignore completely (compared in lowercase)
NOISY_PROCESSES: frozenset[str] = frozenset(
    {
        # ── Windows OS 노이즈 프로세스 ───────────────────────────────────
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "spoolsv.exe",
        "searchindexer.exe",
        "msmpseng.exe",
        "nissrv.exe",
        "svchost.exe",
        "runtimebroker.exe",
        "tiworker.exe",
        "compattelrunner.exe",
        "wmiprvse.exe",
        "wmiapsrv.exe",
        "mscorsvw.exe",
        "ngen.exe",
        "defrag.exe",
        "taskhostw.exe",
        "audiodg.exe",
        "dashost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        # ── 분석 도구 프로세스 — 이벤트 전체 제거 ───────────────────────
        "procmon.exe",
        "procmon64.exe",
        "procexp.exe",
        "procexp64.exe",
        "systeminformer.exe",
        "processhacker.exe",
        "tshark.exe",
        "dumpcap.exe",
        "wireshark.exe",
        "zoomit.exe",
        "zoomit64.exe",
    }
)

# Path prefixes to ignore (compared in lowercase)
NOISY_PATHS: list[str] = [
    r"c:\windows\system32\catroot",
    r"c:\windows\system32\config\journal",
    r"c:\windows\winsxs",
    r"c:\windows\softwaredistribution",
    r"c:\programdata\microsoft\windows defender",
    r"hklm\system\currentcontrolset\control\session manager",
    r"hklm\software\microsoft\windows nt\currentversion\perflib",
    r"hklm\software\microsoft\windows\currentversion\diagnostics",
]

# Operations to ignore
NOISY_OPERATIONS: frozenset[str] = frozenset(
    {
        "RegQueryKey",
        "RegQueryValue",
        "RegOpenKey",
        "ReadFile",
        "QueryBasicInformationFile",
        "QueryNameInformationFile",
        "QueryAllInformationFile",
        "CloseFile",
    }
)

# Suspicious write/create operations that should NOT be filtered even when
# they appear in the NOISY_OPERATIONS set or from a noisy process.
_SUSPICIOUS_WRITE_OPS: frozenset[str] = frozenset({"WriteFile", "CreateFile"})

# Double-extension pattern, e.g. invoice.pdf.exe
_DOUBLE_EXT_RE = re.compile(r"\.\w{2,4}\.\w{2,4}$", re.IGNORECASE)

# Paths considered "suspicious" for WriteFile/CreateFile detection
_SUSPICIOUS_PATH_FRAGMENTS: tuple[str, ...] = (
    r"%temp%",
    r"%appdata%",
    r"\appdata\roaming\\",
    r"\appdata\local\temp\\",
)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def is_suspicious_path(path: str) -> bool:
    """Return *True* if *path* exhibits characteristics typical of malware drops.

    Checks performed (case-insensitive):
    * Contains ``%TEMP%`` or ``%APPDATA%`` environment variable references.
    * Resides under ``AppData\\Roaming`` or ``AppData\\Local\\Temp``.
    * Has a double file extension such as ``invoice.pdf.exe``.
    """
    lower = path.lower()
    for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
        if fragment in lower:
            return True
    if _DOUBLE_EXT_RE.search(path):
        return True
    return False


def filter_events(
    events: list[ProcMonEvent],
    focus_pids: Optional[set[int]] = None,
) -> list[ProcMonEvent]:
    """Remove noisy, benign-OS events from *events*.

    Filtering rules applied in order:

    1. **PID focus** – if *focus_pids* is provided, discard events whose PID
       is not in that set.
    2. **Noisy processes** – discard events from processes listed in
       :data:`NOISY_PROCESSES`, *unless* the operation is a write/create to a
       suspicious path (those are kept regardless of process name).
    3. **Noisy operations** – discard events whose operation is in
       :data:`NOISY_OPERATIONS`.  ``WriteFile`` and ``CreateFile`` are kept
       when the destination path looks suspicious.
    4. **Noisy paths** – discard events whose path (lowercased) starts with
       any prefix in :data:`NOISY_PATHS`.
    5. **Failed basic queries** – discard non-successful basic filesystem /
       registry query events that carry no useful signal.

    Parameters
    ----------
    events:
        Raw event list from :func:`parsers.procmon_csv.parse_csv`.
    focus_pids:
        Optional set of PIDs to restrict analysis to.

    Returns
    -------
    list[ProcMonEvent]
        Filtered event list.
    """
    filtered: list[ProcMonEvent] = []
    noisy_path_tuple = tuple(NOISY_PATHS)  # for startswith

    for ev in events:
        try:
            # --- 1. PID focus -----------------------------------------------
            if focus_pids is not None and ev.pid not in focus_pids:
                continue

            # --- 2. Noisy process filter ------------------------------------
            proc_lower = ev.process.lower()
            is_noisy_proc = proc_lower in NOISY_PROCESSES

            # Always keep suspicious writes even from noisy processes
            write_to_suspicious = (
                ev.operation in _SUSPICIOUS_WRITE_OPS
                and is_suspicious_path(ev.path)
            )

            # wmiprvse.exe 의 Process Create 는 WMI 경유 프로세스 생성(T1047)
            # 체인을 추적하기 위해 통과시킴 — 나머지 wmiprvse 이벤트는 계속 제거
            wmi_spawn = (
                proc_lower == "wmiprvse.exe"
                and ev.operation == "Process Create"
            )
            if is_noisy_proc and not write_to_suspicious and not wmi_spawn:
                continue

            # --- 3. Noisy operations ----------------------------------------
            if ev.operation in NOISY_OPERATIONS:
                # Carve out: keep WriteFile/CreateFile on suspicious paths
                if ev.operation in _SUSPICIOUS_WRITE_OPS and is_suspicious_path(ev.path):
                    pass  # keep
                else:
                    continue

            # --- 4. Noisy paths ---------------------------------------------
            path_lower = ev.path.lower()
            if path_lower.startswith(noisy_path_tuple):
                continue

            # --- 5. Failed basic query operations ---------------------------
            _BASIC_QUERY_OPS = frozenset(
                {
                    "QueryBasicInformationFile",
                    "QueryNameInformationFile",
                    "QueryAllInformationFile",
                    "RegQueryKey",
                    "RegQueryValue",
                }
            )
            if ev.operation in _BASIC_QUERY_OPS and ev.result != "SUCCESS":
                continue

            filtered.append(ev)

        except Exception:
            # Defensive: never crash on a single event
            continue

    return filtered
