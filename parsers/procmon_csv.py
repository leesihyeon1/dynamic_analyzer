"""Parse ProcMon CSV exports into structured ProcMonEvent objects.

연산명 정규화
-------------
ProcMon 은 파일 삭제를 ``SetDispositionInformationFile`` /
``SetDispositionInformationEx`` 로, 이름 변경을 ``SetRenameInformationFile`` /
``SetRenameInformationEx`` 로 기록한다. ``DeleteFile`` · ``RenameFile`` 이라는
연산명은 실제로 나오지 않는다. 그래서 :func:`parse_csv` 가 읽는 시점에

  * 삭제가 확정된 SetDisposition* (Detail ``Delete: True`` 또는
    ``FILE_DISPOSITION_DELETE``)  → ``DeleteFile``
  * SetRenameInformation*                                  → ``RenameFile``

로 바꾸고, 원래 연산명은 :attr:`ProcMonEvent.raw_operation` 에 남긴다.
삭제가 아닌 SetDisposition(``Delete: False``) 은 원래 이름 그대로 두어
삭제로 세지 않는다. 소비자는 :func:`is_delete_event` · :func:`is_rename_event`
· :func:`rename_target` · :func:`is_file_create_event` 를 쓰면 정규화 여부와
관계없이 같은 판정을 얻는다.
"""

from __future__ import annotations

import codecs
import csv
import os as _os
import re
import shlex as _shlex
import sys
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
    # 정규화 전 ProcMon 원래 연산명 (예: SetRenameInformationFile). 정규화가
    # 없었거나 직접 생성한 이벤트는 빈 문자열.
    raw_operation: str = ""

    @property
    def time_secs(self) -> float:
        """하루 기준 초(0~86400). 해석 실패 시 -1.0 — 로캘(오전/오후·AM/PM) 무관."""
        return procmon_time_to_secs(self.time_str)


# ---------------------------------------------------------------------------
# 연산명 정규화 상수 · 판정 헬퍼 (모든 소비자가 공유하는 단일 기준)
# ---------------------------------------------------------------------------

DELETE_OP = "DeleteFile"
RENAME_OP = "RenameFile"

# ProcMon 이 실제로 기록하는 삭제/이름변경 연산명
RAW_DELETE_OPS: frozenset[str] = frozenset({
    "SetDispositionInformationFile",
    "SetDispositionInformationEx",
})
RAW_RENAME_OPS: frozenset[str] = frozenset({
    "SetRenameInformationFile",
    "SetRenameInformationEx",
    "SetRenameInformationExBypassAccessCheck",
})

# 정규화 이름 + 원래 이름 — 이름만으로 비교해야 하는 곳에서 사용
DELETE_OPS: frozenset[str] = frozenset({DELETE_OP}) | RAW_DELETE_OPS
RENAME_OPS: frozenset[str] = frozenset({RENAME_OP}) | RAW_RENAME_OPS

# CreateFile 이 실제로 파일을 새로 만들었거나 내용을 갈아엎은 경우의 OpenResult.
# Disposition(OpenIf/OverwriteIf)은 요청일 뿐 결과가 Opened 일 수 있으므로
# OpenResult 값으로 판정한다.
_CREATE_RESULTS: tuple[str, ...] = (
    "openresult: created", "openresult: overwritten", "openresult: superseded",
)

_RENAME_TARGET_RE = re.compile(r"FileName:\s*([^,\r\n]+)", re.IGNORECASE)


def _disposition_is_delete(detail: str) -> bool:
    """SetDisposition* Detail 이 실제 삭제 표시인지."""
    d = (detail or "").lower()
    if "delete: true" in d:
        return True
    if "do_not_delete" in d:
        return False
    return "file_disposition_delete" in d


def canonical_operation(operation: str, detail: str = "") -> str:
    """ProcMon 원래 연산명을 분석기 정규 연산명으로 바꾼다.

    삭제가 아닌 SetDisposition* 은 원래 이름을 그대로 돌려준다.
    """
    if operation in RAW_RENAME_OPS:
        return RENAME_OP
    if operation in RAW_DELETE_OPS and _disposition_is_delete(detail):
        return DELETE_OP
    return operation


def is_delete_event(ev) -> bool:
    """파일 삭제 이벤트인지 (정규화 DeleteFile · 원래 SetDisposition* · Delete On Close)."""
    op = getattr(ev, "operation", "") or ""
    if op == DELETE_OP:
        return True
    detail = getattr(ev, "detail", "") or ""
    if op in RAW_DELETE_OPS:
        return _disposition_is_delete(detail)
    if op == "CreateFile":
        # Options 에 Delete On Close 가 붙은 열기 = 핸들을 닫을 때 삭제
        return ("delete on close" in detail.lower()
                and (getattr(ev, "result", "") or "") == "SUCCESS")
    return False


def is_rename_event(ev) -> bool:
    return (getattr(ev, "operation", "") or "") in RENAME_OPS


def rename_target(ev) -> str:
    """이름 변경 이벤트의 목적지 경로 (Detail 의 FileName:). 없으면 빈 문자열."""
    if not is_rename_event(ev):
        return ""
    m = _RENAME_TARGET_RE.search(getattr(ev, "detail", "") or "")
    return m.group(1).strip() if m else ""


def is_file_create_event(ev) -> bool:
    """CreateFile 이 파일을 새로 만들었거나 덮어쓴 경우만 True (단순 열기 제외)."""
    if (getattr(ev, "operation", "") or "") != "CreateFile":
        return False
    d = (getattr(ev, "detail", "") or "").lower()
    return any(r in d for r in _CREATE_RESULTS)


def is_paging_io(ev) -> bool:
    """캐시 관리자/메모리 매니저의 Paging I/O 쓰기인지 — 실제 기록 주체가 아니다."""
    return "paging i/o" in (getattr(ev, "detail", "") or "").lower()


def is_file_mutation_event(ev) -> bool:
    """파일 내용·존재를 실제로 바꾼 이벤트 (쓰기 · 생성 · 이름변경 · 삭제)."""
    op = getattr(ev, "operation", "") or ""
    return (op == "WriteFile" or is_file_create_event(ev)
            or is_rename_event(ev) or is_delete_event(ev))


def is_reg_key_created(ev) -> bool:
    """RegCreateKey 가 키를 새로 만든 경우만 True (REG_OPENED_EXISTING_KEY 제외)."""
    if (getattr(ev, "operation", "") or "") != "RegCreateKey":
        return False
    return "reg_created_new_key" in (getattr(ev, "detail", "") or "").lower()


def is_reg_write_event(ev) -> bool:
    """레지스트리를 실제로 바꾼 이벤트 (값 설정 · 신규 키 · 삭제 · 이름변경)."""
    op = getattr(ev, "operation", "") or ""
    if op == "RegCreateKey":
        return is_reg_key_created(ev)
    return op in {"RegSetValue", "RegDeleteValue", "RegDeleteKey", "RegRenameKey"}


# ---------------------------------------------------------------------------
# 시각 파싱 — 로캘별 ProcMon "Time of Day" 표기
#   영어  : "5:24:48.8123456 AM",  24시간제: "17:24:48.8123456"
#   한국어: "오전 5:24:48.8123456" / "오후 …"
#   일본어: "午前 …" / "午後 …",  중국어: "上午 …" / "下午 …"
#   Date & Time 열: "11/18/2026 5:24:48.8123456 AM" (날짜 접두 허용)
# ---------------------------------------------------------------------------

_AM_MARKERS = frozenset({"am", "a.m.", "오전", "午前", "上午"})
_PM_MARKERS = frozenset({"pm", "p.m.", "오후", "午後", "下午"})
_TIME_RE = re.compile(
    r"(?:(오전|오후|午前|午後|上午|下午|AM|PM)\s*)?"
    r"(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?"
    r"(?:\s*(AM|PM|A\.M\.|P\.M\.|오전|오후|午前|午後|上午|下午))?",
    re.IGNORECASE,
)


def procmon_time_to_secs(time_str: str) -> float:
    """ProcMon 시각 문자열 → 하루 기준 초. 해석 실패 시 -1.0."""
    try:
        m = _TIME_RE.search(time_str or "")
        if not m:
            return -1.0
        h, mi, s = int(m.group(2)), int(m.group(3)), int(m.group(4))
        frac = float("0." + m.group(5)) if m.group(5) else 0.0
        marker = (m.group(1) or m.group(6) or "").lower()
        if marker in _PM_MARKERS and h < 12:
            h += 12
        elif marker in _AM_MARKERS and h == 12:
            h = 0
        if h > 23 or mi > 59 or s > 60:
            return -1.0
        return h * 3600 + mi * 60 + s + frac
    except Exception:
        return -1.0


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
# CSV 열 매핑 · 인코딩
# ---------------------------------------------------------------------------

# 헤더 이름(소문자) → 필드. ProcMon 기본 열 순서는 아래 _DEFAULT_ORDER 와 같지만
# 분석가가 GUI 에서 열을 추가·재배치하면 /SaveAs 결과도 그 설정을 따른다.
_HEADER_ALIASES: dict[str, str] = {
    "time of day": "time",
    "date & time": "time",
    "time": "time",
    "process name": "process",
    "pid": "pid",
    "operation": "operation",
    "path": "path",
    "result": "result",
    "detail": "detail",
}
_DEFAULT_ORDER: tuple[str, ...] = (
    "time", "process", "pid", "operation", "path", "result", "detail",
)
_REQUIRED_FIELDS: tuple[str, ...] = ("process", "pid", "operation", "path")

# 마지막 parse_csv 호출의 경고 — errors 인자를 넘기지 않는 호출부도 조회할 수 있게.
last_parse_warnings: list[str] = []


def _raise_field_size_limit() -> None:
    """긴 Detail(환경 변수 블록 등)이 csv 기본 상한(128KB)을 넘어 전체 파싱이
    중단되는 것을 막는다. Windows 의 C long 은 32비트라 sys.maxsize 는 거부된다."""
    limit = sys.maxsize
    while limit > 1024:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 16


def _detect_encoding(path: Path) -> str:
    """BOM → UTF-8 엄격 디코딩 → 시스템 ANSI 코드페이지 순으로 인코딩을 고른다.

    errors="replace" 로만 읽으면 ANSI(cp949) 로 저장된 한글 경로가 조용히
    U+FFFD 로 바뀐다. 앞부분을 엄격하게 디코딩해 보고 실패하면 ANSI 로 읽는다.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(256 * 1024)
    except Exception:
        return "utf-8-sig"
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    try:
        # 잘린 마지막 멀티바이트 문자는 무시 (final=False)
        codecs.getincrementaldecoder("utf-8")("strict").decode(head, final=False)
        return "utf-8-sig"
    except UnicodeDecodeError:
        pass
    for enc in ("mbcs", "cp949"):
        try:
            codecs.lookup(enc)
            return enc
        except LookupError:
            continue
    return "utf-8-sig"


def _build_column_map(header: list) -> "tuple[dict | None, list]":
    """헤더 행 → {필드: 열 인덱스}.

    Returns
    -------
    (colmap, missing_required)
        헤더에서 아는 열 이름을 하나도 찾지 못하면 colmap=None (헤더 없는
        파일로 보고 기본 열 순서로 읽는다).
    """
    colmap: dict = {}
    for idx, name in enumerate(header):
        key = _HEADER_ALIASES.get((name or "").strip().strip("﻿").strip('"').strip().lower())
        if key and key not in colmap:
            colmap[key] = idx
    if not colmap:
        return None, []
    missing = [f for f in _REQUIRED_FIELDS if f not in colmap]
    return colmap, missing


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_csv(
    csv_path: Path,
    pid_filter: Optional[set[int]] = None,
    *,
    errors: Optional[list] = None,
) -> list[ProcMonEvent]:
    """Parse a ProcMon CSV file and return a list of :class:`ProcMonEvent`.

    Parameters
    ----------
    csv_path:
        Path to the CSV file exported from ProcMon.
    pid_filter:
        When provided, only events whose PID is in this set are returned.
    errors:
        (선택) 문제 설명을 덧붙일 리스트 — 보통 ``result.errors``. 필수 열이
        없어 읽지 못했거나, 열 순서가 기본과 달라 헤더 이름으로 읽었을 때 기록한다.
        같은 내용이 모듈 변수 :data:`last_parse_warnings` 에도 남는다.

    Returns
    -------
    list[ProcMonEvent]
        Parsed events.  Returns an empty list on any error (file not found,
        malformed rows, etc.).

    Notes
    -----
    열은 위치가 아니라 **헤더 이름**으로 찾는다. 분석가가 ProcMon GUI 에서
    Parent PID·Command Line 같은 열을 추가했어도 PID·Operation 이 밀리지 않는다.
    삭제/이름변경 연산명은 모듈 docstring 의 규칙대로 정규화한다.
    """
    warnings: list[str] = []

    def _warn(msg: str) -> None:
        warnings.append(msg)
        if errors is not None:
            try:
                errors.append(msg)
            except Exception:
                pass

    try:
        csv_path = Path(csv_path)
        if not csv_path.exists():
            return []

        _raise_field_size_limit()
        encoding = _detect_encoding(csv_path)
        events: list[ProcMonEvent] = []

        with csv_path.open(newline="", encoding=encoding, errors="replace") as fh:
            reader = csv.reader(fh)

            try:
                header = next(reader)
            except StopIteration:
                return []
            except csv.Error as exc:
                _warn(f"ProcMon CSV 헤더 읽기 실패: {exc}")
                return []

            colmap, missing = _build_column_map(header)
            pending_rows: list = []
            if colmap is None:
                # 아는 열 이름이 하나도 없음 — 헤더가 없는 파일일 수 있다.
                # 기존 동작(기본 열 순서) 유지, 첫 행도 데이터로 다시 본다.
                colmap = {f: i for i, f in enumerate(_DEFAULT_ORDER)}
                pending_rows = [header]
            else:
                if missing:
                    _warn("ProcMon CSV 필수 열 누락: " + ", ".join(missing)
                          + " (헤더: " + ", ".join(h for h in header if h)[:200] + ")"
                          " — ProcMon 열 설정을 기본값으로 되돌리거나 해당 열을 추가하세요")
                    return []
                order = tuple(f for f, _ in sorted(colmap.items(), key=lambda kv: kv[1]))
                if order != _DEFAULT_ORDER or len(header) != len(_DEFAULT_ORDER):
                    _warn("ProcMon CSV 열 구성이 기본과 다름 — 헤더 이름으로 매핑해 읽음 "
                          f"(열 {len(header)}개)")
                for opt in ("time", "result", "detail"):
                    if opt not in colmap:
                        _warn(f"ProcMon CSV 선택 열 누락: {opt} — 빈 값으로 처리")

            max_idx = max(colmap.values())
            i_time = colmap.get("time")
            i_res  = colmap.get("result")
            i_det  = colmap.get("detail")
            i_proc, i_pid = colmap["process"], colmap["pid"]
            i_op, i_path  = colmap["operation"], colmap["path"]

            def _rows():
                yield from pending_rows
                consecutive_err = 0
                while True:
                    try:
                        row = next(reader)
                        consecutive_err = 0
                        yield row
                    except StopIteration:
                        return
                    except csv.Error as exc:
                        # 한 행의 형식 오류가 전체 이벤트를 버리게 하지 않는다
                        consecutive_err += 1
                        if consecutive_err == 1:
                            _warn(f"ProcMon CSV 행 파싱 오류(건너뜀): {exc}")
                        if consecutive_err > 1000:
                            return

            for row in _rows():
                try:
                    if len(row) <= max_idx:
                        continue

                    time_str  = row[i_time] if i_time is not None else ""
                    process   = row[i_proc]
                    pid_str   = row[i_pid]
                    operation = row[i_op]
                    path      = row[i_path]
                    result    = row[i_res] if i_res is not None else ""
                    detail    = row[i_det] if i_det is not None else ""

                    # Skip noise results early
                    if result in ("BUFFER OVERFLOW", "FAST IO DISALLOWED"):
                        continue

                    try:
                        pid = int(pid_str)
                    except (ValueError, TypeError):
                        pid = 0

                    if pid_filter is not None and pid not in pid_filter:
                        continue

                    canon = canonical_operation(operation, detail)
                    category = _categorize(canon)

                    events.append(
                        ProcMonEvent(
                            time_str=time_str,
                            process=process,
                            pid=pid,
                            operation=canon,
                            path=path,
                            result=result,
                            detail=detail,
                            category=category,
                            raw_operation=operation if canon != operation else "",
                        )
                    )
                except Exception:
                    # Skip malformed rows without aborting the whole parse
                    continue

        return events

    except FileNotFoundError:
        return []
    except Exception as exc:
        _warn(f"ProcMon CSV 파싱 실패: {type(exc).__name__}: {exc}")
        return []
    finally:
        last_parse_warnings[:] = warnings


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
