"""
프로세스별 행위 역색인 — ProcMon 이벤트를 PID 기준으로 재조직.

HTML 보고서 프로세스 행 expand 패널에 사용됩니다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProcessBehavior:
    pid:           int
    name:          str
    files_written: list[str]              = field(default_factory=list)
    files_deleted: list[str]              = field(default_factory=list)
    reg_written:   list[str]              = field(default_factory=list)
    reg_deleted:   list[str]              = field(default_factory=list)
    children:      list[tuple[int, str]]  = field(default_factory=list)  # (child_pid, child_name)
    tcp_conns:     list[tuple[str, int]]  = field(default_factory=list)  # (remote_ip, port)
    dns_queries:   list[str]              = field(default_factory=list)


_WRITE_OPS   = frozenset({"WriteFile"})
_DELETE_OPS  = frozenset({"DeleteFile", "SetDispositionInformationFile"})
_REG_WR_OPS  = frozenset({"RegSetValue", "RegCreateKey", "RegRenameKey"})
_REG_DEL_OPS = frozenset({"RegDeleteValue", "RegDeleteKey"})


def build_process_behavior_map(
    filtered_events,       # list[ProcMonEvent]
    dns_attributed,        # list[AttributedDnsQuery]
    process_network_map,   # list[ProcNetConnection]
    new_processes,         # list[ProcessSnapshot]  — 부모-자식 관계용
) -> dict[int, ProcessBehavior]:
    """filtered_events + 네트워크/DNS 결과 → {pid: ProcessBehavior}"""

    behaviors: dict[int, ProcessBehavior] = {}

    def _get(pid: int, name: str) -> ProcessBehavior:
        if pid not in behaviors:
            behaviors[pid] = ProcessBehavior(pid=pid, name=name or f"PID {pid}")
        return behaviors[pid]

    try:
        from parsers.procmon_csv import EventCategory
    except ImportError:
        return {}

    # ── ProcMon 이벤트 파싱 ───────────────────────────────────────────
    for ev in (filtered_events or []):
        b = _get(ev.pid, ev.process)

        if ev.category == EventCategory.FILE:
            if ev.operation in _WRITE_OPS and ev.path:
                if ev.path not in b.files_written:
                    b.files_written.append(ev.path)
            elif ev.operation in _DELETE_OPS and ev.path:
                if ev.path not in b.files_deleted:
                    b.files_deleted.append(ev.path)

        elif ev.category == EventCategory.REGISTRY:
            if ev.operation in _REG_WR_OPS and ev.path:
                if ev.path not in b.reg_written:
                    b.reg_written.append(ev.path)
            elif ev.operation in _REG_DEL_OPS and ev.path:
                if ev.path not in b.reg_deleted:
                    b.reg_deleted.append(ev.path)

    # ── 부모-자식 관계 (new_processes ppid 사용) ──────────────────────
    pid_to_name: dict[int, str] = {
        p.pid: (getattr(p, "name", "") or f"PID {p.pid}")
        for p in (new_processes or [])
    }
    for p in (new_processes or []):
        ppid = getattr(p, "ppid", None)
        if ppid and ppid in behaviors:
            child_entry = (p.pid, pid_to_name.get(p.pid, f"PID {p.pid}"))
            parent = behaviors[ppid]
            if child_entry not in parent.children:
                parent.children.append(child_entry)

    # ── TCP 연결 (process_network_map) ───────────────────────────────
    for conn in (process_network_map or []):
        b = _get(conn.pid, conn.process)
        entry = (conn.remote_ip, conn.remote_port)
        if entry not in b.tcp_conns:
            b.tcp_conns.append(entry)

    # ── DNS 쿼리 (dns_attributed) ─────────────────────────────────────
    for q in (dns_attributed or []):
        if q.attributed and q.pid:
            b = _get(q.pid, q.process)
            if q.name not in b.dns_queries:
                b.dns_queries.append(q.name)

    return behaviors
