"""
process_network_map.py — ProcMon 네트워크 이벤트 기반 프로세스↔네트워크 연결 매핑.

ProcMon CSV의 TCP/UDP 이벤트를 집계하여 어떤 프로세스가
어떤 외부 IP·포트와 통신했는지 정리합니다.

netstat 기반 보완 함수도 포함합니다 — ProcMon이 Network 이벤트를
캡처하지 못한 경우(필터 설정 등)에 fallback으로 사용합니다.
"""
from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass

from parsers.procmon_csv import ProcMonEvent, EventCategory


# ---------------------------------------------------------------------------
# 데이터 모델
# ---------------------------------------------------------------------------

@dataclass
class ProcNetConnection:
    """프로세스 단위 네트워크 연결 집계 레코드."""

    pid:         int
    process:     str
    proto:       str   # "TCP" | "UDP"
    remote_ip:   str
    remote_port: int
    direction:   str   # "outbound" | "inbound"
    event_count: int = 0
    local_port:  int = 0   # 로컬 ephemeral 포트 (src_port) — 세션 역추적용


# ---------------------------------------------------------------------------
# 내부 상수
# ---------------------------------------------------------------------------

# ProcMon 네트워크 경로: "src:port -> dst:port" 형태 파싱.
# dst는 순수 IP 주소 또는 ProcMon의 "네트워크 주소 해석" 옵션으로 변환된
# 호스트명(예: dns.google) 모두 허용.  IPv6 주소는 [::1] 형태로 출력됨.
_ARROW_RE = re.compile(
    r'([\w\.\-\:\[\]]+):(\d+)\s*->\s*([\w\.\-\:\[\]]+):(\d+)'
)
# 단독 "host:port" 형태 파싱
_SINGLE_RE = re.compile(r'([\w\.\-\:\[\]]+):(\d+)')

# 분석 환경 도구 — process_network_map에서 제외하여 노이즈 방지
_ANALYSIS_TOOL_PROCESSES: frozenset[str] = frozenset({
    "procmon.exe", "procmon64.exe", "procmon64a.exe",
    "systeminformer.exe", "processhacker.exe", "procexp.exe", "procexp64.exe",
    "hollows_hunter.exe", "pe-sieve64.exe", "pe-sieve32.exe",
    "wireshark.exe", "tshark.exe", "dumpcap.exe",
    "fakenet.exe", "fakenet-ng.exe",
    "x64dbg.exe", "x32dbg.exe", "windbg.exe", "ollydbg.exe",
    "picpick.exe", "greenshot.exe", "sharex.exe",
    "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
})

# 아웃바운드 판정 오퍼레이션
_OUTBOUND_OPS: frozenset[str] = frozenset({
    "TCP Connect", "TCP Send", "TCP Reconnect",
    "UDP Send",
})
# 인바운드 판정 오퍼레이션
_INBOUND_OPS: frozenset[str] = frozenset({
    "TCP Receive", "UDP Receive",
})


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------

def _parse_path(path: str) -> tuple[str | None, int | None, str | None, int | None]:
    """경로 문자열 → (src, src_port, dst, dst_port). 파싱 실패 시 None 반환.

    IPv6 주소는 ProcMon에서 [fe80::1] 형태로 출력되므로 괄호를 제거해 반환.
    dst는 IP 주소 또는 호스트명일 수 있음 (ProcMon 설정에 따라 상이).
    """
    m = _ARROW_RE.search(path)
    if m:
        return m.group(1).strip('[]'), int(m.group(2)), m.group(3).strip('[]'), int(m.group(4))
    m = _SINGLE_RE.search(path)
    if m:
        return None, None, m.group(1).strip('[]'), int(m.group(2))
    return None, None, None, None


_LOCAL_HOSTNAME_SUFFIXES = (".local", ".localdomain", ".lan", ".internal", ".home", ".corp")
_LOCAL_HOSTNAME_EXACT   = frozenset({"localhost", "::1", "broadcasthost"})

def _is_local_hostname(s: str) -> bool:
    """ProcMon이 로컬 IP를 호스트명으로 해석한 경우를 탐지한다.

    예: DESKTOP-T7RA2LH.localdomain, WIN-ABC.local, localhost 등
    """
    if not s:
        return False
    sl = s.lower()
    if sl in _LOCAL_HOSTNAME_EXACT:
        return True
    for sfx in _LOCAL_HOSTNAME_SUFFIXES:
        if sl.endswith(sfx):
            return True
    # 점 없는 단일 레이블이면 로컬 hostname (예: DESKTOP-T7RA2LH)
    if "." not in sl:
        try:
            int(sl)   # 숫자만이면 IP 단편 → 로컬 아님
            return False
        except ValueError:
            return True  # 문자 단일레이블 = 로컬 hostname
    return False


def _is_private(ip: str) -> bool:
    """RFC1918 / 루프백 / 링크로컬 / 로컬 호스트명 여부 판별."""
    if _is_local_hostname(ip):
        return True
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or (a == 169 and b == 254)
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 공개 API
# ---------------------------------------------------------------------------

def build_process_network_map(
    events: list[ProcMonEvent],
    include_private: bool = False,
) -> list[ProcNetConnection]:
    """
    ProcMon 네트워크 이벤트에서 프로세스↔네트워크 연결 목록을 생성.

    Parameters
    ----------
    events:
        ``filter_events()`` 를 통과한 ProcMon 이벤트 목록.
    include_private:
        True 이면 사설 IP 연결도 포함. 기본은 외부 IP만 포함.

    Returns
    -------
    list[ProcNetConnection]
        (pid, process, proto, remote_ip, remote_port, direction) 기준으로
        중복 제거 후 event_count 내림차순 정렬된 목록.
    """
    # key: (pid, process, proto, remote_ip, remote_port, direction)
    agg: dict[tuple, ProcNetConnection] = {}

    for ev in events:
        if ev.category != EventCategory.NETWORK:
            continue
        if ev.process.lower() in _ANALYSIS_TOOL_PROCESSES:
            continue  # 분석 도구 자체 네트워크 활동 제외

        op = ev.operation
        if op in _OUTBOUND_OPS:
            direction = "outbound"
        elif op in _INBOUND_OPS:
            direction = "inbound"
        else:
            continue  # Disconnect 등 무시

        proto = "TCP" if op.startswith("TCP") else "UDP"
        src_ip, src_port, remote_ip, remote_port = _parse_path(ev.path)
        local_port = src_port or 0

        if remote_ip is None or remote_port is None:
            continue
        if not include_private and _is_private(remote_ip):
            continue

        key = (ev.pid, ev.process, proto, remote_ip, remote_port, direction)
        if key in agg:
            agg[key].event_count += 1
        else:
            agg[key] = ProcNetConnection(
                pid=ev.pid,
                process=ev.process,
                proto=proto,
                remote_ip=remote_ip,
                remote_port=remote_port,
                direction=direction,
                event_count=1,
                local_port=local_port,
            )

    return sorted(
        agg.values(),
        key=lambda c: (-c.event_count, c.process.lower(), c.remote_ip),
    )


# ---------------------------------------------------------------------------
# netstat 기반 보완 — ProcMon Network 이벤트 부재 시 fallback
# ---------------------------------------------------------------------------

_NETSTAT_RE = re.compile(
    r'TCP\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\s+ESTABLISHED\s+(\d+)',
    re.IGNORECASE,
)


def capture_netstat_snapshot() -> list[tuple[str, int, int, str]]:
    """현재 ESTABLISHED TCP 연결을 `netstat -ano`로 캡처.

    Returns
    -------
    list of (remote_ip, remote_port, pid, proc_name)
        사설 IP 및 루프백은 제외됩니다.
        proc_name은 캡처 시점에 psutil로 즉시 조회합니다 — 프로세스가
        분석 종료 후 종료되더라도 이름이 보존됩니다.
    """
    try:
        out = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=6,
        ).stdout
    except Exception:
        return []

    try:
        import psutil as _psutil
    except ImportError:
        _psutil = None  # type: ignore[assignment]

    results: list[tuple[str, int, int, str]] = []
    for m in _NETSTAT_RE.finditer(out):
        remote_ip   = m.group(1)
        remote_port = int(m.group(2))
        pid         = int(m.group(3))
        if not _is_private(remote_ip):
            proc_name = ""
            if _psutil is not None:
                try:
                    proc_name = _psutil.Process(pid).name()
                except Exception:
                    pass
            results.append((remote_ip, remote_port, pid, proc_name))
    return results


def build_netstat_proc_map(
    snapshots:      list[list[tuple]],
    proc_snapshots: "dict | None" = None,
) -> list[ProcNetConnection]:
    """netstat 스냅샷 목록 → ProcNetConnection 목록.

    여러 스냅샷에서 동일한 (pid, remote_ip, remote_port) 조합이
    반복될수록 event_count가 높아집니다.

    Parameters
    ----------
    snapshots:
        ``capture_netstat_snapshot()`` 반환값 목록.
        4-튜플 (remote_ip, remote_port, pid, proc_name) — 캡처 시점 이름 포함.
        구형 3-튜플 (remote_ip, remote_port, pid) 도 허용합니다.
    proc_snapshots:
        ``dict[int, ProcessSnapshot]`` — PID → 프로세스 정보 (보조 fallback).
    """
    if not snapshots:
        return []

    agg: dict[tuple[int, str, int], int] = defaultdict(int)
    snap_names: dict[tuple[int, str, int], str] = {}  # 캡처 시점 이름 (최초 비어있지 않은 값)

    for snap in snapshots:
        for entry in snap:
            remote_ip, remote_port, pid = entry[0], entry[1], entry[2]
            snap_proc = entry[3] if len(entry) >= 4 else ""
            key = (pid, remote_ip, remote_port)
            agg[key] += 1
            if snap_proc and key not in snap_names:
                snap_names[key] = snap_proc

    connections: list[ProcNetConnection] = []
    for (pid, remote_ip, remote_port), count in agg.items():
        key = (pid, remote_ip, remote_port)
        # 우선순위: ① 캡처 시점 이름 → ② proc_after_snapshot → ③ psutil 라이브 → ④ pid_{pid}
        proc_name = snap_names.get(key, "")
        if not proc_name and proc_snapshots and pid in proc_snapshots:
            ps = proc_snapshots[pid]
            proc_name = getattr(ps, "name", "") or ""
        if not proc_name:
            try:
                import psutil
                proc_name = psutil.Process(pid).name()
            except Exception:
                proc_name = f"pid_{pid}"

        connections.append(ProcNetConnection(
            pid=pid,
            process=proc_name,
            proto="TCP",
            remote_ip=remote_ip,
            remote_port=remote_port,
            direction="outbound",
            event_count=count,
        ))

    return sorted(connections, key=lambda c: (-c.event_count, c.process.lower(), c.remote_ip))
