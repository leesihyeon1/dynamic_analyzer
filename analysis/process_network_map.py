"""
process_network_map.py — ProcMon 네트워크 이벤트 기반 프로세스↔네트워크 연결 매핑.

ProcMon CSV의 TCP/UDP 이벤트를 집계하여 어떤 프로세스가
어떤 외부 IP·포트와 통신했는지 정리합니다.
"""
from __future__ import annotations

import re
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


def _is_private(ip: str) -> bool:
    """RFC1918 / 루프백 / 링크로컬 주소 여부 판별."""
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

        op = ev.operation
        if op in _OUTBOUND_OPS:
            direction = "outbound"
        elif op in _INBOUND_OPS:
            direction = "inbound"
        else:
            continue  # Disconnect 등 무시

        proto = "TCP" if op.startswith("TCP") else "UDP"
        _, _, remote_ip, remote_port = _parse_path(ev.path)

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
            )

    return sorted(
        agg.values(),
        key=lambda c: (-c.event_count, c.process.lower(), c.remote_ip),
    )
