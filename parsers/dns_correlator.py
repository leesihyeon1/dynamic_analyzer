"""
DNS 쿼리 ↔ 프로세스 귀속 상관 분석.

원리
----
DNS 쿼리는 UDP로 전송된다.  클라이언트 OS가 각 쿼리마다 임시(ephemeral)
소스 포트를 할당하므로, 동일 시간대에 같은 소스 포트를 가진 이벤트는
같은 DNS 트랜잭션이다.

  PCAP  : UDP src_port=52341 dst_port=53  → DNSQuery(name="api.ipify.org")
  ProcMon: UDP Send  path="192.168.1.1:52341 -> 8.8.8.8:53"  PID=5168

  → api.ipify.org 를 요청한 프로세스는 PID 5168

시간 기준
---------
PCAP 타임스탬프는 Unix epoch, ProcMon은 "HH:MM:SS.ffffff [AM|PM]" 형식.
둘 다 자정 기준 초수로 변환해 2초 이내 차이면 매핑한다.
"""
from __future__ import annotations

import re
import time as _time
from collections import defaultdict
from dataclasses import dataclass, field


# ── 데이터클래스 ─────────────────────────────────────────────────────────────

@dataclass
class AttributedDnsQuery:
    """프로세스가 귀속된 DNS 쿼리."""
    pid:        int
    process:    str
    name:       str
    qtype:      str
    answers:    list[str] = field(default_factory=list)
    timestamp:  float = 0.0
    attributed: bool = True    # False → ProcMon 이벤트와 매핑 실패 (프로세스 미상)


# ── 내부 파서 ─────────────────────────────────────────────────────────────────

_UDP_PATH_RE = re.compile(
    r'[\w\.\[\]:]+:(\d+)\s*->\s*[\w\.\[\]:]+:(\d+)',
    re.ASCII,
)

_PM_TIME_RE = re.compile(
    r'^(\d{1,2}):(\d{2}):(\d{2})\.(\d+)(?:\s+(AM|PM))?',
    re.IGNORECASE,
)


def _procmon_time_to_secs(time_str: str) -> float:
    """ProcMon 시간 문자열 → 자정 기준 초수 (float). 파싱 실패 시 -1."""
    m = _PM_TIME_RE.match(time_str.strip())
    if not m:
        return -1.0
    h  = int(m.group(1))
    mi = int(m.group(2))
    s  = int(m.group(3))
    us = int(m.group(4).ljust(6, "0")[:6])
    suffix = (m.group(5) or "").upper()
    if suffix == "PM" and h != 12:
        h += 12
    elif suffix == "AM" and h == 12:
        h = 0
    return h * 3600 + mi * 60 + s + us / 1_000_000


def _pcap_time_to_secs(ts: float) -> float:
    """Unix timestamp → 로컬 시간 기준 자정부터 초수."""
    tz_offset = -_time.timezone if not _time.daylight else -_time.altzone
    return (ts + tz_offset) % 86400


# ── 공개 API ──────────────────────────────────────────────────────────────────

def correlate_dns(
    raw_queries,          # list[DnsRawQuery]  from pcap_parser.PcapResult
    procmon_events,       # list[ProcMonEvent] from parsers.procmon_csv
    time_window: float = 2.0,
) -> list[AttributedDnsQuery]:
    """
    PCAP DNS 쿼리를 ProcMon UDP Send :53 이벤트와 src_port로 매핑.

    Parameters
    ----------
    raw_queries:
        pcap_parser.PcapResult.raw_dns_queries
    procmon_events:
        orchestrator의 result.procmon_events (전체 ProcMon 이벤트)
    time_window:
        허용 타임스탬프 차이 (초). DNS는 RTT가 짧으므로 2s면 충분.

    Returns
    -------
    list[AttributedDnsQuery]
        attributed=True  → PID / 프로세스명 확정
        attributed=False → ProcMon에 매칭 이벤트 없음 (프로세스 미상)
    """
    if not raw_queries:
        return []

    try:
        from parsers.procmon_csv import EventCategory
    except ImportError:
        # procmon 없을 때 — 귀속 없이 그대로 반환
        return [
            AttributedDnsQuery(
                pid=0, process="", name=q.name, qtype=q.qtype,
                answers=q.answers, timestamp=q.pkt_time, attributed=False,
            )
            for q in raw_queries
        ]

    # ── ProcMon에서 UDP Send to :53 이벤트 수집 ──────────────────────
    # key: ephemeral_src_port → list[(pm_secs, pid, process_name)]
    port_map: dict[int, list[tuple[float, int, str]]] = defaultdict(list)

    for ev in (procmon_events or []):
        if ev.category != EventCategory.NETWORK:
            continue
        if not ev.operation.startswith("UDP Send"):
            continue
        m = _UDP_PATH_RE.match(ev.path or "")
        if not m:
            continue
        src_port = int(m.group(1))
        dst_port = int(m.group(2))
        if dst_port != 53:
            continue
        pm_secs = _procmon_time_to_secs(ev.time_str)
        if pm_secs < 0:
            continue
        port_map[src_port].append((pm_secs, ev.pid, ev.process))

    # ── 매핑 ─────────────────────────────────────────────────────────
    results: list[AttributedDnsQuery] = []

    for q in raw_queries:
        pcap_secs  = _pcap_time_to_secs(q.pkt_time)
        candidates = port_map.get(q.src_port, [])

        matched_pid  = 0
        matched_proc = ""

        if candidates:
            # 타임스탬프가 가장 가까운 후보 선택
            best_dt, best_pid, best_proc = min(
                ((abs(pm - pcap_secs), pid, proc) for pm, pid, proc in candidates),
                key=lambda x: x[0],
            )
            if best_dt <= time_window:
                matched_pid  = best_pid
                matched_proc = best_proc

        results.append(AttributedDnsQuery(
            pid=matched_pid,
            process=matched_proc,
            name=q.name,
            qtype=q.qtype,
            answers=q.answers,
            timestamp=q.pkt_time,
            attributed=(matched_pid != 0),
        ))

    return results
