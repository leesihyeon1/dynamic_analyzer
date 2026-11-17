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
둘 다 로컬 시간 자정 기준 초수로 변환해 2초 이내 차이면 매핑한다.

Dnscache 대리 질의
------------------
일반 Win32 이름 해석(getaddrinfo/DnsQuery)은 DNS Client 서비스(Dnscache,
svchost.exe)가 UDP/53 패킷을 대신 보낸다. 이 경우 ProcMon 매칭 결과는
svchost 이므로 실제 요청 프로세스로 볼 수 없다 → attributed=False 로 두고
note 에 사유를 남긴다. 실제 요청 PID는 DNS-Client ETW(core/dns_trace.py)가 준다.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime


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
    note:       str  = ""      # 귀속 보류 사유·응답 상태 등 부가 설명
    status:     int | None = None   # DNS 응답 상태 (0=성공, 9003=NXDOMAIN, None=미상)
    source:     str  = ""      # "pcap" | "etw" — 귀속 근거


# ── 내부 파서 ─────────────────────────────────────────────────────────────────

# 하위 호환용 — 경로 파싱은 analysis.process_network_map._parse_path 로 통일
# (하이픈 호스트명 DESKTOP-XXXX, 서비스 이름 포트 :domain 지원).
_UDP_PATH_RE = re.compile(
    r'[\w\.\-\[\]:]+:(\d+)\s*->\s*[\w\.\-\[\]:]+:(\d+)',
    re.ASCII,
)

# DNS Client 서비스(Dnscache)를 호스팅하는 프로세스 — 대리 질의 송신자
_DNS_PROXY_PROCESSES: frozenset[str] = frozenset({"svchost.exe"})
_PROXY_NOTE = "Dnscache(svchost) 대리 질의 — 실제 요청 프로세스 미상 (DNS-Client ETW 참고)"


def _udp_ports(path: str) -> tuple[int | None, int | None]:
    """ProcMon UDP 경로 → (src_port, dst_port)."""
    try:
        from analysis.process_network_map import _parse_path
        _, sport, _, dport = _parse_path(path or "", "UDP")
        return sport, dport
    except Exception:
        m = _UDP_PATH_RE.search(path or "")
        if not m:
            return None, None
        return int(m.group(1)), int(m.group(2))

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
    """Unix timestamp → 로컬 시간 기준 자정부터 초수.

    해당 시각의 실제 DST 적용 여부를 반영하도록 datetime.fromtimestamp 를 쓴다
    (time.daylight 는 "DST 가 있는 지역"일 뿐 "지금 DST 중"이 아니다).
    """
    try:
        dt = datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return -1.0
    return dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1_000_000


def _secs_diff(a: float, b: float) -> float:
    """자정 기준 초수 차이 — 자정을 넘는 경우도 고려."""
    d = abs(a - b) % 86400
    return min(d, 86400 - d)


# ── 공개 API ──────────────────────────────────────────────────────────────────

def correlate_dns(
    raw_queries,          # list[DnsRawQuery]  from pcap_parser.PcapResult
    procmon_events,       # list[ProcMonEvent] from parsers.procmon_csv
    time_window: float = 2.0,
    sample_pids=None,     # 선택: 샘플 PID — svchost 라도 샘플이면 귀속 유지
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
        attributed=False → ProcMon에 매칭 이벤트 없음 (프로세스 미상) 또는
                           Dnscache(svchost) 대리 질의 (note 참고)
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
                answers=list(q.answers or []), timestamp=q.pkt_time, attributed=False,
                source="pcap",
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
        src_port, dst_port = _udp_ports(ev.path)
        if not src_port or dst_port != 53:
            continue
        pm_secs = _procmon_time_to_secs(ev.time_str)
        if pm_secs < 0:
            continue
        port_map[src_port].append((pm_secs, ev.pid, ev.process))

    # ── 매핑 ─────────────────────────────────────────────────────────
    results: list[AttributedDnsQuery] = []

    sample_pids = set(sample_pids or ())
    for q in raw_queries:
        pcap_secs  = _pcap_time_to_secs(q.pkt_time)
        candidates = port_map.get(q.src_port, []) if pcap_secs >= 0 else []

        matched_pid  = 0
        matched_proc = ""

        if candidates:
            # 타임스탬프가 가장 가까운 후보 선택
            best_dt, best_pid, best_proc = min(
                ((_secs_diff(pm, pcap_secs), pid, proc) for pm, pid, proc in candidates),
                key=lambda x: x[0],
            )
            if best_dt <= time_window:
                matched_pid  = best_pid
                matched_proc = best_proc

        attributed = matched_pid != 0
        note = ""
        if (attributed and (matched_proc or "").lower() in _DNS_PROXY_PROCESSES
                and matched_pid not in sample_pids):
            attributed = False
            note = _PROXY_NOTE

        results.append(AttributedDnsQuery(
            pid=matched_pid,
            process=matched_proc,
            name=q.name,
            qtype=q.qtype,
            answers=list(q.answers or []),
            timestamp=q.pkt_time,
            attributed=attributed,
            note=note,
            source="pcap",
        ))

    return results


def merge_dns_attributions(existing, new_rows, window: float = 2.0):
    """DNS 귀속 행 병합 — (이름, ±window 초) 가 같은 행은 하나로 합친다.

    existing 은 제자리에서 갱신한다: 기존 행이 미귀속(또는 Dnscache 대리)이고
    새 행이 귀속 확정이면 기존 행의 PID/프로세스/귀속 여부를 새 행 값으로 올리고,
    응답 주소·상태는 합친다. 중복이 아닌 새 행만 리스트로 반환한다
    (호출 측이 existing.extend(반환값) 하면 된다).
    """
    existing = existing if existing is not None else []
    by_name: dict[str, list] = defaultdict(list)
    for row in existing:
        by_name[(row.name or "").rstrip(".").lower()].append(row)

    added = []
    for row in new_rows or []:
        key = (row.name or "").rstrip(".").lower()
        dup = None
        for old in by_name.get(key, ()):
            if abs((old.timestamp or 0) - (row.timestamp or 0)) <= window:
                if not old.attributed or not row.attributed or old.pid == row.pid:
                    dup = old
                    break
        if dup is None:
            by_name[key].append(row)
            added.append(row)
            continue
        if row.attributed and not dup.attributed:
            dup.pid, dup.process, dup.attributed = row.pid, row.process, True
            dup.note = ""
            dup.source = row.source or dup.source
        for a in row.answers or []:
            if a not in dup.answers:
                dup.answers.append(a)
        if dup.status is None and row.status is not None:
            dup.status = row.status
    return added
