"""
process_network_map.py — ProcMon 네트워크 이벤트 기반 프로세스↔네트워크 연결 매핑.

ProcMon CSV의 TCP/UDP 이벤트를 집계하여 어떤 프로세스가
어떤 외부 IP·포트와 통신했는지 정리합니다.

netstat 기반 보완 함수도 포함합니다 — ProcMon이 Network 이벤트를
캡처하지 못한 경우(필터 설정 등)에 fallback으로 사용합니다.
"""
from __future__ import annotations

import re
import socket
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache

from parsers.procmon_csv import ProcMonEvent, EventCategory
from parsers.pcap_parser import _ip_obj, is_external_ip, normalize_ip


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

# ProcMon 네트워크 경로: "src:port -> dst:port" 형태.
# ProcMon 기본 설정(Show Resolved Network Addresses)에서는 주소가 호스트명
# (DESKTOP-T7RA2LH, dns.google)으로, 포트가 서비스 이름(:https, :smtp,
# :domain)으로 출력된다. IPv6 주소는 [fe80::1] 형태로 출력될 수 있다.
_ARROW_SPLIT_RE = re.compile(r'\s*->\s*')
# 하위 호환용 (숫자 포트 전용 패턴) — 새 코드는 _parse_path 를 사용할 것
_ARROW_RE = re.compile(
    r'([\w\.\-\:\[\]]+):(\d+)\s*->\s*([\w\.\-\:\[\]]+):(\d+)'
)
_SINGLE_RE = re.compile(r'([\w\.\-\:\[\]]+):(\d+)')

# 서비스 이름 → 포트 (socket.getservbyname 실패 시 사용하는 보조 표)
_SERVICE_PORTS: dict[str, int] = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "bootps": 67, "bootpc": 68, "http": 80, "www-http": 80,
    "www": 80, "kerberos": 88, "pop3": 110, "ntp": 123, "epmap": 135,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139, "imap": 143,
    "snmp": 161, "ldap": 389, "https": 443, "microsoft-ds": 445,
    "smtps": 465, "urd": 465, "submission": 587, "ldaps": 636, "imaps": 993,
    "pop3s": 995, "socks": 1080, "ssdp": 1900, "ms-wbt-server": 3389,
    "rdp": 3389, "ws-discovery": 3702, "mdns": 5353, "llmnr": 5355,
    "http-alt": 8080,
}

# 분석 환경 도구 — process_network_map에서 제외하여 노이즈 방지
_ANALYSIS_TOOL_PROCESSES: frozenset[str] = frozenset({
    "ollama.exe", "ollama app.exe",
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

@lru_cache(maxsize=512)
def _port_value(token: str, proto: str | None = None) -> int | None:
    """포트 토큰 → 정수. 숫자 또는 서비스 이름(https, smtp, domain…)을 허용."""
    tok = (token or "").strip()
    if not tok:
        return None
    if tok.isdigit():
        v = int(tok)
        return v if 0 <= v <= 65535 else None
    name = tok.lower()
    protos = [proto.lower()] if proto and proto.lower() in ("tcp", "udp") else []
    protos += [p for p in ("tcp", "udp") if p not in protos]
    for pr in protos:
        try:
            return socket.getservbyname(name, pr)
        except (OSError, TypeError):
            continue
    return _SERVICE_PORTS.get(name)


def _split_endpoint(text: str, proto: str | None) -> tuple[str | None, int | None]:
    """'host:port' → (host, port). 호스트의 IPv6 괄호·IP 표기를 정규화한다."""
    text = (text or "").strip()
    if ":" not in text:
        return None, None
    host, _, port_tok = text.rpartition(":")
    host = host.strip().strip("[]")
    port = _port_value(port_tok, proto)
    if not host or port is None:
        return None, None
    return normalize_ip(host), port


def _parse_path(path: str, proto: str | None = None
                ) -> tuple[str | None, int | None, str | None, int | None]:
    """경로 문자열 → (src, src_port, dst, dst_port). 파싱 실패 시 None 반환.

    - IPv6 주소는 ProcMon에서 [fe80::1] 형태로 출력되므로 괄호를 제거해 반환.
    - src/dst는 IP 주소 또는 호스트명일 수 있음 (ProcMon 이름 해석 설정에 따라 상이).
    - 포트는 숫자 또는 서비스 이름(:https, :smtp, :domain)을 모두 정수로 변환.
    proto("TCP"/"UDP")를 주면 서비스 이름 조회 시 해당 프로토콜을 우선한다.
    """
    if not path:
        return None, None, None, None
    parts = _ARROW_SPLIT_RE.split(path.strip(), maxsplit=1)
    if len(parts) == 2:
        left = parts[0].split()
        right = parts[1].split()
        src, sport = _split_endpoint(left[-1] if left else "", proto)
        dst, dport = _split_endpoint(right[0] if right else "", proto)
        if dst is None:
            return None, None, None, None
        return src, sport, dst, dport
    tokens = path.split()
    host, port = _split_endpoint(tokens[0] if tokens else "", proto)
    if host is not None:
        return None, None, host, port
    return None, None, None, None


def is_ip_literal(s: str | None) -> bool:
    """IP 주소 표기면 True (호스트명이면 False)."""
    return _ip_obj(s) is not None


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
    """외부가 아닌 주소 여부 — 사설/루프백/링크로컬/멀티캐스트/브로드캐스트/로컬 호스트명.

    IP 표기는 pcap_parser.is_external_ip 단일 기준을 따른다. 원격 호스트명
    (예: dns.google)은 판정 불가이므로 외부로 간주한다 (기존 동작 유지).
    """
    if _is_local_hostname(ip):
        return True
    if _ip_obj(ip) is None:
        return False
    return not is_external_ip(ip)


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
        src_ip, src_port, remote_ip, remote_port = _parse_path(ev.path, proto)
        local_port = src_port or 0

        if remote_ip is None or remote_port is None:
            continue
        if not include_private and _is_private(remote_ip):
            continue

        key = (ev.pid, ev.process, proto, remote_ip, remote_port, direction, local_port)
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

# "TCP  local:port  remote:port  STATE  PID" — IPv4/IPv6([..]) 모두,
# 연결 수립(ESTABLISHED)과 응답 대기(SYN_SENT, 미응답 C2 시도) 상태를 수집.
_NETSTAT_RE = re.compile(
    r'^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(ESTABLISHED|SYN_SENT)\s+(\d+)\s*$',
    re.IGNORECASE | re.MULTILINE,
)


def capture_netstat_snapshot() -> list[tuple[str, int, int, str]]:
    """현재 ESTABLISHED TCP 연결을 `netstat -ano`로 캡처.

    Returns
    -------
    list of (remote_ip, remote_port, pid, proc_name, local_port, state)
        사설 IP·루프백·멀티캐스트는 제외됩니다. IPv6 연결과 SYN_SENT(미응답
        연결 시도)도 포함합니다. 앞 4개 원소는 기존 형식과 동일합니다.
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

    return _parse_netstat_output(out, _psutil)


def _parse_netstat_output(out: str, _psutil=None) -> list[tuple]:
    """`netstat -ano` 출력 → (remote_ip, remote_port, pid, proc_name, local_port, state)."""
    results: list[tuple] = []
    for m in _NETSTAT_RE.finditer(out or ""):
        local_port  = int(m.group(2))
        remote_ip   = normalize_ip(m.group(3).strip("[]"))
        remote_port = int(m.group(4))
        state       = m.group(5).upper()
        pid         = int(m.group(6))
        if pid == 0 or _is_private(remote_ip):
            continue
        proc_name = ""
        if _psutil is not None:
            try:
                proc_name = _psutil.Process(pid).name()
            except Exception:
                pass
        results.append((remote_ip, remote_port, pid, proc_name, local_port, state))
    return results


def build_netstat_proc_map(
    snapshots:      list[list[tuple]],
    proc_snapshots: "dict | None" = None,
    focus_pids: set[int] | None = None,
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
    local_ports: dict[tuple[int, str, int], int] = {}  # 최초 관측 로컬 포트

    for snap in snapshots:
        for entry in snap:
            remote_ip, remote_port, pid = entry[0], entry[1], entry[2]
            snap_proc = entry[3] if len(entry) >= 4 else ""
            key = (pid, remote_ip, remote_port)
            agg[key] += 1
            if snap_proc and key not in snap_names:
                snap_names[key] = snap_proc
            if len(entry) >= 5 and entry[4] and key not in local_ports:
                try:
                    local_ports[key] = int(entry[4])
                except (TypeError, ValueError):
                    pass

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
            local_port=local_ports.get(key, 0),
        ))

    return filter_process_connections(sorted(connections, key=lambda c: (-c.event_count, c.process.lower(), c.remote_ip)), focus_pids)


def filter_process_connections(connections, focus_pids: set[int] | None = None):
    """수집 방식에 관계없이 추적 범위와 분석 도구 제외 규칙 적용.

    명시적으로 추적하는 PID는 이름이 분석 도구와 같아도 보존한다.
    """
    return [c for c in connections
            if (c.pid in focus_pids if focus_pids is not None
                else c.process.lower() not in _ANALYSIS_TOOL_PROCESSES)]
