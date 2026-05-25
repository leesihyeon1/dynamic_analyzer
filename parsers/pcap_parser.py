"""Parse PCAP files into structured network-activity objects.

Improvements over v1:
  - TLS SNI extraction from ClientHello (HTTPS C2 domain detection)
  - DNS response → IP mapping (domain ↔ IP correlation)
  - Shannon entropy per domain (DGA / random domain detection)
  - Beaconing detection (periodic C2 heartbeat)
  - Per-connection byte volume (exfiltration sizing)
  - Suspicious port flagging
  - DNS tunneling heuristics (long names, high query rate)
  - HTTP: Content-Length, Referer, cookie presence

Requires scapy; degrades gracefully when not installed.
"""

from __future__ import annotations

import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional scapy import
# ---------------------------------------------------------------------------

SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw  # type: ignore
    try:
        from scapy.layers.http import HTTPRequest as ScapyHTTPRequest  # type: ignore
    except ImportError:
        ScapyHTTPRequest = None  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 악성코드가 자주 사용하는 비표준 포트
SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444, 4445, 4446,   # Metasploit default
    1337, 31337,        # 전통적 백도어
    6666, 6667, 6668,   # IRC
    8080, 8443, 8888,   # 대체 HTTP/S
    9001, 9050, 9150,   # Tor
    2222, 2323,         # 대체 SSH/Telnet
    3389,               # RDP
    5900,               # VNC
    1080,               # SOCKS
})

# 잘 알려진 정상 포트 (연결 통계에서 강조 제외)
BENIGN_PORTS: frozenset[int] = frozenset({80, 443, 53, 123, 67, 68})

# DGA 탐지용 엔트로피 임계값 (서브도메인 기준)
DGA_ENTROPY_THRESHOLD = 3.5

# DNS 터널링 의심 기준: 단일 베이스 도메인에 대한 최소 쿼리 수
DNS_TUNNEL_QUERY_THRESHOLD = 20

# DNS 터널링 의심 기준: 서브도메인 최소 길이
DNS_TUNNEL_LABEL_LEN = 30

# 비콘 탐지: 최소 반복 횟수, 최대 지터 비율
BEACON_MIN_COUNT = 5
BEACON_MAX_JITTER = 0.30   # 30% 이내 편차면 비콘으로 판단

_QTYPE_MAP: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NetworkConnection:
    proto:      str
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    count:      int   = 1
    bytes_out:  int   = 0    # 송신 바이트 (src→dst)
    bytes_in:   int   = 0    # 수신 바이트 (dst→src)
    first_seen: float = 0.0  # Unix timestamp
    last_seen:  float = 0.0
    suspicious_port: bool = False


@dataclass
class DNSQuery:
    name:         str
    qtype:        str
    response_ips: list[str] = field(default_factory=list)  # A/AAAA 응답 IP
    entropy:      float = 0.0    # 서브도메인 Shannon 엔트로피
    suspicious:   bool  = False  # DGA 의심 or 터널링 의심


@dataclass
class HTTPRequest:
    method:         str
    host:           str
    path:           str
    user_agent:     str
    content_length: int  = 0
    referer:        str  = ""
    has_cookie:     bool = False


@dataclass
class TLSInfo:
    """TLS ClientHello에서 추출한 SNI 정보"""
    sni:      str         # 서버 이름 (복호화 없이 추출)
    dst_ip:   str
    dst_port: int


@dataclass
class BeaconCandidate:
    """주기적 C2 연결 패턴 후보"""
    dst_ip:        str
    dst_port:      int
    count:         int
    interval_avg:  float   # 평균 연결 간격 (초)
    interval_std:  float   # 표준편차
    jitter_ratio:  float   # std / avg


@dataclass
class PcapSummary:
    """전체 캡처 통계"""
    total_packets:   int = 0
    total_bytes_out: int = 0   # 외부로 나간 총 바이트
    total_bytes_in:  int = 0
    unique_dst_ips:  int = 0
    unique_domains:  int = 0


@dataclass
class PcapResult:
    connections:        list[NetworkConnection] = field(default_factory=list)
    dns_queries:        list[DNSQuery]          = field(default_factory=list)
    http_requests:      list[HTTPRequest]       = field(default_factory=list)
    tls_info:           list[TLSInfo]           = field(default_factory=list)
    beacon_candidates:  list[BeaconCandidate]   = field(default_factory=list)
    suspicious_domains: list[str]               = field(default_factory=list)
    dns_tunnel_suspects:list[str]               = field(default_factory=list)
    summary:            PcapSummary             = field(default_factory=PcapSummary)
    # 역참조용
    raw_ips:     set[str] = field(default_factory=set)
    raw_domains: set[str] = field(default_factory=set)
    # DNS A/AAAA 응답: IP → [domain]
    ip_to_domain: dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:            return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168:      return True
        if a == 127:           return True
        if a == 169 and b == 254:      return True
    except (ValueError, AttributeError):
        pass
    return False


def _shannon_entropy(s: str) -> float:
    """문자열의 Shannon 엔트로피 계산"""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _subdomain_entropy(fqdn: str) -> float:
    """FQDN에서 서브도메인 부분(첫 레이블)의 엔트로피"""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) <= 2:
        return _shannon_entropy(parts[0])
    # 첫 번째 레이블(서브도메인)
    return _shannon_entropy(parts[0])


def _base_domain(fqdn: str) -> str:
    """FQDN → eTLD+1 근사 (단순 상위 2레이블)"""
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


# ---------------------------------------------------------------------------
# TLS SNI 추출 (scapy Raw 레이어에서 직접 파싱)
# ---------------------------------------------------------------------------

def _extract_tls_sni(raw_bytes: bytes) -> Optional[str]:
    """
    TLS ClientHello 패킷에서 SNI(Server Name Indication)를 추출.

    TLS 레코드 구조:
      [0]    Content Type  (0x16 = Handshake)
      [1-2]  Version
      [3-4]  Length
      [5]    Handshake Type (0x01 = ClientHello)
      ...
      Extensions → SNI extension (type 0x0000)
    """
    try:
        if len(raw_bytes) < 6:
            return None
        # TLS Handshake record
        if raw_bytes[0] != 0x16:
            return None
        # ClientHello
        if raw_bytes[5] != 0x01:
            return None

        # ClientHello 길이
        hs_len = int.from_bytes(raw_bytes[6:9], "big")
        if len(raw_bytes) < 9 + hs_len:
            return None

        # Version(2) + Random(32) + SessionID length(1)
        offset = 9 + 2 + 32
        if offset >= len(raw_bytes):
            return None

        sid_len = raw_bytes[offset]
        offset += 1 + sid_len

        # Cipher suites
        if offset + 2 > len(raw_bytes):
            return None
        cs_len = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        offset += 2 + cs_len

        # Compression methods
        if offset + 1 > len(raw_bytes):
            return None
        comp_len = raw_bytes[offset]
        offset += 1 + comp_len

        # Extensions length
        if offset + 2 > len(raw_bytes):
            return None
        ext_total = int.from_bytes(raw_bytes[offset:offset + 2], "big")
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end and offset + 4 <= len(raw_bytes):
            ext_type = int.from_bytes(raw_bytes[offset:offset + 2], "big")
            ext_len  = int.from_bytes(raw_bytes[offset + 2:offset + 4], "big")
            offset += 4

            if ext_type == 0x0000:  # SNI
                # SNI list length(2) + type(1) + name length(2) + name
                if offset + 5 <= len(raw_bytes):
                    name_len = int.from_bytes(raw_bytes[offset + 3:offset + 5], "big")
                    name_start = offset + 5
                    if name_start + name_len <= len(raw_bytes):
                        return raw_bytes[name_start:name_start + name_len].decode("ascii", errors="replace")
                return None

            offset += ext_len

    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# HTTP raw 파싱
# ---------------------------------------------------------------------------

_HTTP_REQ_RE  = re.compile(rb"^(?P<method>[A-Z]{3,7})\s+(?P<path>\S+)\s+HTTP/\d", re.MULTILINE)
_HOST_RE      = re.compile(rb"^Host:\s*(?P<v>[^\r\n]+)",           re.MULTILINE | re.IGNORECASE)
_UA_RE        = re.compile(rb"^User-Agent:\s*(?P<v>[^\r\n]+)",     re.MULTILINE | re.IGNORECASE)
_CL_RE        = re.compile(rb"^Content-Length:\s*(?P<v>\d+)",      re.MULTILINE | re.IGNORECASE)
_REF_RE       = re.compile(rb"^Referer:\s*(?P<v>[^\r\n]+)",        re.MULTILINE | re.IGNORECASE)
_COOKIE_RE    = re.compile(rb"^Cookie:\s*",                        re.MULTILINE | re.IGNORECASE)


def _parse_http_raw(raw_bytes: bytes) -> Optional[HTTPRequest]:
    m = _HTTP_REQ_RE.search(raw_bytes)
    if not m:
        return None
    method = m.group("method").decode(errors="replace")
    path   = m.group("path").decode(errors="replace")

    def _get(pattern):
        r = pattern.search(raw_bytes)
        return r.group("v").decode(errors="replace").strip() if r else ""

    host    = _get(_HOST_RE)
    ua      = _get(_UA_RE)
    referer = _get(_REF_RE)
    cl_str  = _get(_CL_RE)
    cl      = int(cl_str) if cl_str.isdigit() else 0
    cookie  = bool(_COOKIE_RE.search(raw_bytes))

    return HTTPRequest(
        method=method, host=host, path=path,
        user_agent=ua, content_length=cl,
        referer=referer, has_cookie=cookie,
    )


# ---------------------------------------------------------------------------
# 비콘 탐지
# ---------------------------------------------------------------------------

def _detect_beacons(
    timestamps: dict[tuple, list[float]]
) -> list[BeaconCandidate]:
    """
    (dst_ip, dst_port) 별 타임스탬프 목록에서 주기적 패턴을 탐지.
    """
    candidates = []
    for (dst_ip, dst_port), ts_list in timestamps.items():
        if len(ts_list) < BEACON_MIN_COUNT:
            continue
        ts_sorted = sorted(ts_list)
        intervals = [ts_sorted[i+1] - ts_sorted[i] for i in range(len(ts_sorted)-1)]
        if not intervals or min(intervals) < 0.5:
            continue
        avg = statistics.mean(intervals)
        std = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        if avg == 0:
            continue
        jitter = std / avg
        if jitter <= BEACON_MAX_JITTER:
            candidates.append(BeaconCandidate(
                dst_ip=dst_ip,
                dst_port=dst_port,
                count=len(ts_list),
                interval_avg=round(avg, 2),
                interval_std=round(std, 2),
                jitter_ratio=round(jitter, 3),
            ))
    return sorted(candidates, key=lambda x: x.jitter_ratio)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_pcap(pcap_path: Path) -> PcapResult:
    """PCAP 파일을 파싱해 구조화된 네트워크 정보를 반환.

    scapy 미설치 시 빈 PcapResult 반환 (예외 없음).
    """
    if not SCAPY_AVAILABLE:
        return PcapResult()

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        return PcapResult()

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return PcapResult()

    # --- 수집 자료구조 ---
    conn_map:     dict[tuple, NetworkConnection]  = {}
    dns_seen:     dict[str, DNSQuery]             = {}
    dns_responses:dict[str, list[str]]            = defaultdict(list)  # name→[ip]
    ip_to_domain: dict[str, list[str]]            = defaultdict(list)  # ip→[domain]
    http_list:    list[HTTPRequest]               = []
    tls_list:     list[TLSInfo]                   = []
    beacon_ts:    dict[tuple, list[float]]        = defaultdict(list)  # (ip,port)→[ts]
    dns_base_cnt: dict[str, int]                  = defaultdict(int)   # base_domain→query count
    raw_ips:      set[str]                        = set()
    raw_domains:  set[str]                        = set()
    total_bytes_out = 0
    total_bytes_in  = 0
    total_packets   = 0

    for pkt in packets:
        try:
            total_packets += 1

            # IP 레이어 확인
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue

            pkt_len = len(pkt)
            ts      = float(pkt.time)

            # 외부 IP 추적
            if not _is_private_ip(dst_ip):
                raw_ips.add(dst_ip)
                total_bytes_out += pkt_len
            else:
                total_bytes_in += pkt_len

            # 전송 계층
            if TCP in pkt:
                proto    = "TCP"
                dst_port = pkt[TCP].dport
                src_port = pkt[TCP].sport
            elif UDP in pkt:
                proto    = "UDP"
                dst_port = pkt[UDP].dport
                src_port = pkt[UDP].sport
            else:
                continue

            # --- 연결 추적 ---
            if proto in ("TCP", "UDP"):
                key = (proto, src_ip, dst_ip, dst_port)
                is_susp = dst_port in SUSPICIOUS_PORTS
                if key in conn_map:
                    c = conn_map[key]
                    c.count += 1
                    c.bytes_out += pkt_len
                    c.last_seen = ts
                else:
                    conn_map[key] = NetworkConnection(
                        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
                        dst_port=dst_port, count=1,
                        bytes_out=pkt_len, bytes_in=0,
                        first_seen=ts, last_seen=ts,
                        suspicious_port=is_susp,
                    )
                # 비콘 타임스탬프 기록 (외부 IP만)
                if not _is_private_ip(dst_ip):
                    beacon_ts[(dst_ip, dst_port)].append(ts)

            # --- DNS 파싱 ---
            if DNS in pkt:
                dns_pkt = pkt[DNS]

                # 쿼리 (QR=0)
                if dns_pkt.qr == 0 and DNSQR in pkt:
                    qr = pkt[DNSQR]
                    try:
                        raw_name = qr.qname
                        name = (raw_name.decode(errors="replace")
                                if isinstance(raw_name, bytes) else str(raw_name))
                        name = name.rstrip(".")
                        qtype_str = _QTYPE_MAP.get(int(qr.qtype), str(qr.qtype))
                        raw_domains.add(name)
                        dns_base_cnt[_base_domain(name)] += 1

                        if name not in dns_seen:
                            ent = _subdomain_entropy(name)
                            dns_seen[name] = DNSQuery(
                                name=name, qtype=qtype_str,
                                entropy=round(ent, 3),
                            )
                    except Exception:
                        pass

                # 응답 (QR=1) → IP 매핑
                if dns_pkt.qr == 1:
                    try:
                        an = dns_pkt.an
                        while an and an != 0:
                            qname = getattr(an, "rrname", b"")
                            if isinstance(qname, bytes):
                                qname = qname.decode(errors="replace").rstrip(".")
                            rdata = getattr(an, "rdata", None)
                            if rdata and isinstance(rdata, str) and not _is_private_ip(rdata):
                                dns_responses[qname].append(rdata)
                                ip_to_domain[rdata].append(qname)
                            an = getattr(an, "payload", None)
                            if not hasattr(an, "rrname"):
                                break
                    except Exception:
                        pass

            # --- TLS SNI 추출 (TCP 443 또는 의심 포트) ---
            if proto == "TCP" and Raw in pkt:
                raw_bytes = bytes(pkt[Raw])
                sni = _extract_tls_sni(raw_bytes)
                if sni:
                    raw_domains.add(sni)
                    tls_list.append(TLSInfo(sni=sni, dst_ip=dst_ip, dst_port=dst_port))

            # --- HTTP 파싱 ---
            if proto == "TCP" and Raw in pkt:
                raw_bytes = bytes(pkt[Raw])
                # scapy HTTP 레이어 우선
                if ScapyHTTPRequest is not None and ScapyHTTPRequest in pkt:
                    try:
                        hl = pkt[ScapyHTTPRequest]
                        method = (hl.Method or b"").decode(errors="replace")
                        host   = (hl.Host   or b"").decode(errors="replace")
                        path   = (hl.Path   or b"").decode(errors="replace")
                        ua     = (hl.User_Agent or b"").decode(errors="replace")
                        cl     = int((hl.Content_Length or b"0").decode(errors="replace") or 0)
                        http_list.append(HTTPRequest(
                            method=method, host=host, path=path,
                            user_agent=ua, content_length=cl,
                        ))
                    except Exception:
                        req = _parse_http_raw(raw_bytes)
                        if req:
                            http_list.append(req)
                else:
                    req = _parse_http_raw(raw_bytes)
                    if req:
                        http_list.append(req)

        except Exception:
            continue

    # --- DNS 응답 IP 병합 ---
    for name, q in dns_seen.items():
        q.response_ips = list(set(dns_responses.get(name, [])))

    # --- DGA / 의심 도메인 판정 ---
    suspicious_domains = []
    for name, q in dns_seen.items():
        is_dga     = q.entropy >= DGA_ENTROPY_THRESHOLD
        is_long    = len(name.split(".")[0]) >= DNS_TUNNEL_LABEL_LEN
        is_tunnel  = dns_base_cnt.get(_base_domain(name), 0) >= DNS_TUNNEL_QUERY_THRESHOLD
        if is_dga or is_long or is_tunnel:
            q.suspicious = True
            suspicious_domains.append(name)

    # --- DNS 터널링 의심 베이스 도메인 ---
    dns_tunnel_suspects = [
        domain for domain, cnt in dns_base_cnt.items()
        if cnt >= DNS_TUNNEL_QUERY_THRESHOLD
    ]

    # --- 비콘 탐지 ---
    beacon_candidates = _detect_beacons(beacon_ts)

    # --- 요약 ---
    summary = PcapSummary(
        total_packets=total_packets,
        total_bytes_out=total_bytes_out,
        total_bytes_in=total_bytes_in,
        unique_dst_ips=len(raw_ips),
        unique_domains=len(raw_domains),
    )

    return PcapResult(
        connections=list(conn_map.values()),
        dns_queries=list(dns_seen.values()),
        http_requests=http_list,
        tls_info=tls_list,
        beacon_candidates=beacon_candidates,
        suspicious_domains=sorted(set(suspicious_domains)),
        dns_tunnel_suspects=sorted(set(dns_tunnel_suspects)),
        summary=summary,
        raw_ips=raw_ips,
        raw_domains=raw_domains,
        ip_to_domain=dict(ip_to_domain),
    )
