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

import hashlib
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
    5228,               # Firebase FCM — RAT C2 채널로 악용 (Google Play Services와 구분 필요)
})

# 정보 탈취 C2에 사용되는 프로토콜별 포트 목록
# 의심 포트와 별개로 관리 — 정상 서비스와 겹치지만 분석 컨텍스트에서는 C2로 사용됨
SMTP_PORTS:  frozenset[int] = frozenset({25, 465, 587})
FTP_PORTS:   frozenset[int] = frozenset({21, 2121})
POP3_PORTS:  frozenset[int] = frozenset({110, 995})
IMAP_PORTS:  frozenset[int] = frozenset({143, 993})
IRC_PORTS:   frozenset[int] = frozenset({6660, 6661, 6662, 6663, 6664,
                                          6665, 6666, 6667, 6668, 6669, 6670, 7000})

# C2 프로토콜 포트 통합 → suspicious_port 판정에 포함
SUSPICIOUS_PORTS = SUSPICIOUS_PORTS | SMTP_PORTS | FTP_PORTS | POP3_PORTS | IMAP_PORTS

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

# ── JA3 / JA3S 핑거프린팅 ─────────────────────────────────────────────
# GREASE 값 (RFC 8701) — JA3 계산 시 제외
_GREASE: frozenset[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# 잘 알려진 JA3 해시 → 도구/악성코드 패밀리 매핑
_KNOWN_JA3: dict[str, str] = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "d4e457bda0a18c7cc79e3c5ca38bb3c8": "Metasploit",
    "a5de71cf37a7f895ead6e6e70f5b6de7": "QakBot",
    "6734f37431109a72a7b3d9c53ef77f20": "TrickBot",
    "51c64c77e60f3980eea90869b68c58a8": "Python-requests",
    "b32309a26951912be7dba376398abc3b": "Go net/http",
    "cca81c9c0d1e5bcaf2e0cc2bef8e61d1": "Emotet",
    "9e10692f1b7f78228b2d4e424db3a98c": "Dridex",
    "de9f2c7fd25e1b3afad3e85a0226c4de": "urllib3",
    "e7d705a3286e19ea42f587b6e7359b5d": "Tor Browser",
    "c35b954d2b7f858c76b9de8f5ec19e76": "Nmap",
    "0d7c6f933c5f4e1c76afa545c5714b49": "Zeek/Bro",
    "3b5074b1b5d032e5620f69f9159c6b5e": "IcedID",
    "a0e9f5d64349fb13191bc781f81f42e1": "BazarLoader",
    "13b3d7c9b3481e0a4e09b4a0bd2de9fd": "RedLine Stealer",
}

# ---------------------------------------------------------------------------
# 분석 도구 / 위협인텔 서비스 도메인 화이트리스트
# tshark 캡처 중 분석 도구 자체가 만드는 네트워크 트래픽을 제거합니다.
# ---------------------------------------------------------------------------

_ANALYSIS_SERVICE_SUFFIXES: tuple[str, ...] = (
    "abuse.ch",             # URLhaus, MalwareBazaar, ThreatFox, Feodo, YARAify
    "virustotal.com",       # VirusTotal API
    "alienvault.com",       # OTX AlienVault
    "shodan.io",            # Shodan
    # system-informer.com 제외: Cloudflare 도메인 프론팅 C2로 악용 사례 있음 —
    # 악성코드가 이 도메인을 SNI로 사용하면 필터 시 누락되므로 표시
    "github.com",           # GitHub (도구 업데이트)
    "githubusercontent.com",
    "phantom.app",          # 브라우저 Web3 확장
    "metamask.io",
    "xdefi.services",
)


def _is_analysis_service_domain(domain: str) -> bool:
    """분석 인프라 전용 도메인이면 True를 반환합니다 (DNS/TLS 레코드에서 제외).

    주의: 악성코드 C2로 악용 가능한 도메인(system-informer.com 등)은 제외하지 말 것.
    위협 인텔 API나 패키지 저장소처럼 악성코드가 직접 접촉할 이유가 없는 도메인만 포함.
    """
    d = domain.lower().rstrip(".")
    for suffix in _ANALYSIS_SERVICE_SUFFIXES:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


# DNS 터널링 판정에서 제외할 베이스 도메인.
# 이들은 정상적으로 서브도메인이 수십 개씩 뻗어 나가므로 "베이스 도메인당
# 쿼리 수" 임계치를 늘 넘긴다. microsoft.com 하나 때문에 하위 도메인 20여 개가
# 통째로 "의심"으로 찍히는 오탐을 막는다.
# 주의: C2 가 이 도메인을 사칭할 수는 없다(실제 DNS 응답 기준). 다만 서브도메인
# 탈취 가능성은 남으므로, 엔트로피/라벨 길이 기반 개별 판정은 그대로 적용된다.
_TUNNEL_EXEMPT_BASES: frozenset[str] = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "windows.net",
    "msftconnecttest.com", "msftncsi.com", "msedge.net", "office.com",
    "office.net", "live.com", "msn.com", "bing.com", "skype.com",
    "akamai.net", "akamaiedge.net", "akadns.net", "edgekey.net",
    "cloudflare.com", "cloudfront.net", "fastly.net", "gstatic.com",
    "google.com", "googleapis.com", "apple.com", "icloud.com",
    "digicert.com", "verisign.com", "globalsign.com", "sectigo.com",
    "letsencrypt.org", "entrust.net", "in-addr.arpa", "ip6.arpa",
})


def _is_tunnel_exempt_base(base: str) -> bool:
    b = (base or "").lower().rstrip(".")
    return b in _TUNNEL_EXEMPT_BASES


def _is_dns_tunnel_base(base: str, count: int) -> bool:
    """베이스 도메인이 DNS 터널링 의심 대상인지.

    단순 쿼리 수만 보면 CDN·업데이트 서비스가 전부 걸린다.
    알려진 정상 베이스는 제외하고 임계치를 적용한다.
    """
    if _is_tunnel_exempt_base(base):
        return False
    return count >= DNS_TUNNEL_QUERY_THRESHOLD


def _is_excluded_dns_name(name: str) -> bool:
    """DGA/터널링 판정에서 제외할 DNS 이름이면 True.

    PTR 역방향 조회(.in-addr.arpa / .ip6.arpa)는 OS·도구가 상시 발생시키는
    노이즈이고, base domain 이 전부 "in-addr.arpa" 로 동일해 터널링 임계치를
    쉽게 넘긴다. scapy 경로와 tshark 폴백 경로 양쪽에서 같은 기준을 쓴다.
    """
    n = name.lower().rstrip(".")
    return (
        n.endswith(".in-addr.arpa")
        or n.endswith(".ip6.arpa")
        or _is_analysis_service_domain(n)
    )


_QTYPE_MAP: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}

# 동적 DNS(DDNS) 서비스 suffix — C2 인프라로 자주 악용됨
_DDNS_SUFFIXES: tuple[str, ...] = (
    ".dynamic-dns.net", ".no-ip.org", ".no-ip.com", ".no-ip.biz",
    ".no-ip.info", ".ddns.net", ".ddns.org", ".dyndns.org",
    ".dyndns.com", ".dyndns.tv", ".dyndns.info", ".duckdns.org",
    ".changeip.com", ".changeip.net", ".dnsdynamic.org",
    ".hopto.org", ".zapto.org", ".sytes.net", ".bounceme.net",
    ".redirectme.net", ".servebeer.com", ".serveblog.net",
    ".myddns.me", ".myftp.org", ".myftp.biz", ".serveftp.com",
    ".3utilities.com", ".blogdns.com", ".gotdns.ch",
    ".mooo.com", ".freedns.afraid.org",
)


def _is_ddns_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d.endswith(s) for s in _DDNS_SUFFIXES)

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
    src_port:   int   = 0    # 로컬 ephemeral 포트 — ProcMon local_port 역추적용


@dataclass
class DNSQuery:
    name:         str
    qtype:        str
    response_ips: list[str] = field(default_factory=list)  # A/AAAA 응답 IP
    entropy:      float = 0.0    # 서브도메인 Shannon 엔트로피
    suspicious:   bool  = False  # DGA 의심 or 터널링 의심
    is_ddns:      bool  = False  # DDNS 서비스 도메인 여부
    no_response:  bool  = False  # DNS 응답 없음 (C2 오프라인 등)


@dataclass
class DnsRawQuery:
    """개별 DNS 쿼리 패킷 — 프로세스 귀속용.

    src_port(클라이언트 ephemeral UDP 포트)가 ProcMon UDP Send 이벤트와
    1:1 매핑되므로 어떤 프로세스가 이 도메인을 조회했는지 특정할 수 있다.
    """
    name:     str
    qtype:    str
    src_port: int       # 클라이언트 ephemeral UDP port — ProcMon 매핑 키
    pkt_time: float     # 패킷 Unix 타임스탬프
    tx_id:    int = 0   # DNS Transaction ID (보조 확인용)
    answers:  list[str] = field(default_factory=list)  # 사후 채움


@dataclass
class HTTPRequest:
    method:         str
    host:           str
    path:           str
    user_agent:     str
    content_length: int  = 0
    referer:        str  = ""
    has_cookie:     bool = False
    dst_ip:         str  = ""
    dst_port:       int  = 80
    content_type:   str  = ""    # 요청 Content-Type
    authorization:  str  = ""    # Authorization 헤더 (토큰 유출 탐지)
    extra_headers:  str  = ""    # 기타 주목할 헤더 (콤마 구분)
    body_preview:   str  = ""    # 요청 바디 앞 512자


@dataclass
class TLSInfo:
    """TLS ClientHello에서 추출한 연결 정보 + JA3 핑거프린트"""
    sni:         str          # 서버 이름 (복호화 없이 추출)
    dst_ip:      str
    dst_port:    int
    ja3:         str  = ""    # JA3 MD5 핑거프린트
    ja3_label:   str  = ""    # 알려진 도구명 (Cobalt Strike 등)
    tls_version: str  = ""    # TLS 버전 문자열 (TLS 1.2 / TLS 1.3)


@dataclass
class SmtpSession:
    """SMTP 세션에서 추출한 C2 통신 정보 (AgentTesla, FormBook 등)."""
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    ehlo_domain: str       = ""   # EHLO/HELO 도메인 (공격자 식별)
    mail_from:   str       = ""   # MAIL FROM 주소
    rcpt_to:     list[str] = field(default_factory=list)  # RCPT TO 주소 목록
    auth_user:   str       = ""   # AUTH LOGIN 디코딩된 사용자명
    has_auth:    bool      = False
    has_data:    bool      = False  # DATA 명령 확인 여부


@dataclass
class FtpSession:
    """FTP 세션에서 추출한 C2 통신 정보."""
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    username:   str       = ""
    has_auth:   bool      = False
    uploaded:   list[str] = field(default_factory=list)   # STOR 파일명
    downloaded: list[str] = field(default_factory=list)   # RETR 파일명


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
    raw_dns_queries:    list[DnsRawQuery]       = field(default_factory=list)
    http_requests:      list[HTTPRequest]       = field(default_factory=list)
    tls_info:           list[TLSInfo]           = field(default_factory=list)
    beacon_candidates:  list[BeaconCandidate]   = field(default_factory=list)
    smtp_sessions:      list[SmtpSession]       = field(default_factory=list)
    ftp_sessions:       list[FtpSession]        = field(default_factory=list)
    suspicious_domains: list[str]               = field(default_factory=list)
    dns_tunnel_suspects:list[str]               = field(default_factory=list)
    summary:            PcapSummary             = field(default_factory=PcapSummary)
    # 역참조용
    raw_ips:     set[str] = field(default_factory=set)
    raw_domains: set[str] = field(default_factory=set)
    # DNS A/AAAA 응답: IP → [domain]
    ip_to_domain: dict[str, list[str]] = field(default_factory=dict)
    # 진단 정보
    packets_loaded: int = 0       # rdpcap으로 읽은 총 패킷 수
    packets_skipped: int = 0      # IP/TCP/UDP 레이어 없어 건너뛴 패킷 수
    parse_error: str = ""         # 파싱 실패 원인 (정상이면 빈 문자열)


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
# JA3 / JA3S 핑거프린팅
# ---------------------------------------------------------------------------

_TLS_VER_STR: dict[int, str] = {
    0x0304: "TLS 1.3", 0x0303: "TLS 1.2",
    0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0",
}


def _parse_ja3_clienthello(raw: bytes) -> Optional[tuple]:
    """
    TLS ClientHello 원시 바이트에서 JA3 필드 및 SNI를 추출.

    Returns: (tls_version:int, ciphers:list, ext_types:list,
              curves:list, point_formats:list, sni:str|None)
    None 반환 시 ClientHello가 아님.
    """
    try:
        if len(raw) < 43:
            return None
        if raw[0] != 0x16 or raw[5] != 0x01:
            return None

        offset = 9  # record header(5) + handshake type(1) + length(3)

        tls_version = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2 + 32  # version + random

        if offset >= len(raw):
            return None
        sid_len = raw[offset]
        offset += 1 + sid_len

        if offset + 2 > len(raw):
            return None
        cs_len = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 > len(raw):
                break
            v = int.from_bytes(raw[offset + i:offset + i + 2], "big")
            if v not in _GREASE:
                ciphers.append(v)
        offset += cs_len

        if offset >= len(raw):
            return None
        comp_len = raw[offset]
        offset += 1 + comp_len

        if offset + 2 > len(raw):
            return (tls_version, ciphers, [], [], [], None)
        ext_total = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        ext_end = min(offset + ext_total, len(raw))

        ext_types: list[int]  = []
        curves:    list[int]  = []
        pf:        list[int]  = []
        sni:       Optional[str] = None

        while offset + 4 <= ext_end:
            et  = int.from_bytes(raw[offset:offset + 2], "big")
            el  = int.from_bytes(raw[offset + 2:offset + 4], "big")
            offset += 4
            ed  = raw[offset:offset + el]

            if et not in _GREASE:
                ext_types.append(et)

            if et == 0x0000 and len(ed) >= 5:          # SNI
                nl = int.from_bytes(ed[3:5], "big")
                if 5 + nl <= len(ed):
                    sni = ed[5:5 + nl].decode("ascii", errors="replace")
            elif et == 0x000a and len(ed) >= 2:        # supported_groups
                gl = int.from_bytes(ed[0:2], "big")
                for i in range(0, gl, 2):
                    if 2 + i + 2 <= len(ed):
                        g = int.from_bytes(ed[2 + i:2 + i + 2], "big")
                        if g not in _GREASE:
                            curves.append(g)
            elif et == 0x000b and len(ed) >= 1:        # ec_point_formats
                pl = ed[0]
                pf.extend(ed[1:1 + pl])
            elif et == 0x002b and len(ed) >= 1:        # supported_versions (TLS 1.3)
                sv_len = ed[0]
                for i in range(0, sv_len, 2):
                    if 1 + i + 2 <= len(ed):
                        sv = int.from_bytes(ed[1 + i:1 + i + 2], "big")
                        if sv not in _GREASE and sv > tls_version:
                            tls_version = sv

            offset += el

        return (tls_version, ciphers, ext_types, curves, pf, sni)
    except Exception:
        return None


def _build_ja3(tls_ver: int, ciphers: list, exts: list,
               curves: list, pf: list) -> str:
    """JA3 문자열을 구성하고 MD5 해시를 반환."""
    s = (
        f"{tls_ver},"
        f"{'-'.join(str(c) for c in ciphers)},"
        f"{'-'.join(str(e) for e in exts)},"
        f"{'-'.join(str(g) for g in curves)},"
        f"{'-'.join(str(p) for p in pf)}"
    )
    return hashlib.md5(s.encode()).hexdigest()


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
# SMTP / FTP 페이로드 파싱
# ---------------------------------------------------------------------------

_SMTP_CMD_RE   = re.compile(rb"^(?:EHLO|HELO|AUTH|MAIL FROM|RCPT TO|DATA|QUIT)", re.IGNORECASE | re.MULTILINE)
_SMTP_FROM_RE  = re.compile(rb"MAIL FROM:\s*<([^>]+)>", re.IGNORECASE)
_SMTP_RCPT_RE  = re.compile(rb"RCPT TO:\s*<([^>]+)>",  re.IGNORECASE)
_SMTP_EHLO_RE  = re.compile(rb"(?:EHLO|HELO)\s+(\S+)",  re.IGNORECASE)
_SMTP_AUTH_RE  = re.compile(rb"AUTH\s+LOGIN",            re.IGNORECASE)

_FTP_CMD_RE    = re.compile(rb"^(USER|PASS|STOR|RETR|MKD|CWD|PWD|QUIT)\s*(\S*)", re.IGNORECASE | re.MULTILINE)


def _parse_smtp_raw(
    raw: bytes,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
) -> Optional[SmtpSession]:
    """TCP 페이로드에서 SMTP 세션 데이터를 추출.

    AUTH LOGIN의 경우 base64 인코딩된 자격증명 라인을 디코딩한다.
    비밀번호는 존재 여부만 `has_auth=True`로 표시하고 평문 저장하지 않음.
    """
    if not _SMTP_CMD_RE.search(raw):
        return None  # SMTP 명령 없음

    import base64

    sess = SmtpSession(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)

    m = _SMTP_EHLO_RE.search(raw)
    if m:
        sess.ehlo_domain = m.group(1).decode(errors="replace")

    m = _SMTP_FROM_RE.search(raw)
    if m:
        sess.mail_from = m.group(1).decode(errors="replace")

    for m in _SMTP_RCPT_RE.finditer(raw):
        addr = m.group(1).decode(errors="replace")
        if addr not in sess.rcpt_to:
            sess.rcpt_to.append(addr)

    if _SMTP_AUTH_RE.search(raw):
        sess.has_auth = True
        # AUTH LOGIN 다음 줄 = base64 사용자명
        lines = raw.splitlines()
        for i, line in enumerate(lines):
            if _SMTP_AUTH_RE.search(line):
                if i + 1 < len(lines):
                    try:
                        decoded = base64.b64decode(lines[i + 1].strip()).decode(errors="replace")
                        # 이메일 주소 형태면 사용자명으로 저장
                        if "@" in decoded or len(decoded) < 64:
                            sess.auth_user = decoded
                    except Exception:
                        pass
                break

    if b"DATA" in raw.upper():
        sess.has_data = True

    return sess


def _parse_ftp_raw(
    raw: bytes,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
) -> Optional[FtpSession]:
    """TCP 페이로드에서 FTP 세션 데이터를 추출."""
    matches = _FTP_CMD_RE.findall(raw)
    if not matches:
        return None

    sess = FtpSession(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)
    for cmd_b, arg_b in matches:
        cmd = cmd_b.decode(errors="replace").upper()
        arg = arg_b.decode(errors="replace").strip()
        if cmd == "USER" and arg:
            sess.username = arg
            sess.has_auth = True
        elif cmd == "STOR" and arg:
            sess.uploaded.append(arg)
        elif cmd == "RETR" and arg:
            sess.downloaded.append(arg)

    return sess


# ---------------------------------------------------------------------------
# HTTP raw 파싱
# ---------------------------------------------------------------------------

_HTTP_REQ_RE  = re.compile(rb"^(?P<method>[A-Z]{3,7})\s+(?P<path>\S+)\s+HTTP/\d", re.MULTILINE)
_HOST_RE      = re.compile(rb"^Host:\s*(?P<v>[^\r\n]+)",           re.MULTILINE | re.IGNORECASE)
_UA_RE        = re.compile(rb"^User-Agent:\s*(?P<v>[^\r\n]+)",     re.MULTILINE | re.IGNORECASE)
_CL_RE        = re.compile(rb"^Content-Length:\s*(?P<v>\d+)",      re.MULTILINE | re.IGNORECASE)
_REF_RE       = re.compile(rb"^Referer:\s*(?P<v>[^\r\n]+)",        re.MULTILINE | re.IGNORECASE)
_COOKIE_RE    = re.compile(rb"^Cookie:\s*",                        re.MULTILINE | re.IGNORECASE)
_CT_RE        = re.compile(rb"^Content-Type:\s*(?P<v>[^\r\n]+)",   re.MULTILINE | re.IGNORECASE)
_AUTH_RE      = re.compile(rb"^Authorization:\s*(?P<v>[^\r\n]+)",  re.MULTILINE | re.IGNORECASE)
_EXTRA_HDRS   = [
    (re.compile(rb"^X-Forwarded-For:\s*(?P<v>[^\r\n]+)",  re.MULTILINE | re.IGNORECASE), "X-Forwarded-For"),
    (re.compile(rb"^Accept-Language:\s*(?P<v>[^\r\n]+)",  re.MULTILINE | re.IGNORECASE), "Accept-Language"),
    (re.compile(rb"^X-Api-Key:\s*(?P<v>[^\r\n]+)",        re.MULTILINE | re.IGNORECASE), "X-Api-Key"),
]


def _parse_http_raw(
    raw_bytes: bytes,
    dst_ip: str = "",
    dst_port: int = 80,
) -> Optional[HTTPRequest]:
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
    ct      = _get(_CT_RE)
    auth    = _get(_AUTH_RE)

    # 바디: 헤더 끝(\r\n\r\n 또는 \n\n) 이후
    body_preview = ""
    sep = raw_bytes.find(b"\r\n\r\n")
    if sep == -1:
        sep = raw_bytes.find(b"\n\n")
    if sep != -1:
        body_raw = raw_bytes[sep + 4:sep + 516]
        body_preview = body_raw.decode(errors="replace").strip()[:512]

    extra_parts = []
    for pat, name in _EXTRA_HDRS:
        v = _get(pat)
        if v:
            extra_parts.append(f"{name}: {v[:60]}")

    return HTTPRequest(
        method=method, host=host, path=path,
        user_agent=ua, content_length=cl,
        referer=referer, has_cookie=cookie,
        dst_ip=dst_ip, dst_port=dst_port,
        content_type=ct, authorization=auth,
        extra_headers=", ".join(extra_parts),
        body_preview=body_preview,
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
# tshark 기반 파서 (scapy 없이 동작하는 fallback)
# ---------------------------------------------------------------------------

def _run_tshark_fields(
    tshark_path: str,
    pcap_path: Path,
    fields: list[str],
    display_filter: str = "",
    occurrence: str = "f",
) -> list[list[str]]:
    """tshark -T fields 실행 → 행×열 리스트 반환"""
    import subprocess

    cmd = [tshark_path, "-r", str(pcap_path), "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", f"-E", f"occurrence={occurrence}", "-E", "quote=n"]
    if display_filter:
        cmd += ["-Y", display_filter]
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        return [ln.split("\t") for ln in r.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def _parse_pcap_with_tshark(pcap_path: Path, tshark_path: str) -> PcapResult:
    """
    tshark를 이용해 PCAP을 파싱한다 (scapy 대체).

    Pass 1 — 전체 패킷: 연결 추적 + DNS 쿼리 + TLS SNI
    Pass 2 — DNS 응답:  IP↔도메인 매핑
    Pass 3 — HTTP 요청: 메서드·호스트·User-Agent
    """
    conn_map:     dict[tuple, NetworkConnection]  = {}
    dns_seen:     dict[str, DNSQuery]             = {}
    ip_to_domain: dict[str, list[str]]            = defaultdict(list)
    http_list:    list[HTTPRequest]               = []
    tls_list:     list[TLSInfo]                   = []
    beacon_ts:    dict[tuple, list[float]]        = defaultdict(list)
    dns_base_cnt: dict[str, int]                  = defaultdict(int)
    raw_ips:      set[str]                        = set()
    raw_domains:  set[str]                        = set()
    total_bytes_out = 0
    total_bytes_in  = 0
    packets_loaded  = 0
    packets_skipped = 0

    # ── Pass 1 ────────────────────────────────────────────────────────
    P1 = [
        "frame.time_epoch",                        # 0
        "ip.src",                                  # 1  (IPv4)
        "ip.dst",                                  # 2
        "ipv6.src",                                # 3  (IPv6 fallback)
        "ipv6.dst",                                # 4
        "tcp.dstport",                             # 5
        "udp.dstport",                             # 6
        "frame.len",                               # 7
        "dns.qry.name",                            # 8
        "dns.qry.type",                            # 9
        "tls.handshake.extensions_server_name",    # 10  SNI
        "tls.handshake.ja3",                       # 11  JA3 해시 (tshark 내장)
        "tls.record.version",                      # 12  TLS 레코드 버전
        "tcp.srcport",                             # 13  로컬 포트 — ProcMon 역추적용
        "udp.srcport",                             # 14
    ]
    for row in _run_tshark_fields(tshark_path, pcap_path, P1):
        packets_loaded += 1
        try:
            def _f(i: int) -> str:
                return row[i].strip() if i < len(row) else ""

            src_ip  = _f(1) or _f(3)
            dst_ip  = _f(2) or _f(4)
            tcp_dp  = _f(5)
            udp_dp  = _f(6)
            flen    = int(_f(7)) if _f(7).isdigit() else 0
            ts_str  = _f(0)
            ts      = float(ts_str) if ts_str else 0.0

            if not src_ip or not dst_ip:
                packets_skipped += 1
                continue

            if tcp_dp and tcp_dp.isdigit():
                proto, dst_port = "TCP", int(tcp_dp)
                src_port = int(_f(13)) if _f(13).isdigit() else 0
            elif udp_dp and udp_dp.isdigit():
                proto, dst_port = "UDP", int(udp_dp)
                src_port = int(_f(14)) if _f(14).isdigit() else 0
            else:
                packets_skipped += 1
                continue

            # 연결 추적
            key = (proto, src_ip, dst_ip, dst_port)
            if key in conn_map:
                c = conn_map[key]
                c.count     += 1
                c.bytes_out += flen
                c.last_seen  = ts
            else:
                conn_map[key] = NetworkConnection(
                    proto=proto, src_ip=src_ip, dst_ip=dst_ip,
                    dst_port=dst_port, count=1,
                    bytes_out=flen, bytes_in=0,
                    first_seen=ts, last_seen=ts,
                    suspicious_port=(dst_port in SUSPICIOUS_PORTS),
                    src_port=src_port,
                )

            if not _is_private_ip(dst_ip):
                raw_ips.add(dst_ip)
                total_bytes_out += flen
                beacon_ts[(dst_ip, dst_port)].append(ts)
            else:
                total_bytes_in += flen

            # DNS 쿼리
            dns_name = _f(8).rstrip(".")
            # PTR 레코드(.in-addr.arpa / .ip6.arpa)와 분석 서비스 도메인은
            # DGA/터널링 판정 대상에서 제외한다. scapy 경로와 동일한 가드로,
            # dns_base_cnt 집계 전에 걸러야 base domain "in-addr.arpa" 가
            # 터널링 임계치를 넘겨 PTR 전체를 오탐하는 것을 막을 수 있다.
            if dns_name and not _is_excluded_dns_name(dns_name):
                raw_domains.add(dns_name)
                dns_base_cnt[_base_domain(dns_name)] += 1
                if dns_name not in dns_seen:
                    qt_raw = _f(9)
                    qtype  = _QTYPE_MAP.get(int(qt_raw) if qt_raw.isdigit() else 0, qt_raw or "A")
                    ent    = _subdomain_entropy(dns_name)
                    dns_seen[dns_name] = DNSQuery(
                        name=dns_name, qtype=qtype, entropy=round(ent, 3),
                        is_ddns=_is_ddns_domain(dns_name),
                    )

            # TLS SNI + JA3 (tshark 내장 계산값 사용)
            sni = _f(10)
            ja3 = _f(11)
            if sni or ja3:
                if sni:
                    raw_domains.add(sni)
                if not (sni and _is_analysis_service_domain(sni)):
                    tls_list.append(TLSInfo(
                        sni=sni, dst_ip=dst_ip, dst_port=dst_port,
                        ja3=ja3, ja3_label=_KNOWN_JA3.get(ja3, ""),
                    ))

        except Exception:
            packets_skipped += 1
            continue

    # ── Pass 2: DNS 응답 → IP 매핑 ───────────────────────────────────
    P2 = ["dns.qry.name", "dns.a", "dns.aaaa"]
    for row in _run_tshark_fields(
        tshark_path, pcap_path, P2,
        display_filter="dns.flags.response == 1",
    ):
        try:
            qname = row[0].rstrip(".") if len(row) > 0 else ""
            for ip in [row[1] if len(row) > 1 else "",
                       row[2] if len(row) > 2 else ""]:
                ip = ip.strip()
                if ip and not _is_private_ip(ip):
                    if qname in dns_seen:
                        if ip not in dns_seen[qname].response_ips:
                            dns_seen[qname].response_ips.append(ip)
                    ip_to_domain[ip].append(qname)
        except Exception:
            continue

    # ── Pass 3: HTTP 요청 ─────────────────────────────────────────────
    # display_filter 없이 tcp.dstport==80 전체를 가져와 HTTP 레이어 유무와 무관하게 파싱
    P3 = [
        "ip.dst", "tcp.dstport",
        "http.host", "http.request.method",
        "http.request.uri", "http.user_agent",
        "http.content_length", "http.referer",
        "http.cookie", "http.content_type", "http.authorization",
    ]
    for row in _run_tshark_fields(
        tshark_path, pcap_path, P3, display_filter="http.request",
    ):
        try:
            def _h(i: int) -> str:
                return row[i].strip() if i < len(row) else ""
            method = _h(3)
            if not method:
                continue
            cl_str = _h(6)
            port_str = _h(1)
            http_list.append(HTTPRequest(
                dst_ip=_h(0),
                dst_port=int(port_str) if port_str.isdigit() else 80,
                host=_h(2),
                method=method,
                path=_h(4),
                user_agent=_h(5),
                content_length=int(cl_str) if cl_str.isdigit() else 0,
                referer=_h(7),
                has_cookie=bool(_h(8)),
                content_type=_h(9),
                authorization=_h(10),
            ))
        except Exception:
            continue

    # ── 공통 후처리 ──────────────────────────────────────────────────
    # no_response 플래그: A/AAAA 쿼리인데 응답 IP가 없는 경우
    for q in dns_seen.values():
        if q.qtype in ("A", "AAAA") and not q.response_ips:
            q.no_response = True

    suspicious_domains: list[str] = []
    for name, q in dns_seen.items():
        if (q.entropy >= DGA_ENTROPY_THRESHOLD
                or len(name.split(".")[0]) >= DNS_TUNNEL_LABEL_LEN
                or _is_dns_tunnel_base(_base_domain(name),
                                       dns_base_cnt.get(_base_domain(name), 0))):
            q.suspicious = True
            suspicious_domains.append(name)

    dns_tunnel_suspects = [
        d for d, cnt in dns_base_cnt.items()
        if _is_dns_tunnel_base(d, cnt)
    ]

    summary = PcapSummary(
        total_packets=packets_loaded,
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
        beacon_candidates=_detect_beacons(beacon_ts),
        suspicious_domains=sorted(set(suspicious_domains)),
        dns_tunnel_suspects=sorted(set(dns_tunnel_suspects)),
        summary=summary,
        raw_ips=raw_ips,
        raw_domains=raw_domains,
        ip_to_domain=dict(ip_to_domain),
        packets_loaded=packets_loaded,
        packets_skipped=packets_skipped,
        parse_error="",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_pcap(pcap_path: Path, tshark_path: Optional[str] = None) -> PcapResult:
    """PCAP 파일을 파싱해 구조화된 네트워크 정보를 반환.

    scapy가 없으면 tshark_path를 이용한 fallback 파서를 사용한다.
    둘 다 없을 경우 parse_error 필드에 원인을 담아 반환한다.
    """
    if not SCAPY_AVAILABLE:
        if tshark_path:
            return _parse_pcap_with_tshark(Path(pcap_path), tshark_path)
        return PcapResult(parse_error="scapy 미설치 (pip install scapy)")

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        return PcapResult(parse_error=f"파일 없음: {pcap_path}")

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        return PcapResult(parse_error=f"PCAP 읽기 실패: {e}")

    # --- 수집 자료구조 ---
    conn_map:     dict[tuple, NetworkConnection]  = {}
    dns_seen:     dict[str, DNSQuery]             = {}
    dns_responses:dict[str, list[str]]            = defaultdict(list)  # name→[ip]
    ip_to_domain: dict[str, list[str]]            = defaultdict(list)  # ip→[domain]
    raw_dns_list: list[DnsRawQuery]               = []                 # 프로세스 귀속용
    http_list:    list[HTTPRequest]               = []
    tls_list:     list[TLSInfo]                   = []
    beacon_ts:    dict[tuple, list[float]]        = defaultdict(list)  # (ip,port)→[ts]
    dns_base_cnt: dict[str, int]                  = defaultdict(int)   # base_domain→query count
    raw_ips:      set[str]                        = set()
    raw_domains:  set[str]                        = set()
    total_bytes_out  = 0
    total_bytes_in   = 0
    total_packets    = 0
    packets_loaded   = len(packets)   # rdpcap 성공 후 총 패킷 수
    packets_skipped  = 0
    pkt_errors: list[str] = []
    # C2 프로토콜 페이로드 수집: connection key → 누적 바이트
    smtp_raw: dict[tuple, bytearray] = defaultdict(bytearray)
    ftp_raw:  dict[tuple, bytearray] = defaultdict(bytearray)

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
                packets_skipped += 1
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
                packets_skipped += 1
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
                        src_port=src_port,
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

                        # 프로세스 귀속용 raw 쿼리 — PTR·분석서비스 포함 모든 쿼리 기록
                        raw_dns_list.append(DnsRawQuery(
                            name=name, qtype=qtype_str,
                            src_port=src_port, pkt_time=ts,
                            tx_id=getattr(dns_pkt, "id", 0) or 0,
                        ))

                        # PTR·분석서비스 도메인은 집계 전에 제외한다.
                        # dns_base_cnt 를 먼저 올리면 base domain "in-addr.arpa" 가
                        # 터널링 임계치를 넘어 dns_tunnel_suspects 를 오염시킨다.
                        _excluded = _is_excluded_dns_name(name)
                        if not _excluded:
                            raw_domains.add(name)
                            dns_base_cnt[_base_domain(name)] += 1

                        if name not in dns_seen:
                            if _excluded:
                                raw_domains.discard(name)
                            else:
                                ent = _subdomain_entropy(name)
                                dns_seen[name] = DNSQuery(
                                    name=name, qtype=qtype_str,
                                    entropy=round(ent, 3),
                                    is_ddns=_is_ddns_domain(name),
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

            # --- TLS ClientHello 파싱 (JA3 + SNI) ---
            if proto == "TCP" and Raw in pkt:
                raw_bytes = bytes(pkt[Raw])
                ja3_fields = _parse_ja3_clienthello(raw_bytes)
                if ja3_fields:
                    tls_ver, ciphers, ext_types, curves, pfmts, sni = ja3_fields
                    ja3_hash  = _build_ja3(tls_ver, ciphers, ext_types, curves, pfmts)
                    ja3_label = _KNOWN_JA3.get(ja3_hash, "")
                    ver_str   = _TLS_VER_STR.get(tls_ver, f"0x{tls_ver:04x}")
                    if sni:
                        raw_domains.add(sni)
                    if not (sni and _is_analysis_service_domain(sni)):
                        tls_list.append(TLSInfo(
                            sni=sni or "",
                            dst_ip=dst_ip, dst_port=dst_port,
                            ja3=ja3_hash, ja3_label=ja3_label,
                            tls_version=ver_str,
                        ))
                else:
                    # ClientHello가 아닌 경우 SNI 전용 폴백
                    sni = _extract_tls_sni(raw_bytes)
                    if sni:
                        raw_domains.add(sni)
                        if not _is_analysis_service_domain(sni):
                            tls_list.append(TLSInfo(sni=sni, dst_ip=dst_ip, dst_port=dst_port))

            # --- HTTP 파싱 ---
            # scapy.layers.http 임포트 시 포트 80 패킷은 HTTPRequest 레이어로 자동
            # 분해되어 Raw 레이어가 사라진다. ScapyHTTPRequest 체크를 Raw 유무와
            # 독립적으로 수행해야 GET 같은 body-없는 요청도 수집할 수 있다.
            if proto == "TCP":
                raw_bytes = bytes(pkt[Raw]) if Raw in pkt else b""
                if ScapyHTTPRequest is not None and ScapyHTTPRequest in pkt:
                    try:
                        hl = pkt[ScapyHTTPRequest]
                        method = (hl.Method or b"").decode(errors="replace")
                        host   = (hl.Host   or b"").decode(errors="replace")
                        path   = (hl.Path   or b"").decode(errors="replace")
                        ua     = (hl.User_Agent or b"").decode(errors="replace")
                        cl     = int((hl.Content_Length or b"0").decode(errors="replace") or 0)
                        ct     = (getattr(hl, "Content_Type", None) or b"").decode(errors="replace")
                        auth   = (getattr(hl, "Authorization", None) or b"").decode(errors="replace")
                        cookie = bool(getattr(hl, "Cookie", None))
                        # scapy HTTP 분해 시 Raw = 바디 그 자체
                        body_preview = raw_bytes[:512].decode(errors="replace").strip()
                        http_list.append(HTTPRequest(
                            method=method, host=host, path=path,
                            user_agent=ua, content_length=cl,
                            has_cookie=cookie, content_type=ct, authorization=auth,
                            body_preview=body_preview,
                            dst_ip=dst_ip, dst_port=dst_port,
                        ))
                    except Exception:
                        if raw_bytes:
                            req = _parse_http_raw(raw_bytes, dst_ip, dst_port)
                            if req:
                                http_list.append(req)
                elif raw_bytes:
                    req = _parse_http_raw(raw_bytes, dst_ip, dst_port)
                    if req:
                        http_list.append(req)

            # --- SMTP / FTP 페이로드 수집 ---
            if proto == "TCP" and Raw in pkt:
                raw_bytes = bytes(pkt[Raw])
                c2_key = (src_ip, dst_ip, dst_port)
                if dst_port in SMTP_PORTS:
                    smtp_raw[c2_key].extend(raw_bytes)
                elif dst_port in FTP_PORTS:
                    ftp_raw[c2_key].extend(raw_bytes)

        except Exception as e:
            # 처음 10개 패킷 오류만 기록 (과도한 로그 방지)
            if len(pkt_errors) < 10:
                pkt_errors.append(str(e))
            packets_skipped += 1
            continue

    # --- DNS 응답 IP 병합 ---
    for name, q in dns_seen.items():
        q.response_ips = list(set(dns_responses.get(name, [])))

    # --- no_response 플래그: A/AAAA 쿼리인데 응답 없음 (C2 오프라인 등) ---
    for q in dns_seen.values():
        if q.qtype in ("A", "AAAA") and not q.response_ips:
            q.no_response = True

    # --- DGA / 의심 도메인 판정 ---
    suspicious_domains = []
    for name, q in dns_seen.items():
        is_dga     = q.entropy >= DGA_ENTROPY_THRESHOLD
        is_long    = len(name.split(".")[0]) >= DNS_TUNNEL_LABEL_LEN
        is_tunnel  = _is_dns_tunnel_base(_base_domain(name), dns_base_cnt.get(_base_domain(name), 0))
        if is_dga or is_long or is_tunnel:
            q.suspicious = True
            suspicious_domains.append(name)

    # --- DNS 터널링 의심 베이스 도메인 ---
    dns_tunnel_suspects = [
        domain for domain, cnt in dns_base_cnt.items()
        if _is_dns_tunnel_base(domain, cnt)
    ]

    # --- 비콘 탐지 ---
    beacon_candidates = _detect_beacons(beacon_ts)

    # --- SMTP / FTP 세션 파싱 ---
    smtp_sessions: list[SmtpSession] = []
    for (src, dst, dport), payload in smtp_raw.items():
        s = _parse_smtp_raw(bytes(payload), src, dst, dport)
        if s:
            smtp_sessions.append(s)

    ftp_sessions: list[FtpSession] = []
    for (src, dst, dport), payload in ftp_raw.items():
        s = _parse_ftp_raw(bytes(payload), src, dst, dport)
        if s:
            ftp_sessions.append(s)

    # --- 요약 ---
    summary = PcapSummary(
        total_packets=total_packets,
        total_bytes_out=total_bytes_out,
        total_bytes_in=total_bytes_in,
        unique_dst_ips=len(raw_ips),
        unique_domains=len(raw_domains),
    )

    parse_error = ""
    if pkt_errors:
        parse_error = f"패킷 파싱 오류 {len(pkt_errors)}건 (처음 오류: {pkt_errors[0]})"

    # raw_dns_list: answers 채우기 (응답 패킷은 이미 dns_responses에 수집됨)
    for _rq in raw_dns_list:
        _rq.answers = list(set(dns_responses.get(_rq.name, [])))

    return PcapResult(
        connections=list(conn_map.values()),
        dns_queries=list(dns_seen.values()),
        raw_dns_queries=raw_dns_list,
        http_requests=http_list,
        tls_info=tls_list,
        beacon_candidates=beacon_candidates,
        smtp_sessions=smtp_sessions,
        ftp_sessions=ftp_sessions,
        suspicious_domains=sorted(set(suspicious_domains)),
        dns_tunnel_suspects=sorted(set(dns_tunnel_suspects)),
        summary=summary,
        raw_ips=raw_ips,
        raw_domains=raw_domains,
        ip_to_domain=dict(ip_to_domain),
        packets_loaded=packets_loaded,
        packets_skipped=packets_skipped,
        parse_error=parse_error,
    )
