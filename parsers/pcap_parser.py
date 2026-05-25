"""Parse PCAP files into structured network-activity objects.

Requires *scapy* for full functionality; degrades gracefully to returning
empty results when scapy is not installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional scapy import
# ---------------------------------------------------------------------------

SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw  # type: ignore
    # HTTPRequest lives in scapy.layers.http (scapy >= 2.4.3)
    try:
        from scapy.layers.http import HTTPRequest as ScapyHTTPRequest  # type: ignore
    except ImportError:
        ScapyHTTPRequest = None  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NetworkConnection:
    """A unique (proto, src_ip, dst_ip, dst_port) flow observed in the capture."""

    proto:    str        # "TCP" | "UDP"
    src_ip:   str
    dst_ip:   str
    dst_port: int
    count:    int = 1   # packet count to this dst


@dataclass
class DNSQuery:
    """A single DNS question observed in the capture."""

    name:  str
    qtype: str   # "A", "AAAA", "MX", etc.


@dataclass
class HTTPRequest:
    """An HTTP request extracted from a Raw payload."""

    method:     str
    host:       str
    path:       str
    user_agent: str


@dataclass
class PcapResult:
    """Aggregated network artefacts from a PCAP file."""

    connections:   list[NetworkConnection] = field(default_factory=list)
    dns_queries:   list[DNSQuery]          = field(default_factory=list)
    http_requests: list[HTTPRequest]       = field(default_factory=list)
    raw_ips:       set[str]                = field(default_factory=set)   # all dst IPs seen
    raw_domains:   set[str]                = field(default_factory=set)   # all DNS names queried


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

_QTYPE_MAP: dict[int, str] = {
    1:  "A",
    2:  "NS",
    5:  "CNAME",
    6:  "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# Simple regex patterns for extracting HTTP fields from raw payloads
_HTTP_REQUEST_RE = re.compile(
    rb"^(?P<method>[A-Z]{3,7})\s+(?P<path>\S+)\s+HTTP/\d",
    re.MULTILINE,
)
_HOST_RE        = re.compile(rb"^Host:\s*(?P<host>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
_UA_RE          = re.compile(rb"^User-Agent:\s*(?P<ua>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is an RFC1918/loopback/link-local address.

    Covers:
    * 10.0.0.0/8
    * 172.16.0.0/12  (172.16.x.x – 172.31.x.x)
    * 192.168.0.0/16
    * 127.0.0.0/8
    * 169.254.0.0/16 (link-local)
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
    except (ValueError, AttributeError):
        pass
    return False


def _extract_http_from_raw(raw_bytes: bytes) -> Optional[HTTPRequest]:
    """Attempt a best-effort HTTP request parse from raw packet bytes."""
    m = _HTTP_REQUEST_RE.search(raw_bytes)
    if not m:
        return None

    method = m.group("method").decode(errors="replace")
    path   = m.group("path").decode(errors="replace")

    host_m = _HOST_RE.search(raw_bytes)
    host   = host_m.group("host").decode(errors="replace").strip() if host_m else ""

    ua_m   = _UA_RE.search(raw_bytes)
    ua     = ua_m.group("ua").decode(errors="replace").strip() if ua_m else ""

    return HTTPRequest(method=method, host=host, path=path, user_agent=ua)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_pcap(pcap_path: Path) -> PcapResult:
    """Parse *pcap_path* and return aggregated network artefacts.

    If scapy is not installed or the file cannot be read, returns an empty
    :class:`PcapResult` without raising.

    Parameters
    ----------
    pcap_path:
        Path to the PCAP or PCAPNG file.

    Returns
    -------
    PcapResult
        Parsed network artefacts.
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

    # State tracking
    conn_map: dict[tuple[str, str, str, int], NetworkConnection] = {}
    dns_seen: dict[str, DNSQuery] = {}
    http_list: list[HTTPRequest] = []
    raw_ips: set[str] = set()
    raw_domains: set[str] = set()

    for pkt in packets:
        try:
            # Determine IP layer
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue

            # Track destination IPs (skip loopback / RFC1918)
            if not _is_private_ip(dst_ip):
                raw_ips.add(dst_ip)

            # Transport layer
            if TCP in pkt:
                proto    = "TCP"
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto    = "UDP"
                dst_port = pkt[UDP].dport
            else:
                proto    = "OTHER"
                dst_port = 0

            # Connection tracking
            if proto in ("TCP", "UDP"):
                key = (proto, src_ip, dst_ip, dst_port)
                if key in conn_map:
                    conn_map[key].count += 1
                else:
                    conn_map[key] = NetworkConnection(
                        proto=proto,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                    )

            # DNS queries
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                qr = pkt[DNSQR]
                try:
                    raw_name = qr.qname
                    if isinstance(raw_name, bytes):
                        name = raw_name.decode(errors="replace")
                    else:
                        name = str(raw_name)
                    name = name.rstrip(".")

                    qtype_int = int(qr.qtype)
                    qtype_str = _QTYPE_MAP.get(qtype_int, str(qtype_int))

                    raw_domains.add(name)

                    if name not in dns_seen:
                        dns_seen[name] = DNSQuery(name=name, qtype=qtype_str)
                except Exception:
                    pass

            # HTTP (via scapy HTTP layer or Raw fallback)
            if ScapyHTTPRequest is not None and ScapyHTTPRequest in pkt:
                try:
                    http_layer = pkt[ScapyHTTPRequest]
                    method = (http_layer.Method or b"").decode(errors="replace")
                    host   = (http_layer.Host   or b"").decode(errors="replace")
                    path   = (http_layer.Path   or b"").decode(errors="replace")
                    ua     = (http_layer.User_Agent or b"").decode(errors="replace")
                    http_list.append(
                        HTTPRequest(method=method, host=host, path=path, user_agent=ua)
                    )
                except Exception:
                    pass
            elif Raw in pkt:
                try:
                    result = _extract_http_from_raw(bytes(pkt[Raw]))
                    if result:
                        http_list.append(result)
                except Exception:
                    pass

        except Exception:
            # Never let a single malformed packet abort the whole parse
            continue

    return PcapResult(
        connections=list(conn_map.values()),
        dns_queries=list(dns_seen.values()),
        http_requests=http_list,
        raw_ips=raw_ips,
        raw_domains=raw_domains,
    )
