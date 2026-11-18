"""샘플 귀속이 확인된 연결만 행위 분석에 제공한다. 원본 PCAP은 유지한다.

귀속 원리
---------
ProcMon 네트워크 이벤트 경로("로컬:포트 -> 원격:포트")와 PCAP 흐름의
(프로토콜, 클라이언트 포트, 서버 포트, 양 끝 주소)를 맞춰 PID를 찾는다.
ProcMon 기본 설정은 주소를 호스트명(DESKTOP-XXXX, dns.google)으로, 포트를
서비스 이름(:https)으로 보여주므로, 호스트명 끝점은 IP 비교 대신 포트 쌍으로
완화 매칭한다. 같은 식별자가 다른 PID에서도 관측되면 귀속 불명으로 보존만 한다.
"""
from __future__ import annotations

from collections import defaultdict

from parsers.pcap_parser import (
    PcapResult, PcapSummary, DNSQuery,
    is_external_ip, normalize_ip, summarize_flows,
    _base_domain, _subdomain_entropy, _is_ddns_domain, _is_excluded_dns_name,
    _is_analysis_service_domain, DGA_ENTROPY_THRESHOLD, DNS_TUNNEL_LABEL_LEN, _QTYPE_MAP,
)
from analysis.process_network_map import _parse_path, is_ip_literal
from parsers.procmon_csv import EventCategory


# 연결 식별자(로컬/원격 주소·포트)를 담는 ProcMon 오퍼레이션
_OWNER_OPS: frozenset[str] = frozenset({
    "TCP Connect", "TCP Send", "TCP Receive", "TCP Reconnect", "TCP Disconnect",
    "TCP Accept", "TCP Retransmit", "TCP TCPCopy",
    "UDP Send", "UDP Receive",
})


class FlowOwners:
    """ProcMon 이벤트 → 연결 식별자별 소유 PID 색인.

    lookup() 은 PCAP 쪽 (proto, src_ip, src_port, dst_ip, dst_port) 로 소유 PID
    집합을 돌려준다. IP 끝점은 정확히 비교하고, ProcMon이 이름 해석한 호스트명
    끝점은 (ip_to_domain 에 있으면 강한 일치, 아니면) 포트 쌍만으로 완화 매칭한다.
    가장 강하게 일치한 후보들의 PID만 반환한다.
    """

    def __init__(self, events, ip_to_domain: dict | None = None,
                 ops: frozenset[str] = _OWNER_OPS, success_only: bool = False) -> None:
        self._index: dict[tuple, list[tuple[str | None, str, int]]] = defaultdict(list)
        self._ip_to_domain = {normalize_ip(k): {str(d).lower() for d in v}
                              for k, v in (ip_to_domain or {}).items()}
        for ev in events or []:
            try:
                if ev.category != EventCategory.NETWORK or ev.operation not in ops:
                    continue
                if success_only and getattr(ev, "result", "SUCCESS") != "SUCCESS":
                    continue
                proto = ev.operation[:3]
                src, sport, dst, dport = _parse_path(ev.path, proto)
            except Exception:
                continue
            if not (sport and dst and dport):
                continue
            self._index[(proto, sport, dport)].append((src, dst, ev.pid))

    def __bool__(self) -> bool:
        return bool(self._index)

    def _end_score(self, host: str | None, ip: str, *, remote: bool) -> int:
        """끝점 일치 점수: 2=정확, 1=호스트명 완화, 0=불일치."""
        if not host:
            return 1
        if is_ip_literal(host):
            return 2 if normalize_ip(host) == ip else 0
        if remote and host.lower().rstrip(".") in self._ip_to_domain.get(ip, ()):
            return 2
        return 1

    def lookup(self, proto: str | None, src_ip: str, src_port: int,
               dst_ip: str, dst_port: int) -> set[int]:
        if not src_port or not dst_port:
            return set()
        protos = [proto.upper()] if proto else ["TCP", "UDP"]
        src_ip, dst_ip = normalize_ip(src_ip), normalize_ip(dst_ip)
        best, pids = 0, set()
        for pr in protos:
            for src, dst, pid in self._index.get((pr, int(src_port), int(dst_port)), ()):
                s = self._end_score(src, src_ip, remote=False)
                d = self._end_score(dst, dst_ip, remote=True)
                if not s or not d:
                    continue
                score = s + d
                if score > best:
                    best, pids = score, {pid}
                elif score == best:
                    pids.add(pid)
        return pids


def _attributed_names(dns_attributed, pids) -> dict[str, list]:
    """샘플 PID로 귀속된 DNS 질의 → {이름: [행...]}"""
    out: dict[str, list] = defaultdict(list)
    for q in dns_attributed or []:
        try:
            if getattr(q, "attributed", False) and q.pid in pids and q.name:
                out[q.name.rstrip(".")].append(q)
        except Exception:
            continue
    return out


def _endpoint_key(item) -> tuple:
    return (normalize_ip(getattr(item, "src_ip", "")), int(getattr(item, "src_port", 0) or 0),
            normalize_ip(getattr(item, "dst_ip", "")), int(getattr(item, "dst_port", 0) or 0))


def sample_network_view(pcap, events, pids, dns_attributed=None):
    """샘플 PID에 귀속된 네트워크 활동만 담은 PcapResult 를 만든다.

    Parameters
    ----------
    pcap:
        전체 PCAP 파싱 결과 (변경하지 않음).
    events:
        전체 ProcMon 이벤트 (다른 PID 소유 여부 확인용).
    pids:
        샘플 계열 PID 집합.
    dns_attributed:
        (선택) AttributedDnsQuery 목록. 샘플 PID로 귀속된 질의 이름·응답을
        raw_domains / dns_queries / ip_to_domain 에 반영한다. PCAP·ETW 귀속
        결과가 모두 병합된 뒤에 넘겨야 한다.
    """
    scoped = PcapResult()
    if pcap is None:
        return scoped
    pids = set(pids or ())
    owners = FlowOwners(events, getattr(pcap, "ip_to_domain", None))

    # ── 흐름 단위 귀속 ────────────────────────────────────────────────
    flows = list(getattr(pcap, "flows", None) or [])
    use_flows = bool(flows)
    candidates = flows if use_flows else list(pcap.connections)
    matched = []
    for conn in candidates:
        ports = [conn.src_port] if use_flows else (
            list(getattr(conn, "src_ports", None) or []) or [conn.src_port])
        hit = False
        for sp in ports:
            owned = owners.lookup(conn.proto, conn.src_ip, sp, conn.dst_ip, conn.dst_port)
            if owned and owned <= pids:
                hit = True
                break
        if hit:
            matched.append(conn)

    if use_flows:
        scoped.flows = matched
        scoped.connections = summarize_flows(matched)
    else:
        scoped.connections = matched
    flow_keys = set()
    for c in matched:
        ports = [c.src_port] if use_flows else (list(getattr(c, "src_ports", None) or []) or [c.src_port])
        for sp in ports:
            flow_keys.add((normalize_ip(c.src_ip), int(sp or 0),
                           normalize_ip(c.dst_ip), int(c.dst_port or 0)))
    server_eps = {(normalize_ip(c.dst_ip), c.dst_port) for c in matched}
    scoped.raw_ips = {normalize_ip(c.dst_ip) for c in scoped.connections
                      if is_external_ip(c.dst_ip)}

    # ── 응용 계층 요약: 귀속된 흐름과 4-튜플이 같은 항목만 옮긴다 ─────────
    for attr in ("http_requests", "tls_info", "smtp_sessions", "ftp_sessions"):
        items = [it for it in (getattr(pcap, attr, None) or [])
                 if _endpoint_key(it) in flow_keys]
        setattr(scoped, attr, items)

    scoped.beacon_candidates = [b for b in (pcap.beacon_candidates or [])
                                if (normalize_ip(b.dst_ip), b.dst_port) in server_eps]
    scoped.attempted_connections = [a for a in (getattr(pcap, "attempted_connections", None) or [])
                                    if (normalize_ip(a.dst_ip), a.dst_port) in server_eps]

    # ── DNS: 샘플 PID로 귀속된 질의 ───────────────────────────────────
    attributed = _attributed_names(dns_attributed, pids)
    names = set(attributed)
    pcap_dns = {q.name: q for q in (pcap.dns_queries or [])}
    for name in sorted(names):
        if _is_excluded_dns_name(name):
            continue
        q = pcap_dns.get(name)
        if q is None:
            rows = attributed[name]
            answers = list(dict.fromkeys(a for r in rows for a in (r.answers or [])))
            statuses = [getattr(r, "status", None) for r in rows]
            failed = any(s not in (None, 0) for s in statuses) and not answers
            ent = _subdomain_entropy(name)
            qtype = str(rows[0].qtype or "A")
            if qtype.isdigit():
                qtype = _QTYPE_MAP.get(int(qtype), qtype)
            q = DNSQuery(name=name, qtype=qtype, response_ips=answers,
                         entropy=round(ent, 3), is_ddns=_is_ddns_domain(name),
                         no_response=failed)
            q.reasons = (["dga"] if ent >= DGA_ENTROPY_THRESHOLD else []) + (
                ["long"] if len(name.split(".")[0]) >= DNS_TUNNEL_LABEL_LEN else [])
            q.suspicious = bool(q.reasons)
        scoped.dns_queries.append(q)
    scoped_names = {q.name for q in scoped.dns_queries}
    scoped.raw_dns_queries = [r for r in (getattr(pcap, "raw_dns_queries", None) or [])
                              if r.name in names]
    scoped.suspicious_domains = sorted(
        {d for d in (pcap.suspicious_domains or []) if d in scoped_names}
        | {q.name for q in scoped.dns_queries if q.suspicious})
    scoped.dga_domains = sorted(
        {d for d in (getattr(pcap, "dga_domains", None) or []) if d in scoped_names}
        | {q.name for q in scoped.dns_queries if "dga" in (getattr(q, "reasons", None) or [])})
    bases = {_base_domain(n) for n in scoped_names}
    scoped.dns_tunnel_suspects = [b for b in (pcap.dns_tunnel_suspects or []) if b in bases]

    # ── 도메인 / IP↔도메인 ────────────────────────────────────────────
    domains = set(scoped_names)
    for h in scoped.http_requests:
        host = (h.host or "").strip()
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]
        if host and not is_ip_literal(host):
            domains.add(host.rstrip("."))
    for t in scoped.tls_info:
        if t.sni and not _is_analysis_service_domain(t.sni):
            domains.add(t.sni.rstrip("."))
    scoped.raw_domains = {d for d in domains if d}

    ip_to_domain: dict[str, list[str]] = {}

    def _link(ip, name):
        ip = normalize_ip(ip)
        lst = ip_to_domain.setdefault(ip, [])
        if name not in lst:
            lst.append(name)

    for ip, doms in (getattr(pcap, "ip_to_domain", None) or {}).items():
        nip = normalize_ip(ip)
        for d in doms:
            if nip in scoped.raw_ips or d in names:
                _link(nip, d)
    for name, rows in attributed.items():
        for r in rows:
            for a in r.answers or []:
                if is_ip_literal(a):
                    _link(a, name)
    scoped.ip_to_domain = ip_to_domain

    scoped.summary = PcapSummary(
        total_packets=sum(c.count for c in scoped.connections),
        total_bytes_out=sum(c.bytes_out for c in scoped.connections),
        total_bytes_in=sum(c.bytes_in for c in scoped.connections),
        unique_dst_ips=len(scoped.raw_ips),
        unique_domains=len(scoped.raw_domains),
    )
    return scoped


def refresh_tracked_events(result):
    """추가 인젝션 검사 이후 최신 추적 PID로 이벤트를 다시 구성한다."""
    from analysis.noise_filter import filter_events
    result.filtered_events = filter_events(result.procmon_events, result.all_pids or None)
