"""샘플 귀속이 확인된 연결만 행위 분석에 제공한다. 원본 PCAP은 유지한다."""
from parsers.pcap_parser import PcapResult
from analysis.process_network_map import _parse_path
from parsers.procmon_csv import EventCategory


def sample_network_view(pcap, events, pids):
    scoped = PcapResult()
    if pcap is None:
        return scoped
    owners = {}
    for ev in events:
        if ev.category != EventCategory.NETWORK or ev.operation not in {"TCP Connect", "TCP Send", "UDP Send"}:
            continue
        src, port, dst, remote_port = _parse_path(ev.path)
        if src and port and dst and remote_port:
            owners.setdefault((ev.operation[:3], src, port, dst, remote_port), set()).add(ev.pid)
    # 같은 연결 식별자가 다른 PID에도 관측되면 귀속 불명으로 보존만 한다.
    for conn in pcap.connections:
        key = (conn.proto.upper(), conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)
        matched = owners.get(key, set())
        if matched and matched <= pids:
            scoped.connections.append(conn)
    scoped.raw_ips = {c.dst_ip for c in scoped.connections}
    # HTTP/TLS/세션 요약에는 로컬 포트가 없어 안전한 프로세스 귀속이 불가능.
    # 원본 네트워크 탭에는 유지하되 샘플 기법의 확정 근거로 사용하지 않는다.
    return scoped


def refresh_tracked_events(result):
    """추가 인젝션 검사 이후 최신 추적 PID로 이벤트를 다시 구성한다."""
    from analysis.noise_filter import filter_events
    result.filtered_events = filter_events(result.procmon_events, result.all_pids or None)
