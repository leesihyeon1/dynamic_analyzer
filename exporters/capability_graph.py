"""행위 그래프의 관측 집계 — 샘플 프로세스별로 무엇을 했는지 모은다.

exporters/behavior_graph.py 가 이 집계(_collect)로 실행 흐름과 행위를 한 그래프에 그린다.
대상의 판정 근거 세기: 2 악성 근거 · 1 의심 근거 · 0 일반 행위.
PCAP 세션은 ProcMon 소켓 이벤트와 4-튜플이 정확히 한 프로세스로 맞을 때만 그 프로세스에 붙이고,
그 밖에는 '프로세스 미확인'(None)으로 둔다 — 포트 번호만 보고 SMTP·FTP 로 단정하지 않는다.
"""
from collections import defaultdict, namedtuple
from html import escape
from pathlib import PureWindowsPath

from analysis.process_network_map import _parse_path
from analysis.sensitive_paths import is_sensitive_read_path


# 24×24 선 아이콘. 외부 이미지 요청 없이 오프라인에서 표시한다.
_ICONS = {
    "proc": "M3 4h18v13H3z M8 21h8 M12 17v4 M6 8l3 2-3 2 M12 12h5",
    "file": "M5 2h9l5 5v15H5z M14 2v6h5 M8 13h8 M8 17h6",
    "module": "M5 5h14v14H5z M9 9h6v6H9z M8 1v4 M15 1v4 M8 19v4 M15 19v4 M1 8h4 M1 15h4 M19 8h4 M19 15h4",
    "net": "M2 12a10 10 0 1 0 20 0a10 10 0 1 0-20 0 M2 12h20 M12 2q-9 10 0 20q9-10 0-20",
    "reg": "M2 2h7v6H2z M15 10h7v5h-7z M15 18h7v5h-7z M5 8v13h10 M5 12h10",
}
_ICON_COLOR = {"proc": "#9bbcff", "file": "#eac185", "module": "#c5a6ff",
               "reg": "#e9acbf", "net": "#76d4c1"}
_LEVEL_COLOR = {2: "#ff6b6b", 1: "#f0b429", 0: "#e3ecf6"}   # 2=악성 근거 1=의심 근거 0=관측
_LEVEL_NAME = {2: "악성 근거", 1: "의심 근거"}
_EXE_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk")
_LOLBINS = frozenset({"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
                      "cmd.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe",
                      "schtasks.exe", "wmic.exe", "msiexec.exe", "installutil.exe", "regasm.exe"})
_Observed = namedtuple("_Observed", "groups procs names lineage loader_pids")

def _is_external(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local
                or a.is_unspecified or a.is_reserved)


def _collect(result, fallback_pids=None):
    """샘플 계보 프로세스별 관측 행위를 집계한다 — 줄(lane) 보기와 통합 그래프가 공유한다."""
    procs = {p.pid: p for p in result.process_diff.get("new_processes", [])}
    lineage = set(result.lineage_pids) or set(fallback_pids or ())
    if result.sample_pid:
        lineage.add(result.sample_pid)
    # actor → (동작, 아이콘) → {(대상, 상세키): [대표 상세, 관측 횟수, 근거 수준]}
    groups = defaultdict(lambda: defaultdict(dict))
    names = {pid: p.name for pid, p in procs.items()}

    ioc = getattr(result, "ioc_report", None)
    tiers = {str(k).lower(): v for k, v in (getattr(ioc, "dropped_file_tiers", {}) or {}).items()}
    dropped = {str(f).lower() for f in (getattr(ioc, "dropped_files", None) or [])
               if tiers.get(str(f).lower(), 2) <= 2}
    try:
        from analysis.registry_relevance import registry_key_interest
    except Exception:
        registry_key_interest = lambda _p: ""          # noqa: E731

    def add(pid, action, icon, target, detail, *, level=0, distinct_detail=False):
        if not target:
            return
        targets = groups[pid][(action, icon)]
        key = (target, detail if distinct_detail else "")
        rec = targets.setdefault(key, [detail, 0, 0])
        rec[1] += 1
        rec[2] = max(rec[2], level)

    def file_level(path):
        p = str(path or "").lower()
        if p in dropped:
            return 2 if p.endswith(_EXE_EXT) else 1
        return 0

    loader_pids = set()
    for finding in result.sideload_findings:
        pid = finding.get("loader_pid")
        if pid in lineage:
            loader_pids.add(pid)
            names.setdefault(pid, finding.get("loader_name") or "로더")
            details = [finding.get("loader_exe"), finding.get("confidence"),
                       *finding.get("companions", [])]
            add(pid, "DLL 사이드로딩 후보", "module", finding.get("dll_path"),
                " · ".join(str(v) for v in details if v),
                level=2 if finding.get("confidence") == "HIGH" else 1)

    for finding in result.injection_findings:
        pid = finding.get("pid")
        if pid in lineage:
            for field, label in (("implanted_pe", "PE 삽입"), ("implanted_shc", "셸코드"),
                                 ("replaced", "이미지 교체"), ("hooked", "후킹")):
                if finding.get(field):
                    add(pid, "메모리 스캔", "module", label,
                        f"{finding['source']} · 탐지 {finding[field]}건 · {finding['confidence']}",
                        level=2 if finding.get("confidence") == "HIGH" else 1)

    actions = {"WriteFile": ("파일 쓰기", "file"), "RegSetValue": ("값 설정", "reg"),
               "Load Image": ("모듈 로드", "module"), "Process Create": ("자식 실행", "proc"),
               "TCP Connect": ("TCP 연결", "net"), "UDP Send": ("UDP 송신", "net")}
    for ev in result.filtered_events:
        if ev.pid not in lineage or ev.result != "SUCCESS":
            continue
        op = actions.get(ev.operation)
        level = 0
        if ev.operation == "ReadFile" and is_sensitive_read_path(ev.path):
            op, level = ("민감 경로 읽기", "file"), 2
        elif ev.operation in ("WriteFile", "Load Image"):
            level = file_level(ev.path)
        elif ev.operation == "RegSetValue":
            why = registry_key_interest(ev.path)
            level = 2 if ("Run" in why or "자동실행" in why) else (1 if why else 0)
        elif ev.operation == "Process Create":
            base = PureWindowsPath(ev.path or "").name.lower()
            level = 2 if file_level(ev.path) else (1 if base in _LOLBINS else 0)
        if op:
            names.setdefault(ev.pid, ev.process)
            add(ev.pid, *op, ev.path, f"ProcMon · {ev.time_str} · {ev.operation} · {ev.detail}",
                level=level)
    for conn in result.process_network_map:
        if conn.pid in lineage:
            names.setdefault(conn.pid, conn.process)
            add(conn.pid, f"{conn.proto} 소켓", "net", f"{conn.remote_ip}:{conn.remote_port}",
                f"{conn.direction} · 로컬 포트 {conn.local_port or '미확인'} · 관측 {conn.event_count}건",
                level=1 if _is_external(conn.remote_ip) else 0)
    attributed_dns = set()
    for q in result.dns_attributed:
        if q.attributed and q.pid in lineage:
            names.setdefault(q.pid, q.process)
            attributed_dns.add(q.name)
            add(q.pid, "DNS 질의", "net", q.name,
                f"{q.qtype} · " + (", ".join(q.answers) or "응답 주소 미확인"),
                level=0 if q.answers else 1)

    cap = result.pcap_result
    # 백그라운드 PID까지 포함해 포트 재사용과 소유자 충돌을 확인한다.
    owners = defaultdict(set)
    if any(getattr(cap, name, ()) for name in ("http_requests", "tls_info", "ftp_sessions", "smtp_sessions")):
        for ev in result.procmon_events or result.filtered_events:
            if ev.operation in ("TCP Connect", "TCP Send", "TCP Reconnect") and ev.result == "SUCCESS":
                key = _parse_path(ev.path)
                if all(key):
                    owners[key].add(ev.pid)

    def packet(session, action, target, detail, level=1):
        key = (getattr(session, "src_ip", ""), getattr(session, "src_port", 0),
               session.dst_ip, session.dst_port)
        pids = owners.get(key, ())
        pid = next(iter(pids)) if len(pids) == 1 else None
        if pid is not None and pid not in lineage:
            return
        route = f"{key[0]}:{key[1]} → {key[2]}:{key[3]}" if all(key) else f"{key[2]}:{key[3]}"
        # 동일 파일/도메인이라도 세션이나 명령 상세가 다르면 보존한다.
        add(pid, action, "net", target, " · ".join(filter(None, ("PCAP", route, detail))),
            level=level, distinct_detail=True)

    for h in getattr(cap, "http_requests", []):
        packet(h, "HTTP " + h.method, h.host + h.path, h.user_agent)
    for t in getattr(cap, "tls_info", []):
        packet(t, "TLS ClientHello", t.sni or t.dst_ip, f"{t.tls_version} · JA3 {t.ja3 or '미확인'}")
    for f in getattr(cap, "ftp_sessions", []):
        for cmd, files in (("STOR", f.uploaded), ("RETR", f.downloaded)):
            for path in files:
                packet(f, "FTP " + cmd, path, f"{cmd} {path}", level=2 if cmd == "STOR" else 1)
    for m in getattr(cap, "smtp_sessions", []):
        commands = [f"EHLO/HELO {m.ehlo_domain}" if m.ehlo_domain else "",
                    f"MAIL FROM {m.mail_from}" if m.mail_from else "",
                    *["RCPT TO " + addr for addr in m.rcpt_to],
                    "AUTH" if m.has_auth else "", "DATA" if m.has_data else ""]
        if any(commands):
            packet(m, "SMTP DATA" if m.has_data else "SMTP", f"{m.dst_ip}:{m.dst_port}",
                   " · ".join(x for x in commands if x), level=2 if m.has_data else 1)

    # 화면 캡처·키 입력 기록 (analysis.malware_traits) — 같은 파일의 '파일 쓰기'보다
    # 센 근거로 올려, 그래프에서 일반 드롭이 아니라 그 행위로 보이게 한다
    for beh in ((getattr(result, "malware_traits", None) or {}).get("behaviors") or []):
        for item in beh.get("items", []):
            if item.get("pid") in lineage:
                names.setdefault(item["pid"], item.get("process", ""))
                add(item["pid"], beh["label"], "file", item["path"],
                    f"{beh['technique_id']} {beh['name']}", level=2)

    # 어느 프로세스에도 귀속하지 못한 응답 없는 DNS — C2 후보이므로 숨기지 않는다
    try:
        from exporters.report_visuals import _unanswered_dns
        for name in _unanswered_dns(result):
            if name not in attributed_dns:
                add(None, "DNS 질의 (응답 없음)", "net", name,
                    "PCAP · 응답 없음 — C2 오프라인 또는 격리망", level=1)
    except Exception:
        pass

    return _Observed(groups, procs, names, lineage, loader_pids)
