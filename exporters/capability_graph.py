"""수집된 프로세스 및 패킷 근거를 자체 포함 SVG로 표시한다."""
from collections import defaultdict
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


def _icon(kind, x, y):
    color = {"proc": "#9bbcff", "file": "#eac185", "module": "#c5a6ff",
             "reg": "#e9acbf", "net": "#76d4c1"}[kind]
    return (f"<g transform='translate({x} {y})' color='{color}'>"
            "<circle cx='12' cy='12' r='18' fill='currentColor' fill-opacity='.11'/>"
            f"<path d='{_ICONS[kind]}' fill='none' stroke='currentColor' "
            "stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/></g>")


def _short(text, n):
    return escape(text if len(text) <= n else text[:n-1] + "…")


def capability_preview_html(result):
    procs = {p.pid: p for p in result.process_diff.get("new_processes", [])}
    lineage = set(result.lineage_pids)
    if result.sample_pid:
        lineage.add(result.sample_pid)
    # actor → 관측 동작 → 대상별 대표 상세와 관측 횟수
    groups = defaultdict(lambda: defaultdict(dict))
    names = {pid: p.name for pid, p in procs.items()}

    def add(pid, action, icon, target, detail, *, distinct_detail=False):
        if not target:
            return
        targets = groups[pid][(action, icon)]
        key = (target, detail if distinct_detail else "")
        previous, n = targets.get(key, (detail, 0))
        targets[key] = previous, n + 1

    loader_pids = set()
    for finding in result.sideload_findings:
        pid = finding.get("loader_pid")
        if pid in lineage:
            loader_pids.add(pid)
            names.setdefault(pid, finding.get("loader_name") or "로더")
            details = [finding.get("loader_exe"), finding.get("confidence"),
                       *finding.get("companions", [])]
            add(pid, "DLL 사이드로딩 후보", "module", finding.get("dll_path"),
                " · ".join(str(v) for v in details if v))

    for finding in result.injection_findings:
        pid = finding.get("pid")
        if pid in lineage:
            for field, label in (("implanted_pe", "PE 삽입"), ("implanted_shc", "셸코드"),
                                 ("replaced", "이미지 교체"), ("hooked", "후킹")):
                if finding.get(field):
                    add(pid, "메모리 스캔", "module", label,
                        f"{finding['source']} · 탐지 {finding[field]}건 · {finding['confidence']}")

    actions = {"WriteFile": ("파일 쓰기", "file"), "RegSetValue": ("값 설정", "reg"),
               "Load Image": ("모듈 로드", "module"), "Process Create": ("자식 실행", "proc"),
               "TCP Connect": ("TCP 연결", "net"), "UDP Send": ("UDP 송신", "net")}
    for ev in result.filtered_events:
        if ev.pid not in lineage or ev.result != "SUCCESS":
            continue
        op = actions.get(ev.operation)
        if ev.operation == "ReadFile" and is_sensitive_read_path(ev.path):
            op = ("민감 경로 읽기", "file")
        if op:
            names.setdefault(ev.pid, ev.process)
            add(ev.pid, *op, ev.path, f"ProcMon · {ev.time_str} · {ev.operation} · {ev.detail}")
    for conn in result.process_network_map:
        if conn.pid in lineage:
            names.setdefault(conn.pid, conn.process)
            add(conn.pid, f"{conn.proto} 소켓", "net", f"{conn.remote_ip}:{conn.remote_port}",
                f"{conn.direction} · 로컬 포트 {conn.local_port or '미확인'} · 관측 {conn.event_count}건")
    for q in result.dns_attributed:
        if q.attributed and q.pid in lineage:
            names.setdefault(q.pid, q.process)
            add(q.pid, "DNS 질의", "net", q.name,
                f"{q.qtype} · " + (", ".join(q.answers) or "응답 주소 미확인"))

    cap = result.pcap_result
    # 백그라운드 PID까지 포함해 포트 재사용과 소유자 충돌을 확인한다.
    owners = defaultdict(set)
    if any(getattr(cap, name, ()) for name in ("http_requests", "tls_info", "ftp_sessions", "smtp_sessions")):
        for ev in result.procmon_events or result.filtered_events:
            if ev.operation in ("TCP Connect", "TCP Send", "TCP Reconnect") and ev.result == "SUCCESS":
                key = _parse_path(ev.path)
                if all(key):
                    owners[key].add(ev.pid)

    def packet(session, action, target, detail):
        key = (getattr(session, "src_ip", ""), getattr(session, "src_port", 0),
               session.dst_ip, session.dst_port)
        pids = owners.get(key, ())
        pid = next(iter(pids)) if len(pids) == 1 else None
        if pid is not None and pid not in lineage:
            return
        route = f"{key[0]}:{key[1]} → {key[2]}:{key[3]}" if all(key) else f"{key[2]}:{key[3]}"
        # 동일 파일/도메인이라도 세션이나 명령 상세가 다르면 보존한다.
        add(pid, action, "net", target, " · ".join(filter(None, ("PCAP", route, detail))), distinct_detail=True)

    for h in getattr(cap, "http_requests", []):
        packet(h, "HTTP " + h.method, h.host + h.path, h.user_agent)
    for t in getattr(cap, "tls_info", []):
        packet(t, "TLS ClientHello", t.sni or t.dst_ip, f"{t.tls_version} · JA3 {t.ja3 or '미확인'}")
    for f in getattr(cap, "ftp_sessions", []):
        for cmd, files in (("STOR", f.uploaded), ("RETR", f.downloaded)):
            for path in files:
                packet(f, "FTP " + cmd, path, f"{cmd} {path}")
    for m in getattr(cap, "smtp_sessions", []):
        commands = [f"EHLO/HELO {m.ehlo_domain}" if m.ehlo_domain else "",
                    f"MAIL FROM {m.mail_from}" if m.mail_from else "",
                    *["RCPT TO " + addr for addr in m.rcpt_to],
                    "AUTH" if m.has_auth else "", "DATA" if m.has_data else ""]
        if any(commands):
            packet(m, "SMTP DATA" if m.has_data else "SMTP", f"{m.dst_ip}:{m.dst_port}",
                   " · ".join(x for x in commands if x))

    if not groups:
        return "<p>도식화할 관측 행위가 없습니다.</p>"
    parts = ["""<style>.cap-lane{border-bottom:1px solid #344256;padding:12px 0;overflow:auto}
.cap-lane svg{display:block;min-width:720px;width:100%;max-width:1020px;color:#75cebf}
.cap-lane svg text{font:14px 'Segoe UI','Malgun Gothic',sans-serif;fill:#e3ecf6}
.cap-lane svg .caption{font-size:12px;fill:#a7b9c9}.cap-lane summary{cursor:pointer}
.cap-lane li{overflow-wrap:anywhere}.cap-lane small{color:#a7b9c9}</style>"""]
    for pid, actions_for_actor in groups.items():
        proc = procs.get(pid)
        actor = names.get(pid) or ("패킷 캡처" if pid is None else "이름 미확인")
        caption = "프로세스 귀속 미확인" if pid is None else f"PID {pid}"
        if pid in loader_pids:
            caption += " · 로더"
        parent = procs.get(getattr(proc, "ppid", None))
        origin = parent.name if parent else ("PCAP" if pid is None else "실행 기록")
        parent_pid = f"PID {parent.pid}" if parent else ""
        height = max(80, len(actions_for_actor) * 53)
        mid = height / 2
        svg = [f"<svg viewBox='-8 -6 986 {height + 12}' role='img' aria-label='{escape(actor)} 관측 관계'>",
               _icon("net" if pid is None else "proc", 5, mid-23),
               f"<text x='5' y='{mid+18}'>{_short(origin,20)}</text><text class='caption' x='5' y='{mid+35}'>{parent_pid}</text>",
               f"<path d='M142 {mid}h33l-5 -4m5 4-5 4' fill='none' stroke='#7694a2'/>",
               _icon("net" if pid is None else "proc", 190, mid-27),
               f"<text x='190' y='{mid+13}'>{_short(actor,23)}</text><text class='caption' x='190' y='{mid+31}'>{caption}</text>"]
        details = []
        for index, ((action, icon), targets) in enumerate(actions_for_actor.items()):
            y = (index + .5) * height / len(actions_for_actor)
            target, _ = next(iter(targets))
            label = PureWindowsPath(target).name if icon != "net" else target
            suffix = f" 외 {len(targets)-1}개" if len(targets)>1 else ""
            svg.extend([f"<path d='M375 {mid} C404 {mid} 405 {y} 435 {y}h8l-5 -4m5 4-5 4' fill='none' stroke='#548d90'/>",
                        _icon(icon,455,y-12),f"<text x='492' y='{y+5}'>{escape(action)}</text>",
                        f"<path d='M621 {y}h27l-5 -4m5 4-5 4' fill='none' stroke='#548d90'/>",
                        f"<text x='662' y='{y+5}'><title>{escape(target)}</title>{_short(label or target,28)}{suffix}</text>"])
            items = "".join(f"<li>{escape(path)} <small>· {count}건 · {escape(info)}</small></li>"
                            for (path, _), (info, count) in targets.items())
            details.append(f"<h4>{escape(action)}</h4><ul>{items}</ul>")
        command = getattr(proc, "cmdline", []) or []
        cmd = command if isinstance(command,str) else " ".join(command)
        parts.append("<section class='cap-lane'>" + "".join(svg) + "</svg><details><summary>"
                     + escape(actor) + " · " + caption + " 근거</summary>"
                     + (f"<code>{escape(cmd)}</code>" if cmd else "") + "".join(details) + "</details></section>")
    return "".join(parts)
