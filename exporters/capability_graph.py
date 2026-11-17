"""행위 그래프 — 샘플 계보 프로세스별 관측 행위를 자체 포함 SVG 로 표시한다.

한 프로세스가 한 줄(lane)이다.  [부모] → [프로세스] → 동작 → 대상
줄은 프로세스 트리 순서(샘플부터 깊이 우선)로 쌓이고, 자식 줄은 들여써서
위아래로 읽으면 실행 체인이, 옆으로 읽으면 그 프로세스가 한 일이 보인다.
대상 색은 판정 근거의 세기다 — 빨강: 악성 근거, 노랑: 의심 근거.
각 줄 아래 "근거"를 펼치면 ProcMon·PCAP 원문이 나온다.
"""
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
_ICON_COLOR = {"proc": "#9bbcff", "file": "#eac185", "module": "#c5a6ff",
               "reg": "#e9acbf", "net": "#76d4c1"}
_LEVEL_COLOR = {2: "#ff6b6b", 1: "#f0b429", 0: "#e3ecf6"}   # 2=악성 근거 1=의심 근거 0=관측
_LEVEL_NAME = {2: "악성 근거", 1: "의심 근거"}
_EXE_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk")
_LOLBINS = frozenset({"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
                      "cmd.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe",
                      "schtasks.exe", "wmic.exe", "msiexec.exe", "installutil.exe", "regasm.exe"})
_INDENT = 22   # 자식 줄 들여쓰기(px)

_CSS = """<style>
.cap-graph{margin:0 0 26px}
.cap-legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:.76rem;color:var(--muted,#a7b9c9);
  padding:0 0 10px;border-bottom:1px solid #344256}
.cap-legend span:before{content:'';display:inline-block;width:10px;height:10px;background:var(--c);margin-right:6px;vertical-align:-1px}
.cap-lane{border-bottom:1px solid #344256;padding:10px 0 8px;overflow:auto;scroll-margin-top:16px}
.cap-lane.cap-child{border-left:1px solid #4a5f7d}
.cap-lane svg{display:block;min-width:600px;width:100%;max-width:1020px;color:#75cebf}
.cap-lane svg text{font:14px 'Segoe UI','Malgun Gothic',sans-serif;fill:#e3ecf6}
.cap-lane svg .caption{font-size:12px;fill:#a7b9c9}
.cap-lane svg .cap-link{cursor:pointer}
.cap-lane svg .cap-link:hover text{text-decoration:underline}
.cap-lane summary{cursor:pointer;color:#a7b9c9;font-size:.82rem;padding:4px 0}
.cap-lane h4{font-size:.8rem;margin:8px 0 2px;color:#b7c9ed}
.cap-lane ul{margin:0;padding-left:18px}
.cap-lane li{overflow-wrap:anywhere;font-family:'Cascadia Code',Consolas,monospace;font-size:.76rem}
.cap-lane small{color:#a7b9c9}
.cap-lane code{display:block;margin:2px 0 4px;overflow-wrap:anywhere}
.cap-mark{display:inline-block;width:8px;height:8px;margin-right:6px;background:var(--c)}
.cap-flash{outline:1px solid var(--accent,#45d6bf)}
</style>
<script>
function capGoLane(pid){
  var el=document.getElementById('cap-'+pid); if(!el) return;
  el.scrollIntoView({block:'center',behavior:'auto'}); el.classList.add('cap-flash');
  setTimeout(function(){el.classList.remove('cap-flash');},1600);
}
</script>"""


def _icon(kind, x, y):
    return (f"<g transform='translate({x} {y})' color='{_ICON_COLOR[kind]}'>"
            "<circle cx='12' cy='12' r='18' fill='currentColor' fill-opacity='.11'/>"
            f"<path d='{_ICONS[kind]}' fill='none' stroke='currentColor' "
            "stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/></g>")


def _short(text, n):
    text = str(text)
    return escape(text if len(text) <= n else text[:n-1] + "…")


def _is_external(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local
                or a.is_unspecified or a.is_reserved)


def _lane_order(groups, procs, lineage, sample_pid):
    """샘플부터 깊이 우선 — (pid, 깊이) 목록. 귀속 미확인(None) 줄은 맨 끝."""
    kids = defaultdict(list)
    for p in procs.values():
        if p.pid in lineage:
            kids[p.ppid].append(p.pid)
    roots = sorted((pid for pid in lineage if getattr(procs.get(pid), "ppid", None) not in lineage),
                   key=lambda pid: (pid != sample_pid, pid))
    order, seen = [], set()

    def walk(pid, depth):
        if pid in seen:
            return
        seen.add(pid)
        if pid in groups:
            order.append((pid, depth))
            depth += 1        # 그려지지 않는 중간 프로세스는 들여쓰기를 늘리지 않는다
        for child in sorted(kids.get(pid, ())):
            walk(child, depth)

    for r in roots:
        walk(r, 0)
    order += [(pid, 0) for pid in groups if pid is not None and pid not in seen]
    if None in groups:
        order.append((None, 0))
    return order


def capability_preview_html(result, fallback_pids=None, *, include_evidence=True):
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

    # 어느 프로세스에도 귀속하지 못한 응답 없는 DNS — C2 후보이므로 숨기지 않는다
    try:
        from exporters.report_visuals import _unanswered_dns
        for name in _unanswered_dns(result):
            if name not in attributed_dns:
                add(None, "DNS 질의 (응답 없음)", "net", name,
                    "PCAP · 응답 없음 — C2 오프라인 또는 격리망", level=1)
    except Exception:
        pass

    if not groups:
        return "<p>도식화할 관측 행위가 없습니다.</p>"

    legend = ("<div class='cap-legend'>"
              f"<span style='--c:{_LEVEL_COLOR[2]}'>악성 근거 (드롭 실행 파일·자동실행 등록·민감 경로 읽기·주입)</span>"
              f"<span style='--c:{_LEVEL_COLOR[1]}'>의심 근거 (외부 통신·LOLBin 실행·관심 레지스트리)</span>"
              f"<span style='--c:{_LEVEL_COLOR[0]}'>관측</span>"
              "<span style='--c:#4a5f7d'>들여쓴 줄 = 위 줄 프로세스의 자식</span></div>")
    parts = [_CSS, "<div class='cap-graph'>", legend]
    sample_pid = getattr(result, "sample_pid", None)
    for pid, depth in _lane_order(groups, procs, lineage, sample_pid):
        actions_for_actor = groups[pid]
        proc = procs.get(pid)
        actor = names.get(pid) or ("패킷 캡처" if pid is None else "이름 미확인")
        caption = "프로세스 귀속 미확인" if pid is None else f"PID {pid}"
        if pid is not None and pid == sample_pid:
            caption += " · 샘플"
        if pid in loader_pids:
            caption += " · 로더"
        parent = procs.get(getattr(proc, "ppid", None))
        origin = parent.name if parent else ("PCAP" if pid is None else "실행 기록")
        parent_pid = f"PID {parent.pid}" if parent else ""
        # 동작 줄: 근거가 센 것부터, 같은 수준이면 관측 순서대로
        rows = sorted(actions_for_actor.items(),
                      key=lambda kv: -max(rec[2] for rec in kv[1].values()))
        height = max(80, len(rows) * 53)
        mid = height / 2
        if parent and parent.pid in groups:
            origin_g = (f"<g class='cap-link' onclick='capGoLane({int(parent.pid)})' role='link' "
                        f"aria-label='{escape(parent.name)} 줄로 이동'>")
        else:
            origin_g = "<g>"
        if pid is not None and include_evidence:
            actor_g = (f"<g class='cap-link' onclick='rvGoProc && rvGoProc({int(pid)})' role='link' "
                       f"aria-label='{escape(actor)} 프로세스 트리로 이동'>")
        else:
            actor_g = "<g>"
        svg = [f"<svg viewBox='-8 -6 986 {height + 12}' role='img' aria-label='{escape(actor)} 관측 관계'>",
               origin_g, _icon("net" if pid is None else "proc", 5, mid-23),
               f"<text x='5' y='{mid+18}'>{_short(origin,20)}</text><text class='caption' x='5' y='{mid+35}'>{parent_pid}</text></g>",
               f"<path d='M142 {mid}h33l-5 -4m5 4-5 4' fill='none' stroke='#7694a2'/>",
               actor_g, _icon("net" if pid is None else "proc", 190, mid-27),
               f"<text x='190' y='{mid+13}'>{_short(actor,23)}</text><text class='caption' x='190' y='{mid+31}'>{escape(caption)}</text></g>"]
        details = []
        for index, ((action, icon), targets) in enumerate(rows):
            y = (index + .5) * height / len(rows)
            # 대표 대상: 근거가 가장 센 것, 같으면 관측이 많은 것
            (target, _), (_, _, level) = max(targets.items(), key=lambda kv: (kv[1][2], kv[1][1]))
            label = PureWindowsPath(target).name if icon != "net" else target
            suffix = f" 외 {len(targets)-1}개" if len(targets) > 1 else ""
            color = _LEVEL_COLOR[level]
            weight = " font-weight='700'" if level else ""
            svg.extend([f"<path d='M375 {mid} C404 {mid} 405 {y} 435 {y}h8l-5 -4m5 4-5 4' fill='none' stroke='#548d90'/>",
                        _icon(icon, 455, y-12), f"<text x='492' y='{y+5}'>{escape(action)}</text>",
                        f"<path d='M621 {y}h27l-5 -4m5 4-5 4' fill='none' stroke='#548d90'/>",
                        f"<text x='662' y='{y+5}' style='fill:{color}'{weight}><title>{escape(target)}"
                        f"{' — ' + _LEVEL_NAME[level] if level else ''}</title>{_short(label or target, 28)}{suffix}</text>"])
            if not include_evidence:
                continue
            items = "".join(
                f"<li>{f'<span class=cap-mark style=--c:{_LEVEL_COLOR[lv]}></span>' if lv else ''}"
                f"{escape(path)} <small>· {count}건 · {escape(info)}</small></li>"
                for (path, _), (info, count, lv) in sorted(targets.items(), key=lambda kv: -kv[1][2]))
            details.append(f"<h4>{escape(action)}</h4><ul>{items}</ul>")
        command = getattr(proc, "cmdline", []) or []
        cmd = command if isinstance(command, str) else " ".join(command)
        indent = min(depth, 6) * _INDENT
        style = f" style='margin-left:{indent}px;padding-left:12px'" if indent else ""
        cls = "cap-lane cap-child" if indent else "cap-lane"
        lane_id = f" id='cap-{pid}'" if pid is not None else " id='cap-unattributed'"
        parts.append(f"<section class='{cls}'{lane_id}{style}>" + "".join(svg) + "</svg>")
        if include_evidence:
            parts.append("<details><summary>" + escape(actor) + " · " + escape(caption)
                         + " 근거</summary>" + (f"<code>{escape(cmd)}</code>" if cmd else "")
                         + "".join(details) + "</details>")
        parts.append("</section>")
    parts.append("</div>")
    return "".join(parts)
