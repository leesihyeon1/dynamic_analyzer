"""
HTML 동적 분석 보고서 생성 (다크 테마)
"""
from __future__ import annotations

import html as _html
from datetime import datetime
from pathlib import Path

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }
.container { max-width: 1300px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; color: #58a6ff; margin-bottom: 0.25rem; }
h2 { font-size: 1.15rem; color: #79c0ff; margin: 2rem 0 0.75rem;
     border-bottom: 1px solid #30363d; padding-bottom: 0.4rem; }
h3 { font-size: 0.95rem; color: #d2a8ff; margin: 1rem 0 0.4rem; }
.subtitle { color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { background: #161b22; color: #8b949e; text-align: left;
     padding: 0.5rem 0.75rem; font-weight: 600; white-space: nowrap; }
td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d;
     word-break: break-all; vertical-align: top; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 9999px;
         font-size: 0.72rem; font-weight: 600; white-space: nowrap; }
.badge-red    { background: #3d1f1f; color: #ff7b72; }
.badge-orange { background: #3d2a1f; color: #ffa657; }
.badge-yellow { background: #3d361f; color: #e3b341; }
.badge-green  { background: #1f3d2a; color: #56d364; }
.badge-blue   { background: #1f2d3d; color: #79c0ff; }
.badge-purple { background: #2d1f3d; color: #d2a8ff; }
.badge-gray   { background: #21262d; color: #8b949e; }
.alert { padding: 0.75rem 1rem; border-radius: 6px; margin: 0.75rem 0; font-size: 0.875rem; }
.alert-danger  { background: #3d1f1f; border-left: 3px solid #ff7b72; }
.alert-warning { background: #3d2a1f; border-left: 3px solid #ffa657; }
.alert-info    { background: #1f2d3d; border-left: 3px solid #79c0ff; }
.alert-success { background: #1f3d2a; border-left: 3px solid #56d364; }
.mono  { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.78rem; }
code   { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 4px;
         font-family: monospace; font-size: 0.8rem; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.card  { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.25rem; }
.kv td:first-child { color: #8b949e; width: 180px; font-weight: 500; white-space: nowrap; }
.tactic-tag { font-size: 0.68rem; color: #8b949e; margin-left: 0.4rem; }
.ev-file     { color: #79c0ff; }
.ev-registry { color: #d2a8ff; }
.ev-process  { color: #ffa657; }
.ev-network  { color: #56d364; }
.pg-wrap{display:flex;align-items:center;gap:.75rem;padding:.6rem 0;flex-wrap:wrap;border-top:1px solid #21262d;margin-top:.25rem}
.pg-info{color:#8b949e;font-size:.78rem;flex:1}
.pg-btns{display:flex;gap:.2rem;flex-wrap:wrap}
.pg-btn{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:.18rem .52rem;font-size:.78rem;cursor:pointer;min-width:28px}
.pg-btn:hover{background:#30363d}
.pg-active{background:#1f6feb!important;color:#fff!important;border-color:#1f6feb!important}
.pg-ellipsis{color:#8b949e;padding:0 .2rem;line-height:2;font-size:.78rem}
.tabs{display:flex;gap:0;border-bottom:1px solid #30363d;margin-bottom:1.5rem;overflow-x:auto;}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:#8b949e;
         padding:.6rem 1.1rem;cursor:pointer;font-size:.85rem;white-space:nowrap;transition:color .15s;}
.tab-btn:hover{color:#e6edf3;background:rgba(255,255,255,.03);}
.tab-btn.active{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600;}
.tab-panel{display:none;}
.tab-panel.active{display:block;animation:fadeIn .18s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.tbadge{display:inline-flex;align-items:center;justify-content:center;min-width:1.6rem;
        height:1.35rem;padding:0 .45rem;border-radius:9999px;font-size:.72rem;font-weight:700;
        line-height:1;margin-left:.3rem;}
.tbadge-red   {background:#3d1f1f;color:#ff7b72;}
.tbadge-orange{background:#3d2a1f;color:#ffa657;}
.tbadge-green {background:#1f3d2a;color:#56d364;}
.tbadge-blue  {background:#1f2d3d;color:#79c0ff;}
.tbadge-gray  {background:#21262d;color:#8b949e;}
"""

_JS = """
function setupPagination(tableId, rowsPerPage) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var allRows = Array.prototype.slice.call(table.rows, 1); // skip header
    var total = allRows.length;
    if (total <= rowsPerPage) return;
    var totalPages = Math.ceil(total / rowsPerPage);
    var cur = 1;
    var wrapper = document.createElement('div');
    wrapper.className = 'pg-wrap';
    table.parentNode.insertBefore(wrapper, table.nextSibling);
    function render(page) {
        cur = page;
        allRows.forEach(function(row, i) {
            row.style.display = (i >= (page-1)*rowsPerPage && i < page*rowsPerPage) ? '' : 'none';
        });
        var start = (page-1)*rowsPerPage + 1;
        var end = Math.min(page*rowsPerPage, total);
        wrapper.innerHTML = '';
        var info = document.createElement('span');
        info.className = 'pg-info';
        info.textContent = start + '–' + end + ' / 중 ' + total + '행';
        wrapper.appendChild(info);
        var btns = document.createElement('span');
        btns.className = 'pg-btns';
        function mkBtn(p, label, active) {
            var b = document.createElement('button');
            b.textContent = label !== undefined ? label : p;
            b.className = 'pg-btn' + (active ? ' pg-active' : '');
            b.onclick = function(){ render(p); };
            btns.appendChild(b);
        }
        function mkEll() {
            var s = document.createElement('span');
            s.className = 'pg-ellipsis';
            s.textContent = '…';
            btns.appendChild(s);
        }
        if (page > 1) mkBtn(page-1, '‹');
        var pages = [1];
        for (var p = Math.max(2, page-2); p <= Math.min(totalPages-1, page+2); p++) pages.push(p);
        if (totalPages > 1) pages.push(totalPages);
        // deduplicate
        pages = pages.filter(function(v,i,a){ return a.indexOf(v) === i; });
        var last = 0;
        pages.forEach(function(p) {
            if (p - last > 1) mkEll();
            mkBtn(p, p, p === cur);
            last = p;
        });
        if (page < totalPages) mkBtn(page+1, '›');
        wrapper.appendChild(btns);
    }
    render(1);
}
document.addEventListener('DOMContentLoaded', function () {
    var btns   = document.querySelectorAll('.tab-btn');
    var panels = document.querySelectorAll('.tab-panel');
    btns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            btns.forEach(function(b){ b.classList.remove('active'); });
            panels.forEach(function(p){ p.classList.remove('active'); });
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });
});
"""

_PG_INIT = """<script>
window.addEventListener('load', function() {
  setupPagination('tbl-file', 100);
  setupPagination('tbl-reg-diff', 100);
  setupPagination('tbl-reg-procmon', 100);
  setupPagination('tbl-net-beacon', 100);
  setupPagination('tbl-net-tls', 100);
  setupPagination('tbl-net-conn', 100);
  setupPagination('tbl-net-dns', 100);
  setupPagination('tbl-net-http', 100);
  setupPagination('tbl-ioc-ip', 100);
  setupPagination('tbl-ioc-domain', 100);
  setupPagination('tbl-ioc-file', 100);
  setupPagination('tbl-ioc-reg', 100);
  setupPagination('tbl-ioc-url', 100);
});
</script>"""

_TACTIC_COLOR = {
    "Execution":        "red",
    "Persistence":      "orange",
    "Privilege Escalation": "red",
    "Defense Evasion":  "yellow",
    "Command and Control": "purple",
    "Exfiltration":     "orange",
    "Impact":           "red",
}

def _b(text: str, color: str = "gray") -> str:
    return f'<span class="badge badge-{color}">{_html.escape(str(text))}</span>'

def _e(text: str) -> str:
    return _html.escape(str(text))

def _tb(val, color: str = "gray") -> str:
    """탭 배지 (숫자 0 이나 빈 값이면 생략)"""
    if not val:
        return ""
    return f'<span class="tbadge tbadge-{color}">{_html.escape(str(val))}</span>'

def _section_html(result) -> str:
    """MITRE ATT&CK 기법 테이블"""
    techs = result.behavior_report.techniques if result.behavior_report else []
    if not techs:
        return "<p class='alert alert-success'>탐지된 MITRE 기법 없음</p>"
    rows = ""
    for t in techs:
        color = _TACTIC_COLOR.get(t.tactic, "gray")
        ref   = t.reference or f"https://attack.mitre.org/techniques/{t.technique_id.replace('.','/')}/"
        evidence_html = "".join(
            f"<div class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(ev[:120])}</div>"
            for ev in t.evidence[:5]
        )
        rows += (
            f"<tr>"
            f"<td><a href='{_e(ref)}' target='_blank' style='color:#f97583;text-decoration:none'>"
            f"{_e(t.technique_id)}</a></td>"
            f"<td>{_e(t.technique_name)}</td>"
            f"<td>{_b(t.tactic, color)}</td>"
            f"<td>{evidence_html}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>ID</th><th>기법</th><th>전술</th><th>근거 (최대 5건)</th></tr>"
        f"{rows}</table>"
    )


def _file_events_html(result) -> str:
    from parsers.procmon_csv import EventCategory
    # CreateFile 제외 — Windows에서 CreateFile은 파일 열기(읽기)도 포함하므로
    # 실제 쓰기/변경 작업(WriteFile, DeleteFile, RenameFile, SetEndOfFile)만 표시
    events = [e for e in result.filtered_events if e.category == EventCategory.FILE
              and e.operation in ("WriteFile","DeleteFile","RenameFile","SetEndOfFile")]
    if not events:
        return "<p class='alert alert-success'>파일 시스템 이벤트 없음</p>"
    rows = ""
    op_color = {"WriteFile":"blue","DeleteFile":"red","RenameFile":"yellow","SetEndOfFile":"gray"}
    for e in events[:2000]:
        rows += (
            f"<tr>"
            f"<td class='mono' style='color:#8b949e;white-space:nowrap'>{_e(e.time_str[:12])}</td>"
            f"<td class='mono'>{_e(e.process)} <span style='color:#8b949e'>({e.pid})</span></td>"
            f"<td>{_b(e.operation, op_color.get(e.operation,'gray'))}</td>"
            f"<td class='mono ev-file'>{_e(e.path[:120])}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(e.result)}</td>"
            f"</tr>"
        )
    return (
        "<table id='tbl-file'><tr><th>시각</th><th>프로세스</th><th>작업</th><th>경로</th><th>결과</th></tr>"
        f"{rows}</table>"
    )


def _registry_events_html(result) -> str:
    from parsers.procmon_csv import EventCategory
    events = [e for e in result.filtered_events if e.category == EventCategory.REGISTRY
              and e.operation in ("RegSetValue","RegCreateKey","RegDeleteValue","RegDeleteKey")]
    reg_diff = result.registry_diff
    added    = reg_diff.get("added", [])
    modified = reg_diff.get("modified", [])

    parts = []

    # RegShot diff
    if added or modified:
        rows = ""
        for k, n, v in added[:500]:
            rows += (f"<tr><td>{_b('추가','green')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(v)[:80])}</td></tr>")
        for k, n, o, nw in modified[:500]:
            rows += (f"<tr><td>{_b('변경','orange')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(nw)[:80])}</td></tr>")
        parts.append(
            "<h3>레지스트리 스냅샷 비교 (Regshot)</h3>"
            "<table id='tbl-reg-diff'><tr><th>변경</th><th>키 경로</th><th>값 이름</th><th>데이터</th></tr>"
            f"{rows}</table>"
        )

    # ProcMon 이벤트
    if events:
        rows = ""
        for e in events[:1000]:
            rows += (
                f"<tr>"
                f"<td class='mono' style='color:#8b949e;white-space:nowrap'>{_e(e.time_str[:12])}</td>"
                f"<td class='mono'>{_e(e.process)}</td>"
                f"<td>{_b(e.operation,'purple')}</td>"
                f"<td class='mono ev-registry'>{_e(e.path[:100])}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(e.detail[:60])}</td>"
                f"</tr>"
            )
        parts.append(
            "<h3>ProcMon 레지스트리 이벤트</h3>"
            "<table id='tbl-reg-procmon'><tr><th>시각</th><th>프로세스</th><th>작업</th><th>키 경로</th><th>상세</th></tr>"
            f"{rows}</table>"
        )

    return "\n".join(parts) if parts else "<p class='alert alert-success'>레지스트리 변경 없음</p>"


def _fmt_bytes(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n/1_000:.1f} KB"
    return f"{n} B"


def _network_html(result) -> str:
    pcap = result.pcap_result
    if not pcap:
        return "<p class='alert alert-info'>tshark 캡처 없음</p>"

    parts = []

    # ── 캡처 요약 ──────────────────────────────────────────────
    s = getattr(pcap, "summary", None)
    if s:
        parts.append(
            f"<div class='card' style='margin-bottom:1rem'>"
            f"<table class='kv'>"
            f"<tr><td>총 패킷</td><td>{s.total_packets:,}</td></tr>"
            f"<tr><td>외부 송신</td><td>{_fmt_bytes(s.total_bytes_out)}</td></tr>"
            f"<tr><td>수신</td><td>{_fmt_bytes(s.total_bytes_in)}</td></tr>"
            f"<tr><td>외부 고유 IP</td><td>{s.unique_dst_ips}</td></tr>"
            f"<tr><td>고유 도메인</td><td>{s.unique_domains}</td></tr>"
            f"</table></div>"
        )

    # ── 비콘 탐지 ──────────────────────────────────────────────
    beacons = getattr(pcap, "beacon_candidates", [])
    if beacons:
        rows = "".join(
            f"<tr>"
            f"<td class='mono ev-network'>{_e(b.dst_ip)}</td>"
            f"<td class='mono'>{b.dst_port}</td>"
            f"<td>{b.count}회</td>"
            f"<td class='mono'>{b.interval_avg}s</td>"
            f"<td>{_b(f'지터 {b.jitter_ratio:.1%}', 'red' if b.jitter_ratio < 0.1 else 'orange')}</td>"
            f"</tr>"
            for b in beacons[:100]
        )
        parts.append(
            "<h3>🚨 비콘(Beaconing) 탐지</h3>"
            "<table id='tbl-net-beacon'><tr><th>목적지 IP</th><th>포트</th><th>횟수</th>"
            "<th>평균 간격</th><th>규칙성</th></tr>"
            f"{rows}</table>"
        )

    # ── TLS SNI ────────────────────────────────────────────────
    tls_list = getattr(pcap, "tls_info", [])
    if tls_list:
        seen = {}
        for t in tls_list:
            if t.sni not in seen:
                seen[t.sni] = t
        rows = "".join(
            f"<tr>"
            f"<td class='mono ev-network'>{_e(t.sni)}</td>"
            f"<td class='mono'>{_e(t.dst_ip)}</td>"
            f"<td class='mono'>{t.dst_port}</td>"
            f"</tr>"
            for t in list(seen.values())[:500]
        )
        parts.append(
            "<h3>🔒 TLS SNI (HTTPS 도메인)</h3>"
            "<table id='tbl-net-tls'><tr><th>SNI 도메인</th><th>목적지 IP</th><th>포트</th></tr>"
            f"{rows}</table>"
        )

    # ── DGA / 의심 도메인 ──────────────────────────────────────
    susp_domains = getattr(pcap, "suspicious_domains", [])
    if susp_domains:
        rows = "".join(
            f"<tr><td class='mono' style='color:#ff7b72'>{_e(d)}</td></tr>"
            for d in susp_domains[:50]
        )
        parts.append(
            "<h3>⚠ DGA / 고엔트로피 도메인</h3>"
            f"<table><tr><th>도메인</th></tr>{rows}</table>"
        )

    # ── 연결 목록 ──────────────────────────────────────────────
    if pcap.connections:
        # 프로세스-네트워크 매핑 룩업 테이블: (proto, dst_ip, dst_port) → 프로세스 목록
        pnmap = getattr(result, "process_network_map", [])
        proc_lookup: dict[tuple, list[str]] = {}
        for pn in pnmap:
            key = (pn.proto.upper(), pn.remote_ip, pn.remote_port)
            label = f"{pn.process} ({pn.pid})"
            if key not in proc_lookup:
                proc_lookup[key] = []
            if label not in proc_lookup[key]:
                proc_lookup[key].append(label)

        rows = ""
        for c in sorted(pcap.connections, key=lambda x: -x.bytes_out)[:1000]:
            ext = not _is_private_ip_str(c.dst_ip)
            ip_color = "ev-network" if ext else ""
            susp_badge = _b("!", "red") if c.suspicious_port else ""
            # IP → 도메인 역매핑
            domains = pcap.ip_to_domain.get(c.dst_ip, [])
            domain_str = f"<br><span style='color:#8b949e;font-size:0.72rem'>{_e(', '.join(domains[:2]))}</span>" if domains else ""
            # 프로세스 매핑
            procs = proc_lookup.get((c.proto.upper(), c.dst_ip, c.dst_port), [])
            if procs:
                proc_html = "<br>".join(
                    f"<span class='ev-process mono' style='font-size:0.72rem'>{_e(p)}</span>"
                    for p in procs[:3]
                )
            else:
                proc_html = "<span style='color:#8b949e'>-</span>"
            rows += (
                f"<tr>"
                f"<td>{_b(c.proto, 'blue')}</td>"
                f"<td class='mono'>{_e(c.src_ip)}</td>"
                f"<td class='mono {ip_color}'>{_e(c.dst_ip)}{domain_str}</td>"
                f"<td class='mono'>{c.dst_port} {susp_badge}</td>"
                f"<td style='color:#8b949e'>{c.count}</td>"
                f"<td class='mono'>{_fmt_bytes(c.bytes_out)}</td>"
                f"<td>{proc_html}</td>"
                f"</tr>"
            )
        parts.append(
            "<h3>네트워크 연결 (송신량 순)</h3>"
            "<table id='tbl-net-conn'><tr><th>프로토콜</th><th>출발지 IP</th><th>목적지 IP</th>"
            "<th>포트</th><th>횟수</th><th>송신량</th><th>프로세스</th></tr>"
            f"{rows}</table>"
        )

    # ── DNS 쿼리 ───────────────────────────────────────────────
    if pcap.dns_queries:
        rows = "".join(
            f"<tr>"
            f"<td class='mono {'ev-network' if not q.suspicious else ''}"
            f"' style='{'color:#ff7b72' if q.suspicious else ''}'>{_e(q.name)}</td>"
            f"<td class='mono' style='color:#8b949e'>{_e(q.qtype)}</td>"
            f"<td class='mono' style='color:#8b949e'>{q.entropy:.2f}</td>"
            f"<td class='mono' style='color:#56d364;font-size:0.72rem'>"
            f"{_e(', '.join(q.response_ips[:3]))}</td>"
            f"{'<td>' + _b('DGA?','red') + '</td>' if q.suspicious else '<td></td>'}"
            f"</tr>"
            for q in sorted(pcap.dns_queries, key=lambda x: -x.entropy)[:1000]
        )
        parts.append(
            "<h3>DNS 쿼리 (엔트로피 순)</h3>"
            "<table id='tbl-net-dns'><tr><th>도메인</th><th>타입</th><th>엔트로피</th>"
            "<th>응답 IP</th><th>의심</th></tr>"
            f"{rows}</table>"
        )

    # ── HTTP 요청 ──────────────────────────────────────────────
    if pcap.http_requests:
        rows = "".join(
            f"<tr>"
            f"<td>{_b(r.method,'orange')}</td>"
            f"<td class='mono'>{_e(r.host)}</td>"
            f"<td class='mono ev-network'>{_e(r.path[:80])}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(r.user_agent[:60])}</td>"
            f"<td class='mono'>{_fmt_bytes(r.content_length) if r.content_length else '-'}</td>"
            f"<td>{'🍪' if r.has_cookie else ''}</td>"
            f"</tr>"
            for r in pcap.http_requests[:500]
        )
        parts.append(
            "<h3>HTTP 요청</h3>"
            "<table id='tbl-net-http'><tr><th>메서드</th><th>호스트</th><th>경로</th>"
            "<th>User-Agent</th><th>Body</th><th>Cookie</th></tr>"
            f"{rows}</table>"
        )

    return "\n".join(parts) if parts else "<p class='alert alert-success'>외부 네트워크 활동 없음</p>"


def _is_private_ip_str(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or a == 127)
    except Exception:
        return False


def _process_network_html(result) -> str:
    """프로세스↔네트워크 연결 매핑 테이블"""
    pnmap = getattr(result, "process_network_map", [])
    if not pnmap:
        return "<p class='alert alert-info'>ProcMon 네트워크 이벤트 없음 (procmon 필요)</p>"

    rows = ""
    for c in pnmap[:1000]:
        dir_color = "blue" if c.direction == "outbound" else "orange"
        dir_label = "→ 송신" if c.direction == "outbound" else "← 수신"
        rows += (
            f"<tr>"
            f"<td class='mono ev-process'>{_e(c.process)}"
            f" <span style='color:#8b949e'>({c.pid})</span></td>"
            f"<td>{_b(c.proto, 'blue')}</td>"
            f"<td>{_b(dir_label, dir_color)}</td>"
            f"<td class='mono ev-network'>{_e(c.remote_ip)}</td>"
            f"<td class='mono'>{c.remote_port}</td>"
            f"<td style='color:#8b949e;text-align:right'>{c.event_count:,}</td>"
            f"</tr>"
        )
    return (
        "<table id='tbl-proc-net'>"
        "<tr><th>프로세스</th><th>프로토콜</th><th>방향</th>"
        "<th>외부 IP</th><th>포트</th><th>이벤트</th></tr>"
        f"{rows}</table>"
    )


def _process_html(result) -> str:
    new_procs = result.process_diff.get("new_processes", [])
    if not new_procs:
        return "<p class='alert alert-success'>신규 프로세스 없음</p>"
    rows = ""
    for p in new_procs:
        cmdline = " ".join(p.cmdline) if p.cmdline else ""
        rows += (
            f"<tr>"
            f"<td class='mono'>{p.pid}</td>"
            f"<td class='mono ev-process'>{_e(p.name)}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(p.exe or '')}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(cmdline[:100])}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>PID</th><th>프로세스</th><th>경로</th><th>명령줄</th></tr>"
        f"{rows}</table>"
    )


def _render_proc_result(proc) -> str:
    """PeSieveResult → HTML 블록 (헤더 + 모듈 테이블)"""
    arch      = "64bit" if proc.is_64bit else "32bit"
    shc_badge = _b(f"쉘코드 {proc.implanted_shc}개", "red") if proc.implanted_shc else ""
    if not proc.modules:
        return (
            f"<p style='margin:.4rem 0;font-size:0.85rem'>PID {proc.pid} "
            f"<span style='color:#8b949e'>({_e(arch)})</span> "
            f"{_b(f'의심 {proc.suspicious}개', 'orange')} {shc_badge}</p>"
        )
    rows = ""
    for mod in proc.modules:
        mod_name  = Path(mod.module_path).name if mod.module_path else "-"
        dump_name = Path(mod.dump_file).name   if mod.dump_file   else "-"
        if mod.is_shellcode:
            kind_badge = _b("쉘코드", "red")
        elif mod.implanted_count:
            kind_badge = _b("PE 인젝션", "orange")
        else:
            kind_badge = _b("훅/패치", "yellow")
        rows += (
            f"<tr>"
            f"<td class='mono' style='color:#c9d1d9'>{_e(mod_name)}</td>"
            f"<td>{kind_badge}</td>"
            f"<td class='mono' style='color:#8b949e'>{mod.patches_count}</td>"
            f"<td class='mono' style='color:#8b949e'>{mod.implanted_count}</td>"
            f"<td class='mono ev-file'>{_e(dump_name)}</td>"
            f"</tr>"
        )
    return (
        f"<h3>PID {proc.pid} "
        f"<span style='color:#8b949e;font-size:0.8rem;font-weight:normal'>"
        f"({_e(arch)}) &nbsp;"
        f"{_b(f'의심 {proc.suspicious}개', 'orange')} {shc_badge}"
        f"</span></h3>"
        f"<table>"
        f"<tr><th>모듈</th><th>유형</th><th>패치 수</th><th>이식 수</th><th>덤프 파일</th></tr>"
        f"{rows}</table>"
    )


def _shellcode_html(result) -> str:
    """pe-sieve / hollows-hunter 쉘코드·인젝션 결과"""
    hh_r    = getattr(result, "hh_result",        None)
    pe_list = getattr(result, "pe_sieve_results",  None) or []

    if hh_r is None and not pe_list:
        return (
            "<p class='alert alert-info'>"
            "pe-sieve / hollows-hunter 미설치 — 메모리 스캔 생략됨. "
            "<code>C:\\Tools</code> 또는 <code>PATH</code>에 실행 파일 배치 후 재분석하면 표시됩니다.</p>"
        )

    parts = []

    # ── hollows-hunter 집계 ────────────────────────────────────────
    hh_scanned = 0
    hh_susp    = 0
    hh_shc     = 0
    hh_pe_inj  = 0
    if hh_r is not None:
        if hh_r.error:
            parts.append(f"<p class='alert alert-warning'>⚠ hollows-hunter: {_e(hh_r.error)}</p>")
        else:
            hh_scanned = hh_r.total_scanned
            hh_susp    = len(hh_r.suspicious_processes)
            hh_shc     = sum(r.implanted_shc for r in hh_r.process_results)
            hh_pe_inj  = sum(r.implanted_pe  for r in hh_r.process_results)

    # ── pe-sieve 신규 프로세스 집계 ───────────────────────────────
    pe_valid   = [r for r in pe_list if not r.error]
    pe_errors  = [r for r in pe_list if r.error]
    pe_susp    = [r for r in pe_valid if r.suspicious > 0]
    pe_shc     = sum(r.implanted_shc for r in pe_valid)
    pe_pe_inj  = sum(r.implanted_pe  for r in pe_valid)

    has_hh_data = hh_r is not None and not hh_r.error
    has_pe_data = bool(pe_valid)

    # ── 요약 카드 ──────────────────────────────────────────────────
    if has_hh_data or has_pe_data:
        rows = ""
        if has_hh_data:
            ss = "#ff7b72" if hh_susp   else "#56d364"
            pi = "#e3b341" if hh_pe_inj else "#8b949e"
            sc = "#ff7b72" if hh_shc    else "#8b949e"
            rows += (
                f"<tr><td>hollows-hunter (전체 시스템)</td><td>"
                f"{hh_scanned}개 스캔 &nbsp;"
                f"<b style='color:{ss}'>의심 {hh_susp}개</b> &nbsp;"
                f"<b style='color:{pi}'>PE인젝션 {hh_pe_inj}개</b> &nbsp;"
                f"<b style='color:{sc}'>쉘코드 {hh_shc}개</b>"
                f"</td></tr>"
            )
        if has_pe_data:
            pss = "#ff7b72" if pe_susp   else "#56d364"
            ppi = "#e3b341" if pe_pe_inj else "#8b949e"
            psc = "#ff7b72" if pe_shc    else "#8b949e"
            rows += (
                f"<tr><td>pe-sieve (신규 프로세스)</td><td>"
                f"{len(pe_valid)}개 스캔 &nbsp;"
                f"<b style='color:{pss}'>의심 {len(pe_susp)}개</b> &nbsp;"
                f"<b style='color:{ppi}'>PE인젝션 {pe_pe_inj}개</b> &nbsp;"
                f"<b style='color:{psc}'>쉘코드 {pe_shc}개</b>"
                f"</td></tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1rem'>"
            f"<table class='kv'>{rows}</table>"
            f"</div>"
        )

    # ── hollows-hunter 상세 (의심 프로세스만) ─────────────────────
    if has_hh_data:
        if hh_r.suspicious_processes:
            for proc in hh_r.suspicious_processes:
                parts.append(_render_proc_result(proc))
        else:
            parts.append(
                "<p class='alert alert-success'>✅ hollows-hunter: 인젝션 / 쉘코드 미탐지</p>"
            )

    # ── pe-sieve 신규 프로세스 상세 ───────────────────────────────
    if pe_list:
        parts.append(
            "<h3 style='margin-top:1.5rem;border-top:1px solid #30363d;padding-top:.75rem'>"
            "pe-sieve — 신규 프로세스 스캔 결과</h3>"
        )
        for r in pe_list:
            if r.error:
                # 이미 종료됐거나 권한 없는 프로세스 — 회색으로
                parts.append(
                    f"<p style='color:#8b949e;font-size:0.82rem;margin:.25rem 0'>"
                    f"PID {r.pid}: {_e(r.error[:120])}</p>"
                )
            elif r.suspicious > 0:
                parts.append(_render_proc_result(r))
            else:
                arch = "64bit" if r.is_64bit else "32bit"
                parts.append(
                    f"<p style='color:#56d364;font-size:0.82rem;margin:.25rem 0'>"
                    f"✅ PID {r.pid} ({_e(arch)}): 이상 없음</p>"
                )

    return "\n".join(parts)


def _ioc_html(result) -> str:
    ioc = result.ioc_report
    if not ioc:
        return ""
    parts = []

    def _list_table(title: str, items: list, label: str, table_id: str = "") -> str:
        if not items:
            return ""
        id_attr = f" id='{table_id}'" if table_id else ""
        rows = "".join(f"<tr><td class='mono'>{_e(str(i))}</td></tr>" for i in items[:1000])
        return f"<h3>{title}</h3><table{id_attr}><tr><th>{label}</th></tr>{rows}</table>"

    parts.append(_list_table("외부 IP", ioc.ip_addresses, "IP 주소", "tbl-ioc-ip"))
    parts.append(_list_table("도메인", ioc.domains, "도메인", "tbl-ioc-domain"))
    parts.append(_list_table("드롭된 파일", ioc.dropped_files, "파일 경로", "tbl-ioc-file"))
    parts.append(_list_table("레지스트리 키", ioc.registry_keys, "키 경로", "tbl-ioc-reg"))
    parts.append(_list_table("URL", ioc.urls, "URL", "tbl-ioc-url"))

    return "\n".join(p for p in parts if p)


def generate_html_report(result, output_path: str) -> None:
    """AnalysisResult → HTML 파일 저장"""
    generated   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sample_name = result.config.sample_path.name if result.config.sample_path else "전체 시스템 모니터링"
    techs = result.behavior_report.techniques if result.behavior_report else []
    ioc   = result.ioc_report

    # ── 요약 카운트 ──────────────────────────────────────────────
    _hh      = getattr(result, "hh_result",        None)
    _ps_list = getattr(result, "pe_sieve_results",  None) or []
    # 의심 프로세스 수 집계 (쉘코드 + PE 인젝션 + 훅 포함)
    shc_total = 0
    if _hh and not _hh.error:
        shc_total += len(_hh.suspicious_processes)
    shc_total += sum(1 for r in _ps_list if not r.error and r.suspicious > 0)

    tech_count = len(techs)
    ip_count   = len(ioc.ip_addresses)  if ioc else 0
    file_count = len(ioc.dropped_files) if ioc else 0
    reg_added  = len(result.registry_diff.get("added",    []))
    reg_mod    = len(result.registry_diff.get("modified", []))
    conn_count = len(result.pcap_result.connections)  if result.pcap_result else 0
    dns_count  = len(result.pcap_result.dns_queries)  if result.pcap_result else 0
    ioc_total  = (ip_count + (len(ioc.domains) if ioc else 0)
                  + file_count + (len(ioc.registry_keys) if ioc else 0)
                  + (len(ioc.urls) if ioc else 0))

    # ── 위협 수준 ────────────────────────────────────────────────
    threat_score = tech_count + (1 if shc_total else 0)
    threat_color = "red" if threat_score >= 3 else ("orange" if threat_score >= 1 else "green")
    threat_label = "HIGH" if threat_score >= 3 else ("MEDIUM" if threat_score >= 1 else "CLEAN")

    tools_html = "  ".join(
        f"{_b('✔ ' + k, 'green') if v else _b('✘ ' + k, 'gray')}"
        for k, v in result.tools_used.items()
    )

    # ── 탭 배지 ──────────────────────────────────────────────────
    tab1_b = _tb(tech_count, "red"    if tech_count else "gray") if tech_count else ""
    tab2_b = _tb(file_count, "blue"   if file_count else "gray") if file_count else ""
    tab3_b = _tb(reg_added + reg_mod,
                 "yellow" if (reg_added + reg_mod) else "gray")  if (reg_added + reg_mod) else ""
    tab4_b = _tb(conn_count, "green"  if conn_count else "gray") if conn_count else ""
    tab5_b = (_tb(shc_total,  "red"    if shc_total  else "gray") if shc_total  else "") + \
             (_tb(ioc_total,  "orange" if ioc_total  else "gray") if ioc_total  else "")

    body = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dynamic Analysis — {_e(sample_name)}</title>
<style>{_CSS}</style>
<script>{_JS}</script>
</head>
<body>
<div class="container">

<h1>🧪 Dynamic Malware Analysis Report</h1>
<p class="subtitle">
  샘플: <code>{_e(str(result.config.sample_path) if result.config.sample_path else "전체 시스템 모니터링")}</code> &nbsp;|&nbsp;
  생성: {generated} &nbsp;|&nbsp;
  모니터링: {result.config.timeout}초 &nbsp;|&nbsp;
  총 소요: {result.end_time - result.start_time:.1f}초
</p>
<p style="margin-bottom:1rem">
  {_b('위협 수준: ' + threat_label, threat_color)}
  &nbsp;
  {_b(f'MITRE {tech_count}건', 'red' if tech_count else 'gray')}
  {_b(f'인젝션·쉘코드 {shc_total}건', 'red' if shc_total else 'gray')}
  {_b(f'외부 IP {ip_count}건', 'orange' if ip_count else 'gray')}
  {_b(f'드롭 파일 {file_count}건', 'orange' if file_count else 'gray')}
</p>
<p style="margin-bottom:1.5rem">{tools_html}</p>

{"".join(f'<p class="alert alert-warning">⚠ {_e(e)}</p>' for e in result.errors) if result.errors else ""}

<!-- ── 탭 네비게이션 ── -->
<div class="tabs">
  <button class="tab-btn active" data-tab="tab-basic">
    📋 기본 분석{tab1_b}
  </button>
  <button class="tab-btn" data-tab="tab-filesystem">
    📂 파일시스템{tab2_b}
  </button>
  <button class="tab-btn" data-tab="tab-registry">
    🔑 레지스트리{tab3_b}
  </button>
  <button class="tab-btn" data-tab="tab-network">
    🌐 네트워크{tab4_b}
  </button>
  <button class="tab-btn" data-tab="tab-ioc">
    🔍 IOC{tab5_b}
  </button>
</div>

<!-- ══════════ 탭 1: 기본 분석 ══════════ -->
<div id="tab-basic" class="tab-panel active">

  <h2>📋 분석 개요</h2>
  <div class="grid2">
    <div class="card">
      <table class="kv">
        <tr><td>샘플 이름</td><td class="mono">{_e(sample_name)}</td></tr>
        <tr><td>샘플 PID</td><td class="mono">{result.sample_pid or '-'}</td></tr>
        <tr><td>추적 PID</td><td class="mono">{', '.join(str(p) for p in sorted(result.all_pids)) or '-'}</td></tr>
        <tr><td>전체 이벤트</td><td>{len(result.procmon_events):,}</td></tr>
        <tr><td>필터 후 이벤트</td><td>{len(result.filtered_events):,}</td></tr>
      </table>
    </div>
    <div class="card">
      <table class="kv">
        <tr><td>신규 프로세스</td><td>{len(result.process_diff.get('new_processes', []))}</td></tr>
        <tr><td>레지스트리 추가</td><td>{reg_added}</td></tr>
        <tr><td>레지스트리 변경</td><td>{reg_mod}</td></tr>
        <tr><td>네트워크 연결</td><td>{conn_count}</td></tr>
        <tr><td>DNS 쿼리</td><td>{dns_count}</td></tr>
        <tr><td>인젝션·쉘코드 의심</td><td><b style="color:{'#ff7b72' if shc_total else '#56d364'}">{shc_total}개 프로세스</b></td></tr>
      </table>
    </div>
  </div>

  <h2>🎯 MITRE ATT&amp;CK 매핑</h2>
  {_section_html(result)}

  <h2>🌲 신규 프로세스</h2>
  {_process_html(result)}

</div>

<!-- ══════════ 탭 2: 파일시스템 활동 ══════════ -->
<div id="tab-filesystem" class="tab-panel">

  <h2>📂 파일 시스템 활동 (ProcMon)</h2>
  {_file_events_html(result)}

</div>

<!-- ══════════ 탭 3: 레지스트리 활동 ══════════ -->
<div id="tab-registry" class="tab-panel">

  <h2>🔑 레지스트리 변경 (ProcMon + Regshot)</h2>
  {_registry_events_html(result)}

</div>

<!-- ══════════ 탭 4: 네트워크 연결 ══════════ -->
<div id="tab-network" class="tab-panel">

  <h2>🌐 네트워크 활동 (tshark)</h2>
  {_network_html(result)}

  <h2>🔗 프로세스 ↔ 네트워크 매핑 (ProcMon)</h2>
  {_process_network_html(result)}

</div>

<!-- ══════════ 탭 5: IOC ══════════ -->
<div id="tab-ioc" class="tab-panel">

  <h2>🔬 쉘코드 / 메모리 인젝션</h2>
  {_shellcode_html(result)}

  <h2>💀 IOC 목록</h2>
  {_ioc_html(result)}

</div>

</div>
{_PG_INIT}
</body>
</html>"""

    Path(output_path).write_text(body, encoding="utf-8")
