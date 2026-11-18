"""
evidence_tab.py — HTML 리포트의 "증거" 탭

리포트의 각 판정을 분석가가 직접 검증할 수 있도록

  ① 행위별 증적  — 드롭 파일(보존 사본·해시), 자동실행 레지스트리, 메모리 덤프,
                   네트워크(Wireshark 필터), 프로세스(ProcMon 필터)
  ② 수집 원본    — 결과 폴더에 남은 ProcMon CSV/PML, PCAP, TLS 키, 덤프, JSON …

을 한 화면에 모은다. 링크는 리포트 기준 상대 경로라 file:// 로 열어도,
hunt_relay 가 서빙하는 http://127.0.0.1 로 열어도 그대로 동작한다.
"경로 복사" 버튼은 FLARE VM 의 도구(Wireshark, ProcMon, x64dbg, HxD …)에
바로 붙여 넣을 수 있도록 절대 경로를 클립보드에 넣는다.
"""

from __future__ import annotations

import html
from pathlib import Path

_e = html.escape

from exporters.report_ui import section_title  # noqa: E402

_TIER_BADGE = {1: ("샘플", "var(--danger)"), 2: ("의심", "var(--warn)"), 3: ("평상시", "var(--fg-4)")}

# 결과 폴더의 원본 수집물 — (판별 함수, 종류, 여는 도구/용도)
_ARTIFACT_KINDS = (
    (lambda n, p: n == "procmon.pml",            "ProcMon 원본(PML)", "Procmon64.exe 로 열기 — 전체 이벤트·스택 확인"),
    (lambda n, p: n == "procmon.csv",            "ProcMon CSV",       "리포트가 파싱한 원본. Timeline Explorer / Excel"),
    (lambda n, p: n.endswith((".pcap", ".pcapng")), "패킷 캡처",       "Wireshark 로 열기 — 아래 필터 식 사용"),
    (lambda n, p: n == "tls_keylog.txt",         "TLS 세션 키",       "Wireshark › Preferences › TLS › (Pre)-Master-Secret log"),
    (lambda n, p: n == "memory.raw",             "메모리 덤프",       "Volatility3 -f memory.raw windows.malfind 등"),
    (lambda n, p: n.endswith("_dynamic_report.json"), "JSON 리포트",   "표시 범위와 관계없이 전체 데이터 포함"),
    (lambda n, p: n.endswith("_dynamic_report.html"), "HTML 리포트",   "이 문서"),
    (lambda n, p: n.endswith(".log"),            "실행 로그",         "분석 파이프라인 콘솔 로그"),
    (lambda n, p: "regshot" in n or n.startswith("registry"), "레지스트리 스냅샷", "전/후 비교 원본"),
    (lambda n, p: "fakenet" in n,                "FakeNet-NG 로그",   "가짜 서비스가 받은 요청"),
)

_CSS = """
<style>
.ev-copy{background:var(--line);border:1px solid var(--line-2);color:var(--fg-3);
  font-size:.68rem;padding:1px 7px;cursor:pointer;white-space:nowrap}
.ev-copy:hover{color:var(--fg-2);border-color:var(--info)}
.ev-copy.ok{color:var(--ok);border-color:var(--ok)}
.ev-tbl td{vertical-align:top}
.ev-path{font-family:monospace;font-size:.76rem;word-break:break-all}
.ev-sub{color:var(--fg-3);font-size:.72rem;margin-top:2px}
.ev-hash{font-family:monospace;font-size:.68rem;color:var(--fg-3);word-break:break-all}
.ev-tag{display:inline-block;padding:0 6px;font-size:.66rem;font-weight:700;
  border:1px solid currentColor;margin-right:4px}
.ev-miss{color:var(--danger)}.ev-ok{color:var(--ok)}
.ev-h3{margin:1.4rem 0 .5rem;font-size:.95rem;color:var(--fg-2)}
</style>
<script>
function evCopy(b){
  var t=b.getAttribute('data-copy')||'';
  function done(){b.classList.add('ok');var o=b.textContent;b.textContent='복사됨';
    setTimeout(function(){b.classList.remove('ok');b.textContent=o;},1200);}
  function fb(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);
    a.select();try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(a);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,fb);}else{fb();}
}
</script>
"""


def _copy_btn(text: str, label: str = "경로 복사") -> str:
    return (f"<button type='button' class='ev-copy' data-copy=\"{_e(text, quote=True)}\" "
            f"onclick='evCopy(this)'>{_e(label)}</button>")


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


def _tier_tag(t: int) -> str:
    label, color = _TIER_BADGE.get(t, ("미판정", "var(--fg-4)"))
    return f"<span class='ev-tag' style='color:{color}'>{label}</span>"


def _link(rel: str, text: str) -> str:
    return f"<a href=\"{_e(rel, quote=True)}\" target='_blank' rel='noopener'>{_e(text)}</a>"


# 원래 확장자로 저장되면 더블클릭으로 실행되는 형식 — 내려받을 때 .bin 을 붙인다
_EXEC_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
             ".js", ".jse", ".wsf", ".hta", ".lnk", ".msi", ".jar", ".cpl", ".shc", ".pif")


def _bin_link(rel: str, name: str) -> str:
    """덤프 등 실행 가능 파일 링크 — download 속성으로 중립 확장자(.bin) 저장을 유도한다.

    릴레이(hunt_relay)로 서빙될 때는 서버도 attachment + .bin 으로 내보낸다.
    """
    dl = name + ".bin" if name.lower().endswith(_EXEC_EXT) else name
    return (f"<a href=\"{_e(rel, quote=True)}\" download=\"{_e(dl, quote=True)}\" rel='noopener'>"
            f"{_e(name)}</a>")


def _wireshark_str(value: str) -> str:
    """Wireshark 표시 필터 문자열 리터럴 — 역슬래시와 큰따옴표를 이스케이프한다."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


# ── ① 행위별 증적 ────────────────────────────────────────────────────────────

def _dropped_section(result, out_dir: Path) -> str:
    ev = getattr(result, "evidence", None) or {}
    rows = []
    smp = ev.get("sample") or {}
    if smp:
        rows.append(
            "<tr><td><span class='ev-tag' style='color:var(--info)'>샘플</span></td>"
            f"<td><div class='ev-path'>{_e(smp.get('path', ''))}</div>"
            f"<div class='ev-hash'>SHA-256 {_e(smp.get('sha256', ''))}</div></td>"
            f"<td>{_size(smp.get('size', 0))}</td><td>-</td>"
            f"<td>{_copy_btn(smp.get('path', ''))} {_copy_btn(smp.get('sha256', ''), '해시 복사')}</td></tr>"
        )
    for d in ev.get("dropped") or []:
        state = ("<span class='ev-ok'>존재</span>" if d.get("exists")
                 else "<span class='ev-miss'>없음</span>")
        saved = d.get("saved_as") or ""
        saved_html = (_link(saved, "보존 사본 열기") + " " + _copy_btn(str(out_dir / saved), "사본 경로")
                      if saved else f"<span class='ev-sub'>{_e(d.get('note', '') or '-')}</span>")
        sha = d.get("sha256") or ""
        rows.append(
            f"<tr><td>{_tier_tag(d.get('tier', 0))}</td>"
            f"<td><div class='ev-path'>{_e(d.get('path', ''))}</div>"
            + (f"<div class='ev-hash'>SHA-256 {_e(sha)}</div>" if sha else "")
            + (f"<div class='ev-sub'>기록: {_e(', '.join(d.get('writers') or []))}</div>"
               if d.get("writers") else "")
            + f"</td><td>{_size(d.get('size', 0)) if d.get('exists') else '-'}<br>{state}</td>"
            f"<td>{saved_html}</td>"
            f"<td>{_copy_btn(d.get('path', ''))}"
            + (f" {_copy_btn(sha, '해시 복사')}" if sha else "") + "</td></tr>"
        )
    if not rows:
        return ""
    return (
        "<h3 class='ev-h3'>드롭 파일 — 보존 사본과 해시</h3>"
        "<p class='ev-sub'>보존 사본은 <code>evidence/dropped/</code> 에 <code>.evd</code> 확장자로 저장됩니다 "
        "(실수 실행 방지). 정적 분석 시 확장자를 원래대로 되돌려 사용하세요.</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>관련성</th><th>원본 경로</th>"
        "<th>크기 / 상태</th><th>보존 사본</th><th>복사</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table></div>"
    )


def _registry_section(result) -> str:
    added = (getattr(result, "registry_diff", None) or {}).get("added", []) or []
    try:
        from analysis.registry_relevance import registry_key_interest
    except Exception:
        return ""
    rows = []
    for r in added:
        if isinstance(r, dict):
            key, name, data = str(r.get("path", "")), str(r.get("name", "")), str(r.get("data", ""))
        elif isinstance(r, (list, tuple)):
            key, name, data = (list(map(str, r)) + ["", "", ""])[:3]
        else:
            key, name, data = str(r), "", ""
        why = registry_key_interest(key)
        if not why:
            continue
        cmd = f'reg query "{key}"' + (f' /v "{name}"' if name else "")
        rows.append(
            f"<tr><td>{_e(why)}</td><td><div class='ev-path'>{_e(key)}</div>"
            f"<div class='ev-sub'>값: <code>{_e(name)}</code> → <code>{_e(data[:300])}</code></div></td>"
            f"<td>{_copy_btn(cmd, '확인 명령 복사')} {_copy_btn(key, '키 복사')}</td></tr>"
        )
    if not rows:
        return ""
    return (
        "<h3 class='ev-h3'>지속성 레지스트리 — 현재 값 확인</h3>"
        "<p class='ev-sub'>복사한 <code>reg query</code> 를 관리자 셸에서 실행하거나, "
        "키를 복사해 regedit 주소창에 붙여 넣으면 실제 값이 남아 있는지 바로 확인됩니다.</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>사유</th><th>키 / 값</th>"
        "<th>확인</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _dump_section(result, out_dir: Path) -> str:
    dumps = out_dir / "dumps"
    if not dumps.is_dir():
        return ""
    lineage = set(getattr(result, "lineage_pids", None) or ())
    names = {}
    for p in (getattr(result, "process_diff", None) or {}).get("new_processes", []) or []:
        names[getattr(p, "pid", None)] = getattr(p, "name", "")
    for r in getattr(result, "pe_sieve_results", None) or []:
        names.setdefault(getattr(r, "pid", None), getattr(r, "name", "") or "")
    hh = getattr(result, "hh_result", None)
    for r in (getattr(hh, "suspicious_processes", None) or []) if hh else []:
        names.setdefault(getattr(r, "pid", None), getattr(r, "name", "") or "")

    rows = []
    for d in sorted(dumps.iterdir()):
        if not d.is_dir():
            continue
        try:
            pid = int(d.name.rsplit("_", 1)[-1])
        except ValueError:
            pid = None
        files = [f for f in d.rglob("*") if f.is_file()]
        if not files:
            continue
        bins = [f for f in files if f.suffix.lower() in (".exe", ".dll", ".shc", ".bin", ".sys")]
        rel = d.relative_to(out_dir).as_posix()
        tag = _tier_tag(1) if pid in lineage else _tier_tag(2)
        listing = "".join(
            f"<div class='ev-path'>{_bin_link(f.relative_to(out_dir).as_posix(), f.name)} "
            f"<span class='ev-sub'>{_size(f.stat().st_size)}</span></div>"
            for f in sorted(bins, key=lambda x: -x.stat().st_size)[:6]
        )
        rows.append((pid not in lineage, pid or 0,
            f"<tr><td>{tag}</td><td>{_e(names.get(pid, '') or '?')} "
            f"<span class='ev-sub'>PID {pid if pid is not None else '?'}</span></td>"
            f"<td>{listing or '<span class=ev-sub>보고서(JSON)만 있음</span>'}"
            + (f"<div class='ev-sub'>… 외 {len(bins) - 6}개</div>" if len(bins) > 6 else "")
            + f"</td><td>{_link(rel + '/', '폴더 열기')} {_copy_btn(str(d))}</td></tr>"))
    if not rows:
        return ""
    rows.sort(key=lambda r: (r[0], r[1]))
    return (
        "<h3 class='ev-h3'>메모리 덤프 — pe-sieve / hollows-hunter</h3>"
        "<p class='ev-sub'>덤프된 PE(<code>.exe/.dll</code>)는 언패킹된 페이로드일 수 있습니다 — "
        "PE-bear·Ghidra·dnSpy 로 열어보세요. <code>.shc</code> 는 쉘코드 조각입니다.</p>"
        "<p class='ev-sub' style='color:var(--warn)'>실제 악성 코드입니다. 링크는 <code>.bin</code> 을 덧붙여 "
        "내려받도록 되어 있으니 실행하지 말고 분석 VM 안에서만 다루세요.</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>관련성</th><th>프로세스</th>"
        "<th>덤프 파일</th><th>위치</th></tr></thead><tbody>"
        + "".join(r[2] for r in rows) + "</tbody></table></div>"
    )


def _network_section(result, out_dir: Path) -> str:
    pcap = getattr(result, "pcap_result", None)
    if pcap is None:
        return ""
    pcaps = [f for f in out_dir.glob("*.pcap*") if f.is_file()]
    pcap_cell = (_link(pcaps[0].name, pcaps[0].name) + " " + _copy_btn(str(pcaps[0]))) if pcaps else "-"
    ip2dom = getattr(pcap, "ip_to_domain", {}) or {}
    rows, seen = [], set()

    for q in getattr(pcap, "dns_queries", None) or []:
        name = (getattr(q, "name", "") or "").strip(".")
        tier = getattr(q, "relevance_tier", 2)
        if not name or "." not in name or tier > 2 or name in seen:
            continue
        seen.add(name)
        ips = getattr(q, "response_ips", None) or []
        flt = f"dns.qry.name == {_wireshark_str(name)}"
        rows.append((tier, f"<tr><td>{_tier_tag(tier)}</td><td>DNS 질의</td>"
                     f"<td><div class='ev-path'>{_e(name)}</div><div class='ev-sub'>"
                     f"{'응답 ' + _e(', '.join(ips[:4])) if ips else '<span class=ev-miss>응답 없음</span>'}</div></td>"
                     f"<td><code>{_e(flt)}</code> {_copy_btn(flt, '필터 복사')}</td></tr>"))

    for c in getattr(pcap, "connections", None) or []:
        tier = getattr(c, "relevance_tier", 2)
        ip, port = getattr(c, "dst_ip", ""), getattr(c, "dst_port", 0)
        if tier > 2 or not ip or port in (137, 138, 1900, 5353, 5355) or (ip, port) in seen:
            continue
        if getattr(c, "src_port", 0) in (53, 80, 443):      # 응답 방향 행
            continue
        try:
            import ipaddress
            if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_multicast:
                continue
        except ValueError:
            continue
        seen.add((ip, port))
        proto = (getattr(c, "proto", "tcp") or "tcp").lower()
        flt = f"ip.addr == {ip} && {proto}.port == {port}"
        doms = ip2dom.get(ip) or []
        dom = doms[0] if isinstance(doms, list) and doms else (doms if isinstance(doms, str) else "")
        rows.append((tier, f"<tr><td>{_tier_tag(tier)}</td><td>{_e(proto.upper())} 연결</td>"
                     f"<td><div class='ev-path'>{_e(ip)}:{port}</div>"
                     + (f"<div class='ev-sub'>{_e(dom)}</div>" if dom else "")
                     + f"</td><td><code>{_e(flt)}</code> {_copy_btn(flt, '필터 복사')}</td></tr>"))
    if not rows:
        return ""
    rows.sort(key=lambda r: r[0])
    more = f"<p class='ev-sub'>… 외 {len(rows) - 40}건은 네트워크 탭 참조</p>" if len(rows) > 40 else ""
    return (
        "<h3 class='ev-h3'>네트워크 — Wireshark 에서 직접 확인</h3>"
        f"<p class='ev-sub'>캡처 파일: {pcap_cell} — Wireshark 로 연 뒤 아래 표시 필터를 붙여 넣으세요.</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>관련성</th><th>유형</th>"
        "<th>대상</th><th>Wireshark 표시 필터</th></tr></thead><tbody>"
        + "".join(r[1] for r in rows[:40]) + "</tbody></table></div>" + more
    )


def _process_section(result, out_dir: Path) -> str:
    lineage = set(getattr(result, "lineage_pids", None) or ())
    procs = (getattr(result, "process_diff", None) or {}).get("new_processes", []) or []
    procs = [p for p in procs if getattr(p, "pid", None) in lineage]
    if not procs:
        return ""
    pml = out_dir / "procmon.pml"
    rows = []
    for p in procs:
        pid = getattr(p, "pid", "")
        cmd = getattr(p, "cmdline", "") or ""
        cmd = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        exe = getattr(p, "exe", "") or ""
        rows.append(
            f"<tr><td>{_e(getattr(p, 'name', '') or '?')} <span class='ev-sub'>PID {pid}</span></td>"
            f"<td><div class='ev-path'>{_e(exe)}</div><div class='ev-sub'>{_e(cmd[:400])}</div></td>"
            f"<td>{_copy_btn(str(pid), 'PID 복사')} {_copy_btn(cmd, '명령줄 복사')}"
            + (f" {_copy_btn(exe)}" if exe else "") + "</td></tr>"
        )
    hint = (f"ProcMon 원본: {_link(pml.name, pml.name)} {_copy_btn(str(pml))} — " if pml.is_file() else "")
    return (
        "<h3 class='ev-h3'>샘플 프로세스 — ProcMon 에서 직접 확인</h3>"
        f"<p class='ev-sub'>{hint}Procmon › Filter(Ctrl+L) › <code>PID is &lt;값&gt; Include</code> 로 "
        "해당 프로세스의 파일·레지스트리·네트워크 이벤트 전체를 볼 수 있습니다.</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>프로세스</th><th>경로 / 명령줄</th>"
        "<th>복사</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


# ── ② 수집 원본 ──────────────────────────────────────────────────────────────

def _artifact_section(out_dir: Path) -> str:
    rows = []
    try:
        entries = sorted(out_dir.iterdir(), key=lambda p: (p.is_dir(), p.name.lower()))
    except OSError:
        return ""
    for f in entries:
        name = f.name.lower()
        if f.is_dir():
            try:
                cnt = sum(1 for x in f.rglob("*") if x.is_file())
            except OSError:
                cnt = 0
            if not cnt:
                continue
            kind = {"dumps": "메모리 덤프 폴더", "evidence": "보존 증거 폴더"}.get(name, "폴더")
            rows.append(f"<tr><td>{_e(kind)}</td><td class='ev-path'>{_link(f.name + '/', f.name + '/')}</td>"
                        f"<td>{cnt:,}개 파일</td><td>-</td><td>{_copy_btn(str(f))}</td></tr>")
            continue
        kind, use = "기타", ""
        for pred, k, u in _ARTIFACT_KINDS:
            try:
                if pred(name, f):
                    kind, use = k, u
                    break
            except Exception:
                continue
        try:
            size = _size(f.stat().st_size)
        except OSError:
            size = "-"
        rows.append(f"<tr><td>{_e(kind)}</td><td class='ev-path'>{_link(f.name, f.name)}</td>"
                    f"<td>{size}</td><td class='ev-sub'>{_e(use)}</td><td>{_copy_btn(str(f))}</td></tr>")
    if not rows:
        return ""
    return (
        "<h3 class='ev-h3'>수집 원본 파일</h3>"
        f"<p class='ev-sub'>결과 폴더: <code>{_e(str(out_dir))}</code> {_copy_btn(str(out_dir), '폴더 경로 복사')}</p>"
        "<div class='table-wrap'><table class='ev-tbl'><thead><tr><th>종류</th><th>파일</th><th>크기</th>"
        "<th>용도</th><th>복사</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def evidence_html(result, output_path: str) -> str:
    """증거 탭 본문. 어떤 섹션이 실패해도 나머지는 그대로 나온다."""
    out_dir = Path(output_path).resolve().parent
    parts = [_CSS,
             section_title("evidence", "증거", "판정을 뒷받침하는 원본과 직접 확인하는 방법"),
             "<p class='ev-sub' style='margin-bottom:.6rem'>리포트의 각 판정을 뒷받침하는 원본 파일과 "
             "확인 방법입니다. 이 VM 안에서 링크를 열거나 경로를 복사해 분석 도구에 붙여 넣으세요.</p>"]
    for fn, args in ((_dropped_section, (result, out_dir)), (_registry_section, (result,)),
                     (_dump_section, (result, out_dir)), (_network_section, (result, out_dir)),
                     (_process_section, (result, out_dir)), (_artifact_section, (out_dir,))):
        try:
            parts.append(fn(*args))
        except Exception as exc:
            parts.append(f"<p class='ev-sub'>({_e(fn.__name__)} 생성 실패: {_e(type(exc).__name__)})</p>")
    if len([p for p in parts[3:] if p]) == 0:
        parts.append("<p class='ev-sub'>표시할 증적이 없습니다.</p>")
    return "".join(parts)
