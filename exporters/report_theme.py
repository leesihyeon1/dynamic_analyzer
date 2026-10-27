"""분석 보고서의 탐색 구조, 요약 헤더와 공통 시각 스타일."""
from html import escape

REPORT_CSS = """
:root{color-scheme:dark;--bg:#0c1422;--surface:#142136;--line:#2a3b54;--text:#e9eff8;--muted:#acbbd0;--accent:#45d6bf}
html{font-size:16px;scroll-behavior:smooth}html.large-text{font-size:18px}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI','Malgun Gothic',sans-serif;line-height:1.75}
.container{max-width:1640px;margin:0 auto 0 244px;padding:42px 48px 72px}
a{color:#77c4ff;text-underline-offset:4px}button,input{font:inherit}
button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
.report-header{margin-bottom:28px}.report-topline{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:22px}
.eyebrow{font-size:.75rem;letter-spacing:.17em;color:var(--accent);font-weight:700}
.report-actions{display:flex;gap:8px}.report-actions button{background:#1c2c43;border:1px solid var(--line);border-radius:8px;color:var(--muted);font-size:.8rem;padding:7px 13px;cursor:pointer}
h1{font-size:clamp(1.8rem,3vw,2.6rem);letter-spacing:-.035em;line-height:1.25;color:var(--text);margin:0 0 10px;overflow-wrap:anywhere}
.report-path{color:var(--muted);font-size:.85rem;overflow-wrap:anywhere;margin-bottom:22px}
.report-meta{display:flex;gap:12px 28px;flex-wrap:wrap;margin-bottom:24px;color:var(--muted);font-size:.8rem}
.report-meta strong{font-weight:500;color:var(--text);margin-left:8px}
.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:24px 0 18px}
.metric{border:1px solid var(--line);border-radius:14px;background:var(--surface);padding:20px 22px}
.metric-label{font-size:.8rem;color:var(--muted)}.metric-value{font-size:2.1rem;font-weight:650;line-height:1.3;margin:8px 0;color:var(--text);font-variant-numeric:tabular-nums;letter-spacing:-.04em}
.metric-note{font-size:.75rem;color:var(--muted)}
.health-strip{display:flex;align-items:flex-start;gap:12px;background:#172c2b;border:1px solid #31534b;border-radius:10px;padding:14px 18px;color:#a2e4d5;font-size:.85rem}
.health-strip.warning{background:#29271e;border-color:#514733;color:#efd9a5}.health-strip strong{white-space:nowrap}
.tools-disclosure{margin:18px 0 24px;border-bottom:1px solid var(--line);padding-bottom:18px}
.tools-disclosure summary{cursor:pointer;color:var(--muted);font-size:.85rem}.tools-disclosure .tool-list{display:flex;flex-wrap:wrap;gap:8px;padding-top:14px}
.tabs{position:fixed;left:0;top:0;bottom:0;width:244px;padding:35px 18px 22px;margin:0;display:flex;flex-direction:column;gap:5px;overflow-y:auto;overflow-x:hidden;background:#101c2e;border:0;border-right:1px solid var(--line);z-index:20}
.tabs:before{content:'DA / ANALYZER';display:block;font-size:1.15rem;font-weight:750;letter-spacing:.04em;color:var(--accent);padding:0 16px 32px}
.tabs:after{content:'DYNAMIC ANALYSIS REPORT';font-size:.61rem;letter-spacing:.13em;color:#8d9eb8;margin-top:auto;padding:28px 16px 0}
.tab-btn{border:0;border-radius:8px;display:flex;align-items:center;text-align:left;padding:13px 16px;color:var(--muted);font-size:.9rem;gap:8px;transition:background .15s,color .15s}
.tab-btn:hover{background:#1c2e45;color:var(--text)}.tab-btn.active{background:#1b3a38;color:#78e4cf;border:0;font-weight:650}
.tab-btn .tbadge{margin-left:auto;border-radius:6px;font-size:.7rem}
.tab-panel{min-width:0}.tab-panel>h2:first-child{margin-top:28px}
h2{font-size:1.25rem;color:var(--text);border:0;letter-spacing:-.02em;margin:32px 0 18px;padding:0}
h3{font-size:1rem;line-height:1.6;margin:22px 0 12px;color:#b7c9ed}
.grid2{grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.card,.hunt-box,.hunt-card{background:var(--surface);border:1px solid var(--line);border-radius:12px}.card{padding:22px}
table{font-size:.875rem;line-height:1.7;border-collapse:separate;border-spacing:0;width:100%}
th{background:#1b2b42;color:#bac8db;padding:13px 16px;font-size:.78rem;font-weight:650;border-bottom:1px solid var(--line);white-space:normal}
td{padding:12px 16px;color:var(--text);border-bottom:1px solid #26364c;word-break:normal;overflow-wrap:anywhere}
tbody tr:nth-child(even)>td{background:rgba(140,170,210,.035)}tr:hover td{background:#1b2e46}
.kv td:first-child{color:var(--muted);width:145px;white-space:normal}.kv td{padding:11px 8px}.kv tr:last-child td{border-bottom:0}
.mono,code{font-family:'Cascadia Code','Consolas',monospace;font-size:.84rem;line-height:1.7}code{color:#d5e2f5;background:#1b2b42;padding:3px 6px}
.badge{padding:4px 9px;font-size:.75rem;font-weight:500;border-radius:6px}.alert{border-radius:10px;padding:16px 20px;font-size:.9rem;line-height:1.8;margin:18px 0}
.srch-wrap{margin:16px 0 12px}.srch-input,.hunt-input{background:#101c2e;border:1px solid #3b506d;font-size:.9rem;padding:10px 14px;border-radius:8px;color:var(--text)}
.srch-input{width:min(100%,460px)}.srch-input::placeholder,.hunt-input::placeholder{color:#94a6c0}.srch-input:focus,.hunt-input:focus{border-color:var(--accent)}
.pg-wrap{padding:16px 0;gap:12px}.pg-info{font-size:.8rem;color:var(--muted)}.pg-btn{padding:6px 11px;border-radius:6px;background:#1b2b42;min-width:34px}.pg-active{background:#20564e!important;border-color:#45d6bf!important;color:#baffee!important}
.hunt-btn{background:#247668;padding:10px 18px}.hunt-btn:hover{background:#309783}.hunt-kv{font-size:.875rem}.hunt-none,.hunt-hint{color:var(--muted)}
.ptree{background:var(--surface);font-size:.88rem;padding:22px}.pt-row{padding:6px}.pt-meta,.pt-pid,.pt-name-existing{color:#9eafc8;font-size:.8rem}.pt-legend{font-size:.8rem}
.beh-list li{font-size:.82rem;padding:6px 0;line-height:1.7}.beh-panel{padding:16px}.beh-tab{padding:6px 12px;font-size:.8rem}.beh-empty{color:var(--muted)}
.tab-panel [style*='font-size:.7'],.tab-panel [style*='font-size:.6']{font-size:.84rem!important}
.tab-panel [style*='color:#484f58'],.tab-panel [style*='color:#6e7681']{color:#a6b5cb!important}
.tab-panel [style*='word-break:break-all']{word-break:normal!important;overflow-wrap:anywhere}
pre{line-height:1.8!important;font-size:.86rem!important;tab-size:4}details>summary{padding:8px 0}
@media(min-width:1850px){.container{margin-left:calc(244px + (100vw - 1850px)/2)}}
@media(max-width:1100px){.container{margin:0;padding:24px}.tabs{position:sticky;top:0;width:auto;bottom:auto;flex-direction:row;padding:10px;gap:4px;margin:0 -24px 22px;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto}.tabs:before,.tabs:after{display:none}.tab-btn{padding:10px 14px}.tab-btn .tbadge{margin-left:4px}}
@media(max-width:700px){.container{padding:20px}.tabs{margin:0 -20px 18px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.metric{padding:16px}.grid2{grid-template-columns:1fr}.report-topline{align-items:flex-start;flex-direction:column}.health-strip{flex-direction:column;gap:4px}.report-meta{gap:6px 16px}td,th{padding:10px 8px}.kv td:first-child{width:120px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
@media print{*{background:transparent!important;color:#111!important;box-shadow:none!important}.tabs,.report-actions,.pg-wrap,.srch-wrap{display:none!important}.container{margin:0;padding:0;max-width:none}.tab-panel:not(.active){display:none!important}.metric,.card{border:1px solid #aaa}h2{break-after:avoid}.metric-grid{grid-template-columns:repeat(4,1fr)}}
"""


def report_header(*, sample_name, sample_path, generated, timeout, duration, techniques,
                  events, connections, ips, tools_html, needs_review=False, indicator=""):
    """사용자 데이터는 이스케이프하고 생성기가 만든 도구 배지만 HTML로 삽입한다."""
    e = lambda value: escape(str(value), quote=True)
    metrics = [("ATT&CK 후보", techniques, "근거별 검토 필요"), ("ProcMon 이벤트", events, "수집·파싱된 이벤트"),
               ("네트워크 연결", connections, "캡처에서 관찰"), ("관찰 IP", ips, "샘플 귀속 확인 필요")]
    cards = "".join(f'<div class="metric"><div class="metric-label">{e(label)}</div><div class="metric-value">{int(count):,}</div><div class="metric-note">{e(note)}</div></div>' for label, count, note in metrics)
    minutes, seconds = divmod(int(max(0, duration)), 60)
    health_title = "수집 확인 필요" if needs_review else "결과 검토"
    health_text = "수집 오류 또는 ProcMon 이벤트 누락이 있습니다. 아래 경고와 원본 로그를 먼저 확인하세요." if needs_review else "후보 수와 관찰 IP는 수집 범위·프로세스 관계·원문 근거와 함께 해석하세요."
    return f'''<header class="report-header">
<div class="report-topline"><span class="eyebrow">DYNAMIC / ANALYSIS REPORT</span><div class="report-actions">
<button type="button" aria-pressed="false" onclick="const large=document.documentElement.classList.toggle('large-text');this.setAttribute('aria-pressed',String(large));this.textContent=large?'기본 글자':'글자 크게'">글자 크게</button>
<button type="button" onclick="window.print()">현재 화면 인쇄</button></div></div>
<h1>{e(sample_name)}</h1><p class="report-path">{e(sample_path)}</p>
<div class="report-meta"><span>생성<strong>{e(generated)}</strong></span><span>모니터링<strong>{e(timeout)}초</strong></span><span>전체 소요<strong>{minutes}분 {seconds}초</strong></span><span>규칙 기반 지표<strong>{e(indicator)}</strong></span></div>
<div class="metric-grid">{cards}</div>
<div class="health-strip{' warning' if needs_review else ''}"><strong>{health_title}</strong><span>{health_text}</span></div>
<details class="tools-disclosure"><summary>수집 도구 상태 보기</summary><div class="tool-list">{tools_html}</div></details>
</header>'''
