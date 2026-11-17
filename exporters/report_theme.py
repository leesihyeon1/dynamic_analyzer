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
@media(max-width:700px){.container{padding:20px}.tabs{margin:0 -20px 18px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.metric{padding:16px}.grid2{grid-template-columns:1fr}.report-topline{align-items:flex-start;flex-direction:column}.report-meta{gap:6px 16px}td,th{padding:10px 8px}.kv td:first-child{width:120px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
@media print{*{background:transparent!important;color:#111!important;box-shadow:none!important}.tabs,.report-actions,.pg-wrap,.srch-wrap{display:none!important}.container{margin:0;padding:0;max-width:none}.tab-panel:not(.active){display:none!important}.metric,.card{border:1px solid #aaa}h2{break-after:avoid}.metric-grid{grid-template-columns:repeat(4,1fr)}}
"""


COMPACT_CSS = """
.report-menu-toggle{position:fixed;top:8px;left:12px;z-index:50;border:1px solid var(--line);background:#182b3b;color:var(--text);padding:5px 13px;cursor:pointer}
.tabs{padding-top:54px}.tabs:before,.tabs:after{display:none}.tabs .tab-btn{padding:8px 15px}
body.menu-hidden .tabs{display:none}body.menu-hidden .container{margin-left:auto;margin-right:auto}
.container{padding-top:48px}.metric-grid{gap:0}
.report-header .metric-grid{overflow:hidden;background:transparent;border:0;border-top:1px solid #304454;border-bottom:1px solid #304454;gap:0}
.report-header .metric{min-width:0;padding:14px clamp(12px,2vw,26px);border:0;border-radius:0;background:none;box-shadow:none}
.report-header .metric+.metric{border-left:1px solid #304454}
.report-header .metric-label{font-size:.82rem;color:#b3c7d1}
.report-header .metric-value{font-size:clamp(1.3rem,2vw,1.85rem);margin:3px 0 0;line-height:1.25}
@media(max-width:700px){.report-header .metric:nth-child(3){border-left:0}.report-header .metric:nth-child(n+3){border-top:1px solid #304454}}.card{border-color:transparent}
.report-table-scroll{max-width:100%;overflow:auto;max-height:32rem;scrollbar-color:#547086 #142136}
.report-table-scroll>table{margin:0}.report-table-scroll td,.report-table-scroll th{padding:6px 10px}
.report-table-scroll td.mono,.report-table-scroll td code{white-space:nowrap;word-break:normal!important;overflow-wrap:normal!important}
#tbl-process-all{table-layout:fixed;min-width:990px;width:100%}
#tbl-process-all th{position:sticky;top:0;z-index:1;background:#172438;text-align:left}
#tbl-process-all th:nth-child(1){width:36px}
#tbl-process-all th:nth-child(2){width:78px}
#tbl-process-all th:nth-child(3){width:205px}
#tbl-process-all th:nth-child(4){width:90px}
#tbl-process-all th:nth-child(7){width:120px}
#tbl-process-all tr[id^='proc-record-']>td{vertical-align:top}
#tbl-process-all tr[id^='proc-record-']>td:nth-child(2){white-space:nowrap}
#tbl-process-all tr[id^='proc-record-']>td:nth-child(5),#tbl-process-all tr[id^='proc-record-']>td:nth-child(6){white-space:normal;overflow-wrap:anywhere!important;word-break:normal!important}
#tbl-process-all tr[id^='proc-record-']>td:nth-child(7){white-space:normal!important}
.process-record-scroll{max-height:36rem}
.tab-panel pre{max-height:22rem;overflow:auto;white-space:pre!important}
@media(max-width:1100px){.tabs{padding-top:8px;top:38px}.report-menu-toggle{top:4px}}
@media print{.report-menu-toggle{display:none}.report-table-scroll,.tab-panel pre{overflow:visible;max-height:none}}
"""
COMPACT_JS = """
document.addEventListener('DOMContentLoaded', function(){
 const nav=document.querySelector('nav.tabs'); if(!nav)return;
 nav.id='report-navigation';
 const toggle=document.createElement('button');
 toggle.className='report-menu-toggle';toggle.setAttribute('aria-controls',nav.id);
 function show(open){document.body.classList.toggle('menu-hidden',!open);
 toggle.textContent='=';toggle.title=open?'메뉴 접기':'메뉴 열기';toggle.setAttribute('aria-label',toggle.title);toggle.setAttribute('aria-expanded',String(open));}
 toggle.onclick=()=>show(document.body.classList.contains('menu-hidden'));
 document.body.prepend(toggle);show(false);
 window.addEventListener('load',function(){
 document.querySelectorAll('.tab-panel table[id]').forEach(table=>{
 if(table.parentElement.classList.contains('report-table-scroll'))return;
 const box=document.createElement('div');box.className='report-table-scroll';
 box.tabIndex=0;table.before(box);box.append(table);});});
});
"""
REPORT_CSS += COMPACT_CSS


def report_header(*, sample_name, sample_path, generated, timeout, duration, techniques,
                  events, connections, ips, indicator=""):
    """사용자 데이터는 이스케이프하고 생성기가 만든 도구 배지만 HTML로 삽입한다."""
    e = lambda value: escape(str(value), quote=True)
    metrics = [("ATT&CK 후보", techniques), ("ProcMon 이벤트", events),
               ("네트워크 연결", connections), ("IOC IP 주소", ips)]
    cards = "".join(f'<div class="metric"><div class="metric-label">{e(label)}</div><div class="metric-value">{int(count):,}</div></div>' for label, count in metrics)
    minutes, seconds = divmod(int(max(0, duration)), 60)
    return f'''<header class="report-header">
<div class="report-topline"><span class="eyebrow">DYNAMIC / ANALYSIS REPORT</span><div class="report-actions">
<button type="button" aria-pressed="false" onclick="const large=document.documentElement.classList.toggle('large-text');this.setAttribute('aria-pressed',String(large));this.textContent=large?'기본 글자':'글자 크게'">글자 크게</button>
<button type="button" onclick="window.print()">현재 화면 인쇄</button></div></div>
<h1>{e(sample_name)}</h1><p class="report-path">{e(sample_path)}</p>
<div class="report-meta"><span>생성<strong>{e(generated)}</strong></span><span>모니터링<strong>{e(timeout)}초</strong></span><span>전체 소요<strong>{minutes}분 {seconds}초</strong></span><span>규칙 기반 지표<strong>{e(indicator)}</strong></span></div>
<div class="metric-grid">{cards}</div>
</header>'''
