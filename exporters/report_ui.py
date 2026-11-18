"""
report_ui.py — 분석 보고서의 디자인 시스템 (토큰 · 레이아웃 · 컴포넌트 · 아이콘)

색·간격·모서리는 여기 토큰 하나로 정한다. 보고서 곳곳의 인라인 스타일도 hex 대신
var(--…) 를 쓰므로, 팔레트를 바꿀 때 이 파일만 고치면 된다.

    UI_CSS       — 문서 맨 끝에 넣는다(본문 중간에 들어가는 구간별 CSS 보다 뒤여야 이긴다)
    UI_JS        — 복사 단추 · 상단 바 그림자
    icon(name)   — 24px 선 아이콘 (외부 요청 없이 오프라인에서 표시)
    topbar(...)  — 상단 고정 바: 샘플 · 판정 · 점수 · 표시 범위 · 동작

화면 원칙
  * 섹션은 카드 하나 — 머리(아이콘·제목) 아래 하위 제목과 표가 이어진다.
  * 판정은 맨 위 히어로 카드에서 한눈에 — 점수 도넛 · 판정 · 패밀리 · 파일 정보 · 핵심 수치.
  * 의미 색은 다섯 가지뿐 — 위험(danger) · 주의(orange) · 경고(warn) · 정상(ok) · 정보(info).
"""
from __future__ import annotations

from html import escape as _e

# 24×24 선 아이콘 (Lucide 계열 모양을 단순화)
_ICONS: dict[str, str] = {
    "overview": "M3 3h7v9H3z M14 3h7v5h-7z M14 12h7v9h-7z M3 16h7v5H3z",
    "process":  "M9 9h6v6H9z M4 4h16v16H4z M9 1v3 M15 1v3 M9 20v3 M15 20v3 M20 9h3 M20 14h3 M1 9h3 M1 14h3",
    "file":     "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h5",
    "registry": "M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3z M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6"
                " M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
    "network":  "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M2 12h20 M12 2a15 15 0 0 1 0 20 M12 2a15 15 0 0 0 0 20",
    "memory":   "M3 7h18v10H3z M7 7v10 M12 7v10 M17 7v10 M6 17v3 M18 17v3 M6 4v3 M18 4v3",
    "ioc":      "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M12 6a6 6 0 1 0 0 12a6 6 0 1 0 0-12z"
                " M12 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4z",
    "evidence": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4",
    "hunt":     "M11 3a8 8 0 1 0 0 16a8 8 0 1 0 0-16z M21 21l-4.3-4.3",
    "graph":    "M18 2a3 3 0 1 0 0 6a3 3 0 1 0 0-6z M6 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z"
                " M18 16a3 3 0 1 0 0 6a3 3 0 1 0 0-6z M8.6 13.5l6.8 4 M15.4 6.5l-6.8 4",
    "ai":       "M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z M19 15l.8 1.9 1.9.8-1.9.8-.8 1.9-.8-1.9"
                "-1.9-.8 1.9-.8z",
    "attack":   "M3 3h18v18H3z M3 9h18 M3 15h18 M9 3v18 M15 3v18",
    "menu":     "M3 6h18 M3 12h18 M3 18h18",
    "print":    "M6 9V2h12v7 M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2 M6 14h12v8H6z",
    "text":     "M4 7V4h16v3 M9 20h6 M12 4v16",
    "copy":     "M9 9h11v11H9z M5 15H4V4h11v1",
    "alert":    "M12 3l10 18H2z M12 10v4 M12 17.5v.5",
    "check":    "M5 12l5 5 9-10",
    "info":     "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M12 11v6 M12 7.5v.5",
}


def icon(name: str, cls: str = "ic") -> str:
    path = _ICONS.get(name, "")
    return (f"<svg class='{cls}' viewBox='0 0 24 24' aria-hidden='true' focusable='false'>"
            f"<path d='{path}'/></svg>")


def section_title(name: str, title: str, sub: str = "") -> str:
    """카드 머리 — 아이콘 칩 + 제목 (+ 한 줄 설명)."""
    sub_html = f"<small class='sec-sub'>{_e(sub)}</small>" if sub else ""
    return (f"<h2 class='sec-h'><span class='sec-ic'>{icon(name)}</span>"
            f"<span class='sec-t'>{_e(title)}{sub_html}</span></h2>")


def topbar(sample_name: str, verdict: dict | None = None, controls: str = "") -> str:
    """상단 고정 바. verdict 가 없으면(이전 보고서 재가공 등) 샘플 이름만 보인다."""
    v = verdict or {}
    level = v.get("level", "")
    color = {"mal": "var(--danger)", "sus": "var(--warn)", "ok": "var(--ok)"}.get(level, "var(--fg-3)")
    pill = (f"<span class='tb-verdict' style='--vc:{color}'>{_e(v.get('label', ''))}</span>"
            f"<span class='tb-score'>{int(v.get('score', 0))}<small>/100</small></span>") if v else ""
    return (
        "<header class='topbar' role='banner'>"
        f"<div class='tb-title'><span class='tb-name' title='{_e(sample_name, quote=True)}'>{_e(sample_name)}</span>"
        f"{pill}</div><div class='tb-spacer'></div>{controls}"
        "<div class='tb-actions'>"
        "<button type='button' class='btn btn-icon' title='글자 크게' aria-pressed='false' "
        "onclick=\"const on=document.documentElement.classList.toggle('large-text');"
        "this.setAttribute('aria-pressed',String(on));this.title=on?'기본 글자':'글자 크게'\">"
        f"{icon('text')}</button>"
        f"<button type='button' class='btn btn-icon' title='인쇄' onclick='window.print()'>{icon('print')}</button>"
        "</div></header>"
    )


def nav_brand() -> str:
    return ("<div class='nav-brand'><span class='logo'>DA</span>"
            "<span><b>Dynamic Analyzer</b><small>MALWARE ANALYSIS REPORT</small></span></div>")


UI_CSS = """<style id='report-ui'>
/* ══ 토큰 ═══════════════════════════════════════════════════════════════ */
:root{
  color-scheme:dark;
  --bg:#0a111d;--bg-inset:#070d18;--surface:#0f1828;--surface-2:#132036;--surface-3:#1a2842;
  --line:#1d2a41;--line-2:#2a3a56;
  --fg-1:#e8eef8;--fg-2:#c3cee0;--fg-3:#8fa1bc;--fg-4:#67788f;
  --text:var(--fg-1);--muted:var(--fg-3);
  --accent:#3dd6c0;--accent-strong:#14a594;--accent-bg:rgba(61,214,192,.12);
  --danger:#f87171;--orange:#fb923c;--warn:#fbbf24;--ok:#34d399;--info:#60a5fa;--purple:#b392f0;
  --danger-bg:rgba(248,113,113,.13);--orange-bg:rgba(251,146,60,.13);--warn-bg:rgba(251,191,36,.12);
  --ok-bg:rgba(52,211,153,.12);--info-bg:rgba(96,165,250,.13);--purple-bg:rgba(179,146,240,.14);
  --radius:14px;--radius-sm:9px;--radius-xs:6px;
  --shadow:0 1px 0 rgba(255,255,255,.035) inset,0 12px 32px -18px rgba(0,0,0,.7);
  --mono:'Cascadia Mono','Cascadia Code',Consolas,'D2Coding',monospace;
  --sans:'Segoe UI Variable Text','Segoe UI','Malgun Gothic',system-ui,sans-serif;
  --nav-w:236px;--top-h:60px;
}
*{scrollbar-width:thin;scrollbar-color:var(--line-2) transparent}
body{background:var(--bg)!important;color:var(--fg-1);font-family:var(--sans);-webkit-font-smoothing:antialiased;line-height:1.65}
a{color:var(--info)}
code,.mono{font-family:var(--mono)}
code{background:var(--bg-inset);border:1px solid var(--line);border-radius:var(--radius-xs);padding:1px 6px;color:var(--fg-2)}
.ic{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}

/* ══ 뼈대: 왼쪽 메뉴 · 본문 ═════════════════════════════════════════════ */
.container{max-width:1480px!important;margin:0 0 0 var(--nav-w)!important;padding:0 32px 72px!important}
@media(min-width:1800px){.container{margin-left:calc(var(--nav-w) + (100vw - var(--nav-w) - 1480px)/2)!important}}
body.menu-hidden .container{margin:0 auto!important}
.tabs{position:fixed!important;inset:0 auto 0 0;width:var(--nav-w)!important;margin:0!important;padding:18px 12px!important;
  background:var(--bg-inset)!important;border:0!important;border-right:1px solid var(--line)!important;
  display:flex!important;flex-direction:column;gap:2px!important;overflow-y:auto;z-index:30}
.tabs:before,.tabs:after{display:none!important}
body.menu-hidden .tabs{display:none!important}
.nav-brand{display:flex;align-items:center;gap:11px;padding:4px 10px 20px}
.nav-brand .logo{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;flex:none;
  background:linear-gradient(135deg,#3dd6c0,#3b82f6);color:#04121c;font:800 .78rem/1 var(--sans);letter-spacing:.02em}
.nav-brand b{display:block;font-size:.92rem;color:var(--fg-1);font-weight:700}
.nav-brand small{display:block;font-size:.76rem;letter-spacing:.14em;color:var(--fg-4)}
.tab-btn{display:flex!important;align-items:center;gap:11px;width:100%;padding:9px 12px!important;margin:0;
  border:0!important;border-radius:var(--radius-sm)!important;background:transparent!important;color:var(--fg-3)!important;
  font:500 .90rem/1.3 var(--sans)!important;text-align:left;cursor:pointer;transition:background .12s,color .12s}
.tab-btn .ic{color:var(--fg-4)}
.tab-btn:hover{background:var(--surface-2)!important;color:var(--fg-1)!important}
.tab-btn.active{background:var(--accent-bg)!important;color:var(--fg-1)!important;font-weight:650!important}
.tab-btn.active .ic{color:var(--accent)}
.tab-btn .tbadge,.tab-btn .badge{margin-left:auto;background:var(--surface-3)!important;color:var(--fg-2)!important;
  border-radius:999px!important;padding:0 8px!important;font:600 .76rem/1.7 var(--mono)!important}

/* ══ 상단 고정 바 ════════════════════════════════════════════════════════ */
.topbar{position:sticky;top:0;z-index:25;display:flex;align-items:center;gap:14px;min-height:var(--top-h);
  margin:0 -32px 22px;padding:8px 32px;background:rgba(10,17,29,.86);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--line);flex-wrap:wrap}
.topbar.scrolled{box-shadow:0 10px 24px -18px rgba(0,0,0,.9)}
.tb-title{display:flex;align-items:center;gap:10px;min-width:0}
.tb-name{font-weight:650;font-size:.98rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:32vw}
.tb-verdict{display:inline-flex;align-items:center;gap:6px;padding:2px 11px;border-radius:999px;font-size:.78rem;font-weight:700;
  color:var(--vc);background:color-mix(in srgb,var(--vc) 15%,transparent)}
.tb-verdict:before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor}
.tb-score{font:650 .90rem var(--mono);color:var(--fg-1)}.tb-score small{color:var(--fg-4);font-weight:400}
.tb-spacer{flex:1}
.tb-actions{display:flex;gap:6px}
.btn,.report-menu-toggle{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 12px;
  border-radius:var(--radius-sm)!important;border:1px solid var(--line-2)!important;background:var(--surface)!important;
  color:var(--fg-2)!important;font:500 .80rem var(--sans);cursor:pointer}
.btn:hover,.report-menu-toggle:hover{border-color:var(--accent)!important;color:var(--fg-1)!important}
.btn-icon,.report-menu-toggle{width:34px;padding:0!important;position:static!important}
.report-menu-toggle .ic{width:17px;height:17px}

/* 표시 범위 — 구분 단추 */
.scope-bar{display:flex!important;align-items:center;gap:8px;margin:0!important;padding:0!important;border:0!important}
.scope-label{font-size:.76rem;color:var(--fg-3);font-weight:600;cursor:help;margin:0}
.scope-seg{display:inline-flex;padding:2px;background:var(--bg-inset);border:1px solid var(--line-2);border-radius:var(--radius-sm)}
.tier-btn{border:0!important;background:transparent!important;color:var(--fg-3)!important;font:600 .76rem var(--sans)!important;
  padding:5px 11px!important;border-radius:7px!important;cursor:pointer}
.tier-btn:hover{color:var(--fg-1)!important}
.tier-btn-on{background:var(--surface-3)!important;color:var(--fg-1)!important;box-shadow:0 0 0 1px var(--line-2) inset}
.scope-note{font-size:.76rem!important;color:var(--warn)!important;white-space:nowrap}
.scope-basis{display:none!important}

/* ══ 판정 히어로 ════════════════════════════════════════════════════════ */
.va{position:relative;background:linear-gradient(180deg,var(--surface-2),var(--surface))!important;border:1px solid var(--line)!important;
  border-radius:var(--radius)!important;padding:26px 28px 22px!important;margin:0 0 20px!important;box-shadow:var(--shadow);overflow:hidden}
.va:before{content:'';position:absolute;inset:0 0 auto 0;height:3px;background:var(--vc)}
.hero-top{display:grid;grid-template-columns:auto minmax(0,1fr) minmax(250px,330px);gap:26px;align-items:center}
.hero-score{position:relative;width:116px;height:116px;flex:none}
.hero-score svg{width:116px;height:116px;transform:rotate(-90deg)}
.hero-score .track{fill:none;stroke:var(--line-2);stroke-width:9}
.hero-score .val{fill:none;stroke:var(--vc);stroke-width:9;stroke-linecap:round}
.hero-score .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.hero-score b{font:700 2rem/1 var(--sans);color:var(--fg-1);font-variant-numeric:tabular-nums}
.hero-score small{font-size:.76rem;color:var(--fg-3);margin-top:5px;letter-spacing:.06em}
.hero-id{min-width:0}
.va-head{display:flex!important;flex-wrap:wrap;align-items:center;gap:7px!important;margin:0 0 8px!important}
.va-pill{display:inline-flex;align-items:center;gap:7px;padding:4px 12px;border-radius:999px;font-size:.82rem!important;font-weight:750!important;
  letter-spacing:.02em;color:var(--vc)!important;background:color-mix(in srgb,var(--vc) 15%,transparent)}
.va-pill:before{content:'';width:8px;height:8px;border-radius:50%;background:currentColor}
.va-tag{padding:3px 10px!important;border:0!important;border-radius:999px;background:var(--surface-3);color:var(--fg-2)!important;font-size:.76rem!important}
.va-tag.va-family{background:var(--danger-bg);color:var(--danger)!important;font-weight:700}
.hero-name{font-size:1.65rem;font-weight:750;letter-spacing:-.02em;line-height:1.25;margin:0;overflow-wrap:anywhere;color:var(--fg-1)}
.hero-path{font:400 .80rem/1.5 var(--mono);color:var(--fg-3);margin-top:5px;overflow-wrap:anywhere}
.hero-hash{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-top:12px;font-size:.76rem;color:var(--fg-4)}
.hero-hash code{font-size:.76rem;padding:3px 8px;overflow-wrap:anywhere}
.hero-hash .btn{height:26px;padding:0 9px;font-size:.76rem}
.hero-hash .btn .ic{width:13px;height:13px}
.hero-facts{display:grid;grid-template-columns:1fr 1fr;gap:12px 18px;margin:0;padding:15px 18px;background:var(--bg-inset);
  border:1px solid var(--line);border-radius:var(--radius-sm)}
.hero-facts div{min-width:0}
.hero-facts dt{font-size:.76rem;color:var(--fg-4);letter-spacing:.05em}
.hero-facts dd{margin:2px 0 0;font-size:.86rem;color:var(--fg-1);font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.va-hash{display:none!important}
.va-stats{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))!important;gap:12px!important;margin:22px 0 0!important;border:0!important}
.va-stat{background:var(--bg-inset)!important;border:1px solid var(--line)!important;border-radius:var(--radius-sm)!important;padding:14px 16px!important}
.va-stat-label{font-size:.76rem!important;letter-spacing:.04em!important;color:var(--fg-3)!important;font-weight:600!important}
.va-stat b{font-size:1.65rem!important;font-weight:700!important;color:var(--fg-1)}
.va-bar{height:5px!important;border-radius:999px;overflow:hidden;background:var(--line-2)!important;margin:8px 0!important}
.va-leg{font-size:.76rem!important;color:var(--fg-3)!important}
.va-leg span:before{border-radius:2px}
.va-ind{margin-top:16px!important;display:grid;gap:10px}
.va-block{background:var(--bg-inset);border:1px solid var(--line)!important;border-radius:var(--radius-sm);overflow:hidden}
.va-block>summary{padding:12px 16px!important;font-weight:650;color:var(--fg-1)}
.va-block>summary:before{border-radius:3px;width:9px!important;height:9px!important}
.va-block>summary:after{content:'';margin-left:auto;width:8px;height:8px;border-right:2px solid var(--fg-4);border-bottom:2px solid var(--fg-4);
  transform:rotate(45deg);transition:transform .15s}
.va-block[open]>summary:after{transform:rotate(-135deg)}
.va-count{background:color-mix(in srgb,var(--c) 15%,transparent);border-radius:999px;padding:0 8px;font-size:.76rem!important}
.va-row{grid-template-columns:150px minmax(0,1fr) 100px!important;padding:10px 16px!important;border-top:1px solid var(--line)!important;font-size:.86rem}
.va-row:hover{background:rgba(96,165,250,.04)}
.va-cat{color:var(--fg-3)!important}
.va-ev{color:var(--fg-3)!important;margin-top:2px}
.va-tid a{color:var(--info);text-decoration:none}
@media(max-width:1180px){.hero-top{grid-template-columns:auto minmax(0,1fr)}.hero-facts{grid-column:1/-1}}
@media(max-width:700px){.hero-top{grid-template-columns:1fr}.hero-score{margin:0 auto}}

/* ══ 섹션 카드 ══════════════════════════════════════════════════════════ */
.tab-panel{display:block!important;background:var(--surface);border:1px solid var(--line)!important;border-radius:var(--radius);
  padding:6px 28px 26px!important;margin:20px 0 0!important;box-shadow:var(--shadow);scroll-margin-top:calc(var(--top-h) + 14px);
  animation:none!important;counter-increment:none!important}
#tab-basic{background:transparent;border:0!important;box-shadow:none;padding:0!important;margin:0!important}
.tab-panel>h2:first-of-type:before{content:none!important}
h2{color:var(--fg-1)}
.sec-h{display:flex!important;align-items:center;gap:12px;font-size:1.12rem!important;font-weight:700;letter-spacing:-.01em;
  margin:18px 0 6px!important;padding:0 0 16px!important;border-bottom:1px solid var(--line)}
#tab-basic>.sec-h{border:0;margin:30px 0 12px!important;padding:0!important}
.sec-ic{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;flex:none;background:var(--accent-bg);color:var(--accent)}
.sec-ic .ic{width:18px;height:18px}
.sec-t{display:flex;flex-direction:column;line-height:1.3}
.sec-sub{font-size:.76rem;font-weight:400;color:var(--fg-3);margin-top:2px}
.tab-panel h3,#tab-basic h3{display:flex;align-items:center;gap:9px;font-size:.96rem!important;font-weight:650;color:var(--fg-1)!important;
  margin:26px 0 12px!important;padding:0!important;border:0!important;line-height:1.4}
.tab-panel h3:before{content:'';width:3px;height:15px;border-radius:2px;background:var(--accent);flex:none}
.tab-panel h4{font-size:.88rem;color:var(--fg-2);margin:18px 0 8px}
.card{background:var(--bg-inset)!important;border:1px solid var(--line)!important;border-radius:var(--radius-sm)!important;padding:16px 18px!important}

/* ══ 표 ════════════════════════════════════════════════════════════════ */
.report-table-scroll{border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--bg-inset)}
table{border-collapse:separate!important;border-spacing:0;width:100%}
th{background:var(--surface-2)!important;color:var(--fg-3)!important;font-weight:600!important;letter-spacing:.01em;
  padding:10px 14px!important;border:0!important;border-bottom:1px solid var(--line-2)!important;text-align:left;position:sticky;top:0;z-index:1}
td{padding:9px 14px!important;border:0!important;border-bottom:1px solid var(--line)!important;color:var(--fg-1)}
tr:last-child>td{border-bottom:0!important}
tbody tr:nth-child(even)>td{background:transparent!important}
tr:hover>td{background:rgba(96,165,250,.05)!important}
.kv td:first-child{color:var(--fg-3)!important}
.srch-input,.hunt-input{background:var(--bg-inset)!important;border:1px solid var(--line-2)!important;border-radius:var(--radius-sm)!important;color:var(--fg-1)}
.srch-input:focus,.hunt-input:focus{outline:0;border-color:var(--accent)!important;box-shadow:0 0 0 3px var(--accent-bg)}
.pg-wrap{padding:10px 2px!important}
.pg-btn{border-radius:var(--radius-xs)!important;background:var(--surface-2)!important;border:1px solid var(--line-2)!important;color:var(--fg-2)!important}
.pg-active{background:var(--accent-bg)!important;border-color:var(--accent)!important;color:var(--fg-1)!important}

/* ══ 배지 · 칩 ═══════════════════════════════════════════════════════════ */
.badge{display:inline-flex;align-items:center;gap:4px;padding:1px 9px!important;border-radius:999px!important;border:0!important;
  font-weight:600!important;line-height:1.7!important;vertical-align:middle;white-space:nowrap}
.tier{display:inline-flex;align-items:center;padding:0 9px;border-radius:999px;font:650 .76rem/1.8 var(--sans);white-space:nowrap;vertical-align:middle}
.tier-1{background:var(--danger-bg);color:var(--danger)}
.tier-2{background:var(--orange-bg);color:var(--orange)}
.tier-3{background:var(--surface-3);color:var(--fg-4)}
.attk-chip{border:0!important;border-radius:var(--radius-xs)!important;background:var(--info-bg)!important;color:var(--info)!important;
  font-family:var(--mono)!important;padding:0 7px!important}
.act-badge{border-radius:999px!important}
.va-tid,.atk-id{font-family:var(--mono)}

/* ══ 알림 ════════════════════════════════════════════════════════════════ */
.alert{border:1px solid var(--line)!important;border-left:3px solid var(--fg-4)!important;border-radius:var(--radius-sm)!important;
  background:var(--surface-2)!important;padding:12px 16px!important;margin:12px 0!important;color:var(--fg-1)!important;font-size:.88rem!important}
.alert-danger{background:var(--danger-bg)!important;border-left-color:var(--danger)!important}
.alert-warning{background:var(--orange-bg)!important;border-left-color:var(--orange)!important}
.alert-info{background:var(--info-bg)!important;border-left-color:var(--info)!important}
.alert-success{background:var(--ok-bg)!important;border-left-color:var(--ok)!important}
.container>.alert{margin:0 0 12px!important}

/* ══ 접기 · 단추 · 기타 ══════════════════════════════════════════════════ */
details>summary{cursor:pointer;color:var(--fg-2)}
details>summary:hover{color:var(--fg-1)}
details.plain>summary{border-top:1px solid var(--line)!important;padding:14px 0!important}
.ev-copy,.copy-btn,.hunt-btn{border-radius:var(--radius-xs)!important;border:1px solid var(--line-2)!important;background:var(--surface-2)!important;
  color:var(--fg-2)!important;cursor:pointer}
.ev-copy:hover,.copy-btn:hover,.hunt-btn:hover{border-color:var(--accent)!important;color:var(--fg-1)!important}
.hunt-box,.hunt-card{background:var(--bg-inset)!important;border:1px solid var(--line)!important;border-radius:var(--radius-sm)!important}
.ptree{border:1px solid var(--line)!important;border-radius:var(--radius-sm);background:var(--bg-inset)!important;padding:8px 12px!important}
.ptree .pt-row{border-radius:var(--radius-xs)}
.bg-view{border-color:var(--line)!important;border-radius:var(--radius)!important;background-color:var(--bg-inset)!important}
.bg-zoom button{border-radius:var(--radius-xs)!important}
::selection{background:rgba(61,214,192,.28)}

@media(max-width:1199px){
  /* 좁은 화면: 메뉴는 상단 바 아래에서 여는 서랍 — 메뉴 단추를 가리지 않는다 */
  .tabs{top:var(--top-h)!important;box-shadow:18px 0 40px -20px rgba(0,0,0,.9)}
  .container{margin:0 auto!important;padding:0 20px 56px!important}
  .topbar{margin:0 -20px 18px;padding:8px 20px}
  .tab-panel{padding:4px 18px 20px!important}
}
@media print{
  :root{--bg:#fff;--surface:#fff;--surface-2:#f4f6f9;--bg-inset:#fff;--fg-1:#111;--fg-2:#333;--fg-3:#555;--fg-4:#777;--line:#d0d7e2;--line-2:#c0c8d6}
  .tabs,.topbar,.report-menu-toggle,.bg-zoom,.srch-wrap,.pg-wrap{display:none!important}
  .container{margin:0!important;max-width:none!important;padding:0!important}
  .tab-panel,.va{box-shadow:none!important;break-inside:auto}
  body{background:#fff!important;color:#111}
}
</style>"""

UI_JS = """
(function(){
  function ready(f){ if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',f); else f(); }
  function copyText(t){
    if(navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(t);
    return new Promise(function(ok,fail){
      var a=document.createElement('textarea'); a.value=t; a.style.position='fixed'; a.style.opacity='0';
      document.body.appendChild(a); a.select();
      try{ document.execCommand('copy') ? ok() : fail(); }catch(e){ fail(e); } finally{ a.remove(); }
    });
  }
  ready(function(){
    document.addEventListener('click',function(e){
      var b=e.target.closest('[data-copy]'); if(!b) return;
      var label=b.querySelector('.lbl'), old=label?label.textContent:'';
      copyText(b.getAttribute('data-copy')).then(function(){ if(label){ label.textContent='복사됨'; setTimeout(function(){label.textContent=old;},1400);} });
    });
    // 좁은 화면에서 메뉴 항목을 고르면 서랍을 닫는다 (넓은 화면의 펼침 선택은 건드리지 않는다)
    document.addEventListener('click',function(e){
      if(window.innerWidth>=1200 || !e.target.closest('.tab-btn')) return;
      document.body.classList.add('menu-hidden');
      var t=document.querySelector('.report-menu-toggle');
      if(t){ t.setAttribute('aria-expanded','false'); t.title='메뉴 열기'; t.setAttribute('aria-label','메뉴 열기'); }
    }, true);   // 캡처 단계 — 메뉴 단추의 처리기가 전파를 막기 전에 받는다
    var tb=document.querySelector('.topbar');
    if(tb){ var f=function(){ tb.classList.toggle('scrolled', window.scrollY>8); }; window.addEventListener('scroll',f,{passive:true}); f(); }
  });
})();
"""
