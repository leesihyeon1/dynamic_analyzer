"""
report_visuals.py — 리포트 개요 화면의 판정 요약 · 위험 지표 · 행위 그래프

세 가지 상용 샌드박스 리포트의 읽는 방식을 가져왔다.

  * Hybrid Analysis — 판정(악성/의심) + 점수 링 + "악성 / 의심 / 정보성 지표" 목록.
    리포트를 열자마자 "그래서 악성인가, 근거가 뭔가"에 답한다.
  * Joe Sandbox     — 행위 그래프. 프로세스 체인과 각 프로세스가 남긴
    파일·레지스트리·네트워크 흔적을 한 장의 그림으로 보여준다.
  * ANY.RUN         — 프로세스 트리 행마다 활동 배지와 펼침 상세.
    (트리 본체는 html_report._process_tree_html, 여기서는 상세 패널과 스타일만 제공)

모든 수치는 이미 수집·판정된 데이터(관련도 등급, ATT&CK 근거, 주입 신뢰도 등)에서
계산한다. 새로운 탐지는 하지 않는다 — 점수는 "규칙 기반 지표의 합"일 뿐이며
리포트에도 그렇게 표기한다.

그래프는 라이브러리 없이 인라인 SVG 로 그린다(격리 VM 에서 오프라인으로 열려야 한다).
"""

from __future__ import annotations

import html
import ipaddress
import math
import os

_e = html.escape

# 의미 색 — 리포트 전체에서 같은 뜻으로만 쓴다
C_MAL, C_SUS, C_INFO, C_OK, C_MUTE = "#ff6b6b", "#f0b429", "#4fb3d9", "#3fb98f", "#2a3b54"

VISUALS_CSS = """
<style>
/* ══ 화면 원칙: 상자 대신 선 ═══════════════════════════════════════════════
   둥근 카드·채운 배경을 걷어내고 구분선과 표로만 구획한다.
   리포트는 탭이 아니라 위에서 아래로 읽는 한 장의 문서다. */
.card,.metric,.hunt-box,.hunt-card,.health-strip,.alert,.badge,.tab-btn,.srch-input,.hunt-input,
.pg-btn,code,.act-badge,.attk-chip,.ptree,.beh-panel,.report-actions button,.tbadge,
.tab-panel [style*='border-radius']{border-radius:0!important}
.card{background:transparent;border:0;border-top:1px solid var(--line);padding:4px 0}
.grid2{gap:0 48px}
.health-strip,.health-strip.warning{background:transparent;border:0;border-left:3px solid currentColor;padding:6px 14px}
.tools-disclosure{border-bottom:0;margin:10px 0 0;padding-bottom:0}
th{background:transparent;border-bottom:2px solid #4a5f7d;padding:9px 12px}
td{padding:8px 12px;border-bottom:1px solid #1f2e45}
tbody tr:nth-child(even)>td{background:transparent}
h2{font-size:1.2rem;margin:18px 0 14px;display:flex;align-items:baseline}
h3{border-bottom:1px solid var(--line);padding-bottom:6px;color:var(--text);font-size:.95rem}
.tab-btn{border-left:3px solid transparent!important;padding:9px 14px}
.tab-btn.active{background:transparent;border-left-color:var(--accent)!important;color:var(--text)}
.tab-btn:hover{background:transparent;color:var(--text)}

/* ── 세로 단일 페이지: 모든 구간을 순서대로 펼친다 ── */
.container{counter-reset:sec}
.tab-panel{display:block!important;animation:none!important;border-top:2px solid #4a5f7d;margin-top:64px;
  padding-top:2px;scroll-margin-top:14px;counter-increment:sec}
#tab-basic{border-top:0;margin-top:0;counter-increment:none}
.tab-panel:not(#tab-basic)>h2:first-of-type:before{content:counter(sec,decimal-leading-zero);
  font-family:'Cascadia Code',Consolas,monospace;font-size:.82rem;color:var(--accent);margin-right:14px;letter-spacing:.06em}

/* ── 판정 요약 ── */
.va{border-top:3px solid var(--vc);padding:16px 0 0;margin:0 0 30px}
.va-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 16px;margin-bottom:4px}
.va-pill{font-weight:750;font-size:1.15rem;letter-spacing:.04em;color:var(--vc)}
.va-tag{font-size:.76rem;color:var(--muted);border-left:1px solid var(--line);padding-left:14px}
.va-name{font-size:1.05rem;font-weight:650;overflow-wrap:anywhere}
.va-hash{font-family:'Cascadia Code',Consolas,monospace;font-size:.76rem;color:var(--muted);overflow-wrap:anywhere;margin-bottom:14px}
.va-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.va-stat{padding:12px 22px;border-left:1px solid var(--line)}
.va-stat:first-child{border-left:0;padding-left:0}
.va-stat-label{font-size:.72rem;letter-spacing:.08em;color:var(--muted);font-weight:650}
.va-stat b{display:block;font-size:1.8rem;font-weight:650;line-height:1.25;font-variant-numeric:tabular-nums}
.va-stat b small{font-size:.8rem;color:var(--muted);font-weight:400;margin-left:4px}
.va-bar{display:flex;height:4px;background:#2a3b54;margin:6px 0 7px}
.va-bar i{display:block;height:100%}
.va-leg{font-size:.76rem;color:var(--muted)}
.va-leg span{margin-right:12px;white-space:nowrap}
.va-leg span:before{content:'';display:inline-block;width:8px;height:8px;background:var(--c);margin-right:5px}
.va-note{font-size:.74rem;color:var(--muted);margin:10px 0 0}
.va-ind{margin-top:22px}
.va-block{border-top:1px solid var(--line)}
.va-block>summary{cursor:pointer;list-style:none;padding:10px 0;display:flex;align-items:center;gap:10px;font-weight:650}
.va-block>summary::-webkit-details-marker{display:none}
.va-block>summary:before{content:'';width:10px;height:10px;background:var(--c);flex:none}
.va-count{color:var(--c);font-family:'Cascadia Code',Consolas,monospace;font-size:.86rem}
.va-row{display:grid;grid-template-columns:150px minmax(0,1fr) 96px;gap:18px;padding:7px 0;border-top:1px solid #1f2e45;font-size:.86rem;line-height:1.55}
.va-cat{color:var(--muted);font-size:.8rem}
.va-ev{display:block;font-family:'Cascadia Code',Consolas,monospace;font-size:.74rem;color:var(--muted);overflow-wrap:anywhere}
.va-tid{font-family:'Cascadia Code',Consolas,monospace;font-size:.76rem;color:#9fb4d1;text-align:right;white-space:nowrap}
.va-tid a{color:inherit}
.va-empty{font-size:.84rem;color:var(--muted);padding:2px 0 10px 20px}

/* ── 행위 그래프 ── */
.bg-fig{margin:0 0 24px;padding:0}
.bg-scroll{overflow:auto;max-height:760px;border:1px solid var(--line);background:#0e1828}
.bg-svg{display:block;color:var(--text)}
.bg-svg text{font-family:'Cascadia Code',Consolas,'Malgun Gothic',monospace;fill:currentColor}
.bg-svg .bg-sub{fill:#9fb0c8;font-size:10px}
.bg-svg .bg-el{fill:#a9bbd6;font-size:10px;paint-order:stroke;stroke:#0e1828;stroke-width:4px;stroke-linejoin:round}
.bg-svg .bg-edge{fill:none;stroke:#5a7196;stroke-width:1.3}
.bg-svg .bg-edge-art{stroke-dasharray:4 3}
.bg-svg .bg-proc{cursor:pointer}
.bg-svg .bg-proc:hover rect{filter:brightness(1.4)}
.bg-legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:.76rem;color:var(--muted);margin-top:10px}
.bg-legend i{display:inline-block;width:16px;height:10px;border:1.5px solid var(--c);margin-right:6px;vertical-align:-1px}
.bg-fig figcaption{font-size:.8rem;color:var(--muted);margin-top:8px}

/* ── 구간별 ATT&CK (별도 목록 대신 해당 텔레메트리 옆에) ── */
.atk{margin:4px 0 24px;border-bottom:1px solid var(--line)}
.atk-h{font-size:.72rem;letter-spacing:.1em;color:var(--muted);font-weight:650;padding:0 0 6px}
.atk-row{display:grid;grid-template-columns:86px minmax(150px,270px) 120px minmax(0,1fr);gap:14px;
  padding:7px 0 7px 10px;border-top:1px solid #1f2e45;border-left:3px solid var(--c);font-size:.84rem;line-height:1.5}
.atk-id{font-family:'Cascadia Code',Consolas,monospace}
.atk-id a{color:#9fc4ff;text-decoration:none}
.atk-tac{color:var(--muted);font-size:.78rem}
.atk-ev{font-family:'Cascadia Code',Consolas,monospace;font-size:.74rem;color:#b3c2d8;overflow-wrap:anywhere}
.atk-ev div+div{margin-top:2px}
.atk-more{color:var(--muted)}
@media(max-width:900px){.atk-row{grid-template-columns:80px 1fr}.atk-tac{display:none}.atk-ev{grid-column:1/-1}
  .va-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.va-row{grid-template-columns:1fr}.va-tid{text-align:left}}

/* ── 프로세스 트리 ── */
.ptree{font-family:inherit;background:transparent;border:0;border-top:1px solid var(--line);padding:2px 0}
.ptree .pt-children{padding-left:22px;margin-left:9px;border-left:1px solid #4a5f7d}
.ptree .pt-wrap{position:relative;margin:0}
.ptree .pt-children>.pt-wrap:before{content:'';position:absolute;left:-22px;top:19px;width:18px;border-top:1px solid #4a5f7d}
.ptree .pt-row{align-items:center;gap:8px;padding:8px 4px;border:0;border-bottom:1px solid #1f2e45;background:transparent;line-height:1.4}
.ptree .pt-row:hover{background:#132238}
.ptree .pt-pid{font-family:'Cascadia Code',Consolas,monospace;color:#8ea2bf;font-size:.76rem}
.ptree .pt-meta{font-family:'Cascadia Code',Consolas,monospace;color:#8496b0;font-size:.74rem;padding:2px 0 0 44px;word-break:normal;overflow-wrap:anywhere}
.ptree .pt-spacer{flex:1}
.pt-ic{display:inline-block;width:18px;height:18px;line-height:16px;text-align:center;border:1px solid currentColor;
  font:700 .66rem/16px 'Cascadia Code',Consolas,monospace;flex:none}
.pt-ic-s{color:#58a6ff}.pt-ic-n{color:#f0b429}.pt-ic-x{color:#ff6b6b}.pt-ic-e{color:#6b7f9c}
.ptree .pt-more{background:transparent;border:1px solid var(--line);color:#9fb0c8;font-size:.72rem;padding:1px 8px;cursor:pointer}
.ptree .pt-more:hover{color:var(--text);border-color:var(--accent)}
.ptree .pt-detail{display:none;margin:4px 0 8px 44px;border-left:2px solid #4a5f7d;padding:4px 0 4px 14px}
.ptree .pt-detail.open{display:block}
.ptree .pt-detail h5{font-size:.74rem;color:#9fb4d1;margin:8px 0 3px;font-weight:650}
.ptree .pt-detail h5:first-child{margin-top:0}
.ptree .pt-detail div{font-family:'Cascadia Code',Consolas,monospace;font-size:.74rem;color:#c8d6ea;overflow-wrap:anywhere;line-height:1.55}
.ptree .pt-flash>.pt-row{outline:1px solid var(--accent);background:#132238}
details.plain>summary{cursor:pointer;color:var(--muted);font-size:.85rem;padding:10px 0;border-top:1px solid var(--line)}
</style>
<script>
function rvGoProc(pid){
  const row=document.getElementById('proc-record-'+pid);
  if(!row)return;
  document.querySelector('[data-tab="tab-process"]')?.click();
  const table=row.closest('table');
  table.dispatchEvent(new CustomEvent('reveal-process',{detail:row}));
  row.scrollIntoView({block:'center'});row.classList.add('pt-flash');
  setTimeout(()=>row.classList.remove('pt-flash'),1800);
}
function rvToggleDetail(ev,id){
  ev.stopPropagation(); var d=document.getElementById(id); if(d) d.classList.toggle('open');
}
// 왼쪽 목차 = 구간 바로가기. 스크롤 위치에 맞춰 현재 구간을 표시한다.
document.addEventListener('DOMContentLoaded',function(){
  var btns=[].slice.call(document.querySelectorAll('.tab-btn'));
  function mark(id){btns.forEach(function(b){var on=b.dataset.tab===id;b.classList.toggle('active',on);
    b.setAttribute('aria-current',on?'true':'false');});}
  btns.forEach(function(b){b.addEventListener('click',function(e){
    e.stopImmediatePropagation();
    var p=document.getElementById(b.dataset.tab); if(!p) return;
    window.scrollTo({top:p.getBoundingClientRect().top+window.scrollY-10,behavior:'auto'}); mark(b.dataset.tab);
  },true);});
  var tick=false;
  window.addEventListener('scroll',function(){ if(tick) return; tick=true;
    requestAnimationFrame(function(){ tick=false; var cur=null;
      btns.forEach(function(b){var p=document.getElementById(b.dataset.tab);
        if(p&&p.getBoundingClientRect().top<=140) cur=b.dataset.tab;});
      if(cur) mark(cur); });
  },{passive:true});
});
</script>
"""

_TACTIC_KO = {
    "Initial Access": "초기 침투", "Execution": "실행", "Persistence": "지속성",
    "Privilege Escalation": "권한 상승", "Defense Evasion": "방어 회피",
    "Credential Access": "자격증명 접근", "Discovery": "탐색", "Lateral Movement": "측면 이동",
    "Collection": "수집", "Command and Control": "C2 통신", "Exfiltration": "유출", "Impact": "영향",
}
# 계보에서 관측되면 그 자체로 악성 판단 근거가 되는 기법 (접두 일치)
_HIGH_SEV = ("T1055", "T1547", "T1543", "T1053", "T1574", "T1555", "T1539", "T1562",
             "T1486", "T1490", "T1003", "T1056", "T1041", "T1048")
_EXTERNAL_SOURCES = {"virustotal", "capa"}
_EXE_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk")


def _short(s: str, n: int) -> str:
    """가운데 생략 — 경로는 앞(드라이브)과 뒤(파일명)가 둘 다 의미 있다."""
    s = str(s or "")
    if len(s) <= n:
        return s
    keep = n - 1
    head = keep // 3
    return s[:head] + "…" + s[-(keep - head):]


def _is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local
                    or a.is_unspecified or a.is_reserved)
    except ValueError:
        return False


def _reg_tuple(r):
    if isinstance(r, dict):
        return str(r.get("path", "")), str(r.get("name", "")), str(r.get("data", r.get("detail", "")))
    if isinstance(r, (list, tuple)):
        v = [str(x) for x in r] + ["", "", ""]
        return v[0], v[1], v[2]
    return str(r), "", ""


def _unanswered_dns(result) -> list:
    """응답이 없고 배경이 아닌 DNS 질의 — C2 가 죽었거나 격리망이라 실패한 경우."""
    pcap = getattr(result, "pcap_result", None)
    out = []
    for q in (getattr(pcap, "dns_queries", None) or []):
        nm = (getattr(q, "name", "") or "").strip(".")
        if not nm or "." not in nm or getattr(q, "relevance_tier", 2) > 2:
            continue
        if nm.lower().endswith((".local", ".arpa", ".lan", ".home")):
            continue
        if getattr(q, "response_ips", None) and not getattr(q, "no_response", False):
            continue
        if nm not in out:
            out.append(nm)
    return out


# ═════════════════════════════════════════════════════════════════════════════
# 위험 지표
# ═════════════════════════════════════════════════════════════════════════════

def build_indicators(result) -> list:
    """수집 결과 → [{level: mal|sus|info, cat, title, ev, tid}] (새 탐지 없음, 재분류만)."""
    out: list = []
    covered: set = set()   # 전용 지표가 이미 설명한 기법 — 기법 목록에서 중복 제거

    def add(level, cat, title, ev="", tid=""):
        out.append({"level": level, "cat": cat, "title": title, "ev": ev, "tid": tid})

    lineage = set(getattr(result, "lineage_pids", None) or ())

    # ── 주입 탐지 (신뢰도 판정 결과) ──
    low = 0
    for f in (getattr(result, "injection_findings", None) or []):
        conf = f.get("confidence", "")
        line = f"{f.get('name', '?')} (PID {f.get('pid', '?')})"
        if conf == "HIGH":
            add("mal", "프로세스 주입", f"샘플 계보 프로세스에서 코드 주입 탐지 — {line}", f.get("reason", ""), "T1055")
            covered.add("T1055")
        elif conf == "MEDIUM":
            add("sus", "프로세스 주입", f"계보 밖 프로세스에서 PE 교체/주입 탐지 — {line}", f.get("reason", ""), "T1055")
            covered.add("T1055")
        else:
            low += 1
    if low:
        add("info", "프로세스 주입", f"오탐으로 추정되는 주입 탐지 {low}건 (JIT·재배치 영역)",
            "메모리 탭에서 개별 확인 가능")
        covered.add("T1055")

    # ── DLL 사이드로딩 / 사칭 / 패커 ──
    for f in (getattr(result, "sideload_findings", None) or []):
        lvl = "mal" if f.get("confidence") == "HIGH" else "sus"
        add(lvl, "방어 회피", f"DLL 사이드로딩 — {f.get('loader_name', '?')} 가 같은 폴더의 드롭된 DLL 로드",
            f.get("dll_path", ""), "T1574.002")
        covered.add("T1574.002")
    for f in (getattr(result, "masquerade_findings", None) or []):
        lvl = "mal" if (f.get("confidence") == "HIGH" and f.get("in_lineage")) else "sus"
        add(lvl, "방어 회피", f"정상 구성요소 사칭 — {f.get('filename', '')}", f.get("path", ""), "T1036")
        covered.add("T1036")
    for f in (getattr(result, "packer_findings", None) or []):
        add("info", "정적 특성", f"패커/인스톨러 식별 — {f.get('name', '?')} ({f.get('confidence', '')})")

    # ── 자동실행 레지스트리 ──
    try:
        from analysis.registry_relevance import registry_key_interest
    except Exception:
        registry_key_interest = lambda _p: ""          # noqa: E731
    for r in ((getattr(result, "registry_diff", None) or {}).get("added", []) or []):
        key, name, data = _reg_tuple(r)
        why = registry_key_interest(key)
        if not why:
            continue
        auto = "자동실행" in why or "Run" in why
        add("mal" if auto else "sus", "지속성", f"{why} 레지스트리 등록 — {name or '(기본값)'}",
            f"{key} → {data[:160]}", "T1547.001" if auto else "")
        if auto:
            covered.add("T1547.001")

    # ── 드롭 파일 ──
    ioc = getattr(result, "ioc_report", None)
    tiers = getattr(ioc, "dropped_file_tiers", {}) or {}
    drops = [str(f) for f in (getattr(ioc, "dropped_files", None) or [])]
    d1 = [f for f in drops if tiers.get(f, 2) == 1 and f.lower().endswith(_EXE_EXT)]
    d2 = [f for f in drops if tiers.get(f, 2) == 2 and f.lower().endswith(_EXE_EXT)]
    if d1:
        add("mal", "파일 드롭", f"샘플 계보가 실행 가능 파일 {len(d1)}건 드롭",
            ", ".join(os.path.basename(f.replace("\\", "/")) for f in d1[:5]))
    if d2 and not lineage:
        add("sus", "파일 드롭", f"분석 중 실행 가능 파일 {len(d2)}건 생성 (프로세스 계보 미확정)",
            ", ".join(os.path.basename(f.replace("\\", "/")) for f in d2[:5]))

    # ── 네트워크 ──
    pcap = getattr(result, "pcap_result", None)
    for s in (getattr(pcap, "smtp_sessions", None) or [])[:3]:
        add("mal", "유출", "SMTP 세션 관측 — 메일로 데이터 유출 가능", f"{s.dst_ip}:{s.dst_port}", "T1048")
    for s in (getattr(pcap, "ftp_sessions", None) or [])[:3]:
        add("mal", "유출", "FTP 세션 관측 — 파일 업로드 가능", f"{s.dst_ip}:{s.dst_port}", "T1048")
    ip2dom = getattr(pcap, "ip_to_domain", {}) or {}
    lin_conns = []
    for c in (getattr(pcap, "connections", None) or []):
        if getattr(c, "relevance_tier", 2) != 1 or not _is_external(getattr(c, "dst_ip", "")):
            continue
        d = ip2dom.get(c.dst_ip) or []
        host = d[0] if isinstance(d, list) and d else c.dst_ip
        lbl = f"{host}:{c.dst_port}"
        if lbl not in lin_conns:
            lin_conns.append(lbl)
    if lin_conns:
        add("sus", "C2 통신", f"샘플 계보 프로세스의 외부 통신 {len(lin_conns)}건", ", ".join(lin_conns[:6]))
    un = _unanswered_dns(result)
    if un:
        add("sus", "C2 통신", f"응답 없는 DNS 질의 {len(un)}건 — C2/유출 서버 후보 (접속 실패)", ", ".join(un[:6]))
    for b in (getattr(pcap, "beacon_candidates", None) or [])[:2]:
        add("sus", "C2 통신", "주기적 비콘 패턴",
            f"{getattr(b, 'dst_ip', '')}:{getattr(b, 'dst_port', '')}", "T1071")

    # ── YARA ──
    yr = getattr(result, "yara_result", None)
    for m in (getattr(yr, "matches", None) or [])[:6]:
        rule = getattr(m, "rule", None) or (m.get("rule") if isinstance(m, dict) else "") or str(m)
        add("sus", "패턴 매칭", f"YARA 룰 일치 — {rule}")

    # ── ATT&CK 기법 (관측 vs 외부 출처 구분) ──
    br = getattr(result, "behavior_report", None)
    ext_by_tactic: dict = {}
    for t in (getattr(br, "techniques", None) or []):
        tid = getattr(t, "technique_id", "")
        if tid in covered or tid.split(".")[0] in covered:
            continue
        tier = getattr(t, "relevance_tier", 0) or 2
        if tier >= 3:
            continue
        srcs = {str(s).lower() for s in (getattr(t, "sources", None) or [])}
        tactic = getattr(t, "tactic", "") or "기타"
        name = getattr(t, "technique_name", "") or tid
        if srcs and srcs <= _EXTERNAL_SOURCES:
            ext_by_tactic.setdefault(tactic, []).append(f"{name} ({tid})")
            continue
        high = tid.startswith(_HIGH_SEV)
        if tier == 1:
            lvl = "mal" if high else "sus"
        else:
            lvl = "sus" if high else "info"
        ev = next((x for x in (getattr(t, "evidence", None) or []) if x), "")
        add(lvl, _TACTIC_KO.get(tactic, tactic), name, str(ev)[:200], tid)
    for tactic, names in ext_by_tactic.items():
        add("info", "외부 출처 (이번 실행에서 미관측)",
            f"{_TACTIC_KO.get(tactic, tactic)} — 타 샌드박스·정적 분석이 보고한 기법 {len(names)}건",
            ", ".join(names[:6]) + (" …" if len(names) > 6 else ""))

    # ── 실행 진단 ──
    v = getattr(br, "execution_verdict", "") if br else ""
    _VTXT = {"CONFIRMED": "실행과 네트워크 활동이 확인됨", "PARTIAL": "실행됐으나 C2 응답 미확인",
             "EVADED": "분석 환경 탐지 후 조기 종료 의심", "FAILED": "샘플 실행 실패 의심"}
    if v in _VTXT:
        add("sus" if v == "EVADED" else "info", "실행 진단", _VTXT[v], f"execution_verdict = {v}")
    return out


def score_indicators(inds: list) -> tuple:
    """(점수 0-100, 판정 키, 판정 문구, 색). 지표 개수에 대한 단순 가중합이다."""
    mal = sum(1 for i in inds if i["level"] == "mal")
    sus = sum(1 for i in inds if i["level"] == "sus")
    info = sum(1 for i in inds if i["level"] == "info")
    score = (40 + 15 * (mal - 1) if mal else 0) + min(30, 6 * sus) + min(5, info)
    score = max(0, min(100, score))
    if mal >= 2 or score >= 70:
        return score, "mal", "악성 · MALICIOUS", C_MAL
    if mal == 1 or score >= 30:
        return score, "sus", "의심 · SUSPICIOUS", C_SUS
    return score, "ok", "특이 위협 미확인", C_OK


def _stat(label: str, big: str, unit: str, segments: list) -> str:
    """숫자 하나 + 구성비 막대(선) + 범례. segments: [(값, 이름, 색)]."""
    total = sum(v for v, _, _ in segments) or 1
    bar = "".join(f"<i style='width:{100 * v / total:.2f}%;background:{c}'></i>" for v, _, c in segments if v > 0)
    leg = "".join(f"<span style='--c:{c}'>{_e(t)} {v}</span>" for v, t, c in segments if t)
    return (f"<div class='va-stat'><div class='va-stat-label'>{_e(label)}</div>"
            f"<b>{_e(big)}<small>{_e(unit)}</small></b><div class='va-bar'>{bar}</div>"
            f"<div class='va-leg'>{leg}</div></div>")


def _attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _indicator_block(title: str, color: str, items: list, opened: bool) -> str:
    rows = []
    for i in sorted(items, key=lambda x: x["cat"]):
        tid = (f"<a href='{_attack_url(i['tid'])}' target='_blank' rel='noopener'>{_e(i['tid'])}</a>"
               if i["tid"] else "")
        ev = f"<span class='va-ev'>{_e(i['ev'])}</span>" if i["ev"] else ""
        rows.append(f"<div class='va-row'><div class='va-cat'>{_e(i['cat'])}</div>"
                    f"<div>{_e(i['title'])}{ev}</div><div class='va-tid'>{tid}</div></div>")
    if not items:
        rows.append("<div class='va-empty'>해당 지표 없음</div>")
    return (f"<details class='va-block' style='--c:{color}'{' open' if opened else ''}>"
            f"<summary>{_e(title)} <span class='va-count'>{len(items)}</span></summary>"
            f"{''.join(rows)}</details>")


def verdict_overview_html(result, sample_name: str, sample_sha256: str = "") -> str:
    """개요 탭 최상단 — 판정, 점수 링, 지표 목록."""
    inds = build_indicators(result)
    score, _key, verdict, vcolor = score_indicators(inds)
    mal = [i for i in inds if i["level"] == "mal"]
    sus = [i for i in inds if i["level"] == "sus"]
    info = [i for i in inds if i["level"] == "info"]

    counts = getattr(result, "relevance_counts", {}) or {}

    def _tc(kind):
        d = counts.get(kind) or {}
        return tuple(int(d.get(k, d.get(str(k), 0)) or 0) for k in (1, 2, 3))

    p1, p2, p3 = _tc("processes")
    t1, t2, t3 = _tc("techniques")
    _BG = "#5b6f8c"
    rings = [
        _stat("위협 점수", str(score), "/ 100", [(score, "", vcolor), (100 - score, "", C_MUTE)]),
        _stat("위험 지표", str(len(inds)), "건",
              [(len(mal), "악성", C_MAL), (len(sus), "의심", C_SUS), (len(info), "정보", C_INFO)]),
        _stat("신규 프로세스", str(p1 + p2 + p3), "개", [(p1, "계보", C_MAL), (p2, "의심", C_SUS), (p3, "배경", _BG)]),
        _stat("ATT&CK 기법", str(t1 + t2 + t3), "건", [(t1, "계보", C_MAL), (t2, "의심", C_SUS), (t3, "배경", _BG)]),
    ]

    ext = os.path.splitext(sample_name)[1].lower().lstrip(".")
    tags = "".join(f"<span class='va-tag'>{_e(t)}</span>" for t in (
        [ext.upper()] if ext else []) + (["스크립트"] if ext in ("js", "jse", "vbs", "vbe", "wsf", "hta", "ps1")
                                         else ["문서"] if ext in ("doc", "docx", "docm", "xls", "xlsx", "xlsm", "rtf", "pdf")
                                         else ["실행 파일"] if ext in ("exe", "dll", "scr") else []))
    sample_pid = getattr(result, "sample_pid", None)
    host = ""
    for p in ((getattr(result, "process_diff", None) or {}).get("new_processes", []) or []):
        if getattr(p, "pid", None) == sample_pid and (getattr(p, "name", "") or "").lower() != sample_name.lower():
            host = f"<span class='va-tag'>호스트 {_e(getattr(p, 'name', ''))} · PID {sample_pid}</span>"
            break

    return (
        "<section class='va' aria-label='판정 요약' style='--vc:" + vcolor + "'>"
        f"<div class='va-head'><span class='va-pill'>{_e(verdict)}</span>"
        f"<span class='va-name'>{_e(sample_name)}</span>{tags}{host}</div>"
        + (f"<div class='va-hash'>SHA-256 {_e(sample_sha256)}</div>" if sample_sha256 else "<div class='va-hash'></div>")
        + f"<div class='va-stats'>{''.join(rings)}</div>"
        "<div class='va-ind'>"
        + _indicator_block("악성 지표", C_MAL, mal, len(mal) <= 3)
        + _indicator_block("의심 지표", C_SUS, sus, len(sus) <= 3)
        + _indicator_block("정보성 지표", C_INFO, info, False)
        + "</div></section>"
    )


# ═════════════════════════════════════════════════════════════════════════════
# 행위 그래프
# ═════════════════════════════════════════════════════════════════════════════

_COL_W, _PW, _PH, _AW, _AH, _GAP, _PAD = 300, 196, 44, 232, 28, 14, 18
_MAX_NODES = 90
_LEVEL_COLOR = {"mal": C_MAL, "sus": C_SUS, "info": C_INFO, "root": "#58a6ff", "plain": "#5b7397", "ghost": "#5b7397"}


class _N:
    __slots__ = ("kind", "label", "sub", "level", "title", "edge", "pid", "children", "x", "y")

    def __init__(self, kind, label, sub="", level="plain", title="", edge="", pid=None):
        self.kind, self.label, self.sub, self.level = kind, label, sub, level
        self.title, self.edge, self.pid = title or label, edge, pid
        self.children, self.x, self.y = [], 0, 0.0

    @property
    def h(self):
        return _PH if self.kind in ("proc", "ghost") else _AH

    @property
    def w(self):
        return _PW if self.kind in ("proc", "ghost") else _AW


def _build_graph(result, fallback_procs: list) -> list:
    procs_all = (getattr(result, "process_diff", None) or {}).get("new_processes", []) or []
    lineage = set(getattr(result, "lineage_pids", None) or ())
    procs = [p for p in procs_all if getattr(p, "pid", None) in lineage] or list(fallback_procs or [])
    if not procs:
        return []
    behaviors = getattr(result, "process_behaviors", {}) or {}
    sample_pid = getattr(result, "sample_pid", None)
    ioc = getattr(result, "ioc_report", None)
    tiers = {str(k).lower(): v for k, v in (getattr(ioc, "dropped_file_tiers", {}) or {}).items()}
    dropped = {str(f).lower() for f in (getattr(ioc, "dropped_files", None) or [])
               if tiers.get(str(f).lower(), 2) <= 2}
    pcap = getattr(result, "pcap_result", None)
    ip2dom = getattr(pcap, "ip_to_domain", {}) or {}
    inj = {f.get("pid"): f.get("confidence") for f in (getattr(result, "injection_findings", None) or [])}
    try:
        from analysis.registry_relevance import registry_key_interest
    except Exception:
        registry_key_interest = lambda _p: ""          # noqa: E731

    by_pid = {p.pid: p for p in procs}
    nodes: dict = {}
    budget = [_MAX_NODES]

    def _arts(node: _N, b) -> None:
        def _group(items, mk, edge, more_kind, cap):
            for it in items[:cap]:
                if budget[0] <= 0:
                    return
                n = mk(it)
                n.edge = edge
                node.children.append(n)
                budget[0] -= 1
            if len(items) > cap:
                node.children.append(_N(more_kind, f"… 외 {len(items) - cap}건", level="plain", edge=edge,
                                        title="\n".join(str(i) for i in items[cap:cap + 30])))

        files = [f for f in (getattr(b, "files_written", None) or []) if str(f).lower() in dropped]
        files.sort(key=lambda f: (not str(f).lower().endswith(_EXE_EXT), str(f).lower()))
        _group(files, lambda f: _N("file", _short(os.path.basename(str(f).replace("\\", "/")), 30),
                                   level="mal" if str(f).lower().endswith(_EXE_EXT) else "sus", title=str(f)),
               "드롭", "file", 4)

        regs = [(r, registry_key_interest(r)) for r in (getattr(b, "reg_written", None) or [])]
        regs = [(r, w) for r, w in regs if w]
        _group(regs, lambda rw: _N("reg", _short(rw[0].split("\\", 1)[-1], 30),
                                   level="mal" if ("Run" in rw[1] or "자동실행" in rw[1]) else "sus",
                                   title=f"{rw[0]}\n({rw[1]})"),
               "등록", "reg", 3)

        conns = [(ip, port) for ip, port in (getattr(b, "tcp_conns", None) or []) if _is_external(str(ip))]

        def _mk_net(c):
            d = ip2dom.get(c[0]) or []
            dom = d[0] if isinstance(d, list) and d else ""
            return _N("net", _short(f"{dom or c[0]}:{c[1]}", 30), level="sus", title=f"{c[0]}:{c[1]} {dom}")
        _group(conns, _mk_net, "연결", "net", 4)
        _group(list(getattr(b, "dns_queries", None) or []),
               lambda q: _N("dns", _short(str(q), 30), level="sus", title=str(q)), "DNS", "dns", 3)

    for p in procs:
        b = behaviors.get(p.pid)
        nm = getattr(p, "name", "") or f"PID {p.pid}"
        # 흔적 없는 콘솔 호스트는 그림에서 뺀다 (트리에는 그대로 남는다)
        if nm.lower() == "conhost.exe" and not any(q.ppid == p.pid for q in procs):
            continue
        n = _N("proc", _short(nm, 22), sub=f"PID {p.pid}", pid=p.pid,
               title=" ".join(getattr(p, "cmdline", None) or []) or (getattr(p, "exe", "") or nm))
        if b is not None:
            _arts(n, b)
        if inj.get(p.pid) == "HIGH":
            n.level, n.sub = "mal", n.sub + " · 코드 주입 탐지"
        elif any(c.level == "mal" for c in n.children):
            n.level = "mal"
        elif n.children:
            n.level = "sus"
        if p.pid == sample_pid:
            n.sub += " · 샘플"
            if n.level == "plain":
                n.level = "root"
        nodes[p.pid] = n

    roots = []
    for p in procs:
        n = nodes.get(p.pid)
        if n is None:
            continue
        parent = nodes.get(getattr(p, "ppid", None))
        if parent is not None and parent is not n:
            n.edge = "생성"
            parent.children.insert(sum(1 for c in parent.children if c.kind == "proc"), n)
        else:
            roots.append(n)
    roots.sort(key=lambda n: (n.pid != sample_pid, n.pid or 0))

    # 프로세스에 귀속하지 못한 C2 후보 — 숨기지 않고 "귀속 미확인"으로 따로 세운다
    attributed = {getattr(q, "name", "") for q in (getattr(result, "dns_attributed", None) or [])
                  if getattr(q, "attributed", False)}
    loose = [d for d in _unanswered_dns(result) if d not in attributed]
    if loose:
        g = _N("ghost", "프로세스 귀속 미확인", sub="응답 없는 DNS 질의", level="ghost",
               title="DNS 질의는 Dnscache 서비스가 대신 보내므로 어느 프로세스의 요청인지 확정하지 못했습니다")
        for d in loose[:5]:
            c = _N("dns", _short(d, 30), level="sus", title=d)
            c.edge = "DNS"
            g.children.append(c)
        roots.append(g)
    return roots


def _layout(roots: list) -> tuple:
    cur = [float(_PAD)]
    maxd = [0]

    def place(n: _N, depth: int) -> None:
        n.x = depth
        maxd[0] = max(maxd[0], depth)
        if not n.children:
            n.y = cur[0] + n.h / 2
            cur[0] += n.h + _GAP
            return
        top = cur[0]
        for c in n.children:
            place(c, depth + 1)
        n.y = max((n.children[0].y + n.children[-1].y) / 2, top + n.h / 2)
        cur[0] = max(cur[0], n.y + n.h / 2 + _GAP)

    for r in roots:
        place(r, 0)
        cur[0] += 10
    width = _PAD * 2 + maxd[0] * _COL_W + max(_PW, _AW if maxd[0] else _PW)
    return int(width), int(cur[0] + _PAD)


def _node_svg(n: _N) -> str:
    x = _PAD + n.x * _COL_W
    y = n.y - n.h / 2
    color = _LEVEL_COLOR.get(n.level, "#5b7397")
    title = f"<title>{_e(n.title)}</title>"
    if n.kind in ("proc", "ghost"):
        dash = " stroke-dasharray='5 4'" if n.kind == "ghost" else ""
        fill = "#1a2a43" if n.level in ("plain", "ghost") else "#1d2536"
        body = (f"<rect x='{x}' y='{y:.1f}' width='{n.w}' height='{n.h}' rx='0' fill='{fill}' "
                f"stroke='{color}' stroke-width='1.8'{dash}/>"
                f"<rect x='{x}' y='{y:.1f}' width='4' height='{n.h}' fill='{color}'/>"
                f"<text x='{x + 14}' y='{n.y - 3:.1f}' font-size='12.5' font-weight='700'>{_e(n.label)}</text>"
                f"<text x='{x + 14}' y='{n.y + 12:.1f}' class='bg-sub'>{_e(n.sub)}</text>")
        if n.kind == "proc" and n.pid is not None:
            return (f"<g class='bg-proc' onclick='rvGoProc({int(n.pid)})' role='link' "
                    f"aria-label='{_e(n.label)} {_e(n.sub)} 프로세스 트리로 이동'>{title}{body}</g>")
        return f"<g>{title}{body}</g>"
    # 흔적 노드 — 종류를 모양으로 구분: 파일=접힌 모서리, 레지스트리=각진 상자, 네트워크/DNS=알약
    tx = x + 30
    icon = {"file": "F", "reg": "R", "net": "N", "dns": "D"}.get(n.kind, "")
    if n.kind == "file":
        shape = (f"<path d='M{x} {y:.1f} h{n.w - 10} l10 10 v{n.h - 10} h-{n.w} z' fill='#142136' "
                 f"stroke='{color}' stroke-width='1.4'/>")
    elif n.kind == "reg":
        shape = (f"<rect x='{x}' y='{y:.1f}' width='{n.w}' height='{n.h}' fill='#142136' "
                 f"stroke='{color}' stroke-width='1.4'/>")
    else:
        dash = " stroke-dasharray='4 3'" if n.kind == "dns" else ""
        shape = (f"<rect x='{x}' y='{y:.1f}' width='{n.w}' height='{n.h}' rx='0' fill='#142136' "
                 f"stroke='{color}' stroke-width='1.4'{dash}/>")
    return (f"<g>{title}{shape}"
            f"<text x='{x + 13}' y='{n.y + 4:.1f}' font-size='10.5' font-weight='700' fill='{color}' "
            f"text-anchor='middle' style='fill:{color}'>{icon}</text>"
            f"<text x='{tx - 6}' y='{n.y + 4:.1f}' font-size='11'>{_e(n.label)}</text></g>")


def behavior_graph_html(result, fallback_procs: list = None) -> str:
    """프로세스 체인과 흔적을 한 장으로 — 없으면 빈 문자열."""
    try:
        roots = _build_graph(result, fallback_procs or [])
    except Exception:
        return ""
    if not roots:
        return ""
    W, H = _layout(roots)
    edges, shapes = [], []
    n_proc = n_art = 0

    def walk(n: _N) -> None:
        nonlocal n_proc, n_art
        if n.kind == "proc":
            n_proc += 1
        elif n.kind != "ghost":
            n_art += 1
        shapes.append(_node_svg(n))
        x1 = _PAD + n.x * _COL_W + n.w
        for c in n.children:
            x2 = _PAD + c.x * _COL_W
            mx = (x1 + x2) / 2
            cls = "bg-edge" + ("" if c.kind == "proc" else " bg-edge-art")
            edges.append(f"<path class='{cls}' d='M{x1} {n.y:.1f} C{mx:.0f} {n.y:.1f} {mx:.0f} {c.y:.1f} "
                         f"{x2 - 5} {c.y:.1f}' marker-end='url(#bg-arrow)'/>")
            if c.edge:
                edges.append(f"<text class='bg-el' x='{x2 - 9}' y='{c.y - 8:.1f}' text-anchor='end'>{_e(c.edge)}</text>")
            walk(c)

    for r in roots:
        walk(r)

    legend = "".join(
        f"<span><i style='--c:{c}'></i>{_e(t)}</span>" for t, c, _r in (
            ("샘플·호스트 프로세스", _LEVEL_COLOR["root"], "4px"), ("악성 근거가 있는 프로세스·흔적", C_MAL, "4px"),
            ("의심 흔적", C_SUS, "4px"), ("흔적 없는 프로세스", _LEVEL_COLOR["plain"], "4px"),
            ("F 드롭 파일", "#8ea2bf", "1px"), ("R 레지스트리", "#8ea2bf", "0"),
            ("N 네트워크 · D DNS", "#8ea2bf", "8px")))
    caption = (f"샘플 계보 프로세스 {n_proc}개와 각 프로세스가 남긴 흔적 {n_art}건. 실선은 프로세스 생성, "
               "점선은 파일 드롭·레지스트리 등록·통신입니다. 프로세스 상자를 누르면 프로세스 탭의 해당 행으로 이동하고, "
               "노드에 마우스를 올리면 전체 경로·명령줄이 보입니다. 배경(Tier 3) 활동은 그리지 않습니다.")
    return (
        "<figure class='bg-fig'>"
        f"<div class='bg-scroll'><svg class='bg-svg' viewBox='0 0 {W} {H}' width='{W}' height='{H}' "
        f"role='img' aria-label='행위 그래프: 샘플 계보 프로세스 {n_proc}개와 흔적 {n_art}건'>"
        "<defs><marker id='bg-arrow' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' "
        "orient='auto-start-reverse'><path d='M0 1 L10 5 L0 9 z' fill='#6b83a6'/></marker></defs>"
        + "".join(edges) + "".join(shapes) +
        f"</svg></div><div class='bg-legend'>{legend}</div><figcaption>{_e(caption)}</figcaption></figure>"
    )


# ═════════════════════════════════════════════════════════════════════════════
# 프로세스 트리 행 상세 (ANY.RUN 식 펼침)
# ═════════════════════════════════════════════════════════════════════════════

def proc_detail_html(b, uid: str, limit: int = 12) -> tuple:
    """(버튼 HTML, 상세 패널 HTML) — 행위가 없으면 빈 문자열 쌍."""
    if b is None:
        return "", ""
    groups = (
        ("파일 쓰기", list(getattr(b, "files_written", None) or [])),
        ("파일 삭제", list(getattr(b, "files_deleted", None) or [])),
        ("레지스트리 쓰기", list(getattr(b, "reg_written", None) or [])),
        ("레지스트리 삭제", list(getattr(b, "reg_deleted", None) or [])),
        ("네트워크 연결", [f"{ip}:{port}" for ip, port in (getattr(b, "tcp_conns", None) or [])]),
        ("DNS 질의", list(getattr(b, "dns_queries", None) or [])),
    )
    parts = []
    for title, items in groups:
        if not items:
            continue
        rows = "".join(f"<div>{_e(str(i))}</div>" for i in items[:limit])
        more = f"<div style='color:#8496b0'>… 외 {len(items) - limit}건 (아래 표에서 전체 확인)</div>" if len(items) > limit else ""
        parts.append(f"<h5>{_e(title)} ({len(items)})</h5>{rows}{more}")
    if not parts:
        return "", ""
    btn = (f"<button type='button' class='pt-more' onclick=\"rvToggleDetail(event,'{uid}')\" "
           f"aria-controls='{uid}'>상세</button>")
    return btn, f"<div class='pt-detail' id='{uid}'>{''.join(parts)}</div>"


# ═════════════════════════════════════════════════════════════════════════════
# 구간별 ATT&CK — 기법을 따로 나열하지 않고 근거가 나온 텔레메트리 옆에 둔다
# ═════════════════════════════════════════════════════════════════════════════

import re as _re

_EV_PREFIX_RE = _re.compile(r"^\[([^\]]+)\]\s*")
_IP_RE = _re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_SECTION_TITLE = {"process": "프로세스", "file": "파일", "registry": "레지스트리",
                  "network": "네트워크", "memory": "메모리"}


def _evidence_section(ev: str) -> str:
    """근거 문자열 하나가 어느 텔레메트리에서 나왔는지 — 외부 출처면 빈 문자열."""
    text = str(ev or "")
    m = _EV_PREFIX_RE.match(text)
    if m:
        who = m.group(1).strip().lower()
        # "[프로세스명] 근거" 는 로컬 관측, "[CAPE Sandbox] …" 같은 것은 타 샌드박스 보고
        if not (who.endswith((".exe", ".dll", ".com", ".scr")) or who in ("system", "idle")):
            return ""
        text = text[m.end():]
    low = text.lower()
    if "susp=" in low or "shellcode=" in low or "hooked=" in low or "implanted" in low:
        return "memory"
    if low.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkey_")) or "\\software\\microsoft\\windows\\currentversion\\run" in low:
        return "registry"
    if "command line:" in low or low.startswith("pid:"):
        return "process"
    if _re.match(r"^[a-z]:\\", low) or low.startswith("\\\\"):
        return "file"
    if _IP_RE.search(low) or _re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\s|$)", low):
        return "network"
    return ""


def attack_inline_html(result, section: str, limit: int = 3) -> str:
    """해당 구간(process/file/registry/network/memory)에서 근거가 나온 기법만 보여준다."""
    br = getattr(result, "behavior_report", None)
    rows = []
    for t in (getattr(br, "techniques", None) or []):
        evs = [e for e in (getattr(t, "evidence", None) or []) if _evidence_section(e) == section]
        if not evs:
            continue
        tier = getattr(t, "relevance_tier", 0) or 2
        color = {1: C_MAL, 2: C_SUS}.get(tier, "#5b6f8c")
        tid = getattr(t, "technique_id", "")
        ev_html = "".join(f"<div>{_e(str(e)[:220])}</div>" for e in evs[:limit])
        if len(evs) > limit:
            ev_html += f"<div class='atk-more'>… 외 {len(evs) - limit}건</div>"
        tactic = getattr(t, "tactic", "") or ""
        rows.append((tier, tid,
            f"<div class='atk-row' data-tier='{tier}' style='--c:{color}'>"
            f"<div class='atk-id'><a href='{_attack_url(tid)}' target='_blank' rel='noopener'>{_e(tid)}</a></div>"
            f"<div>{_e(getattr(t, 'technique_name', '') or tid)}</div>"
            f"<div class='atk-tac'>{_e(_TACTIC_KO.get(tactic, tactic))}</div>"
            f"<div class='atk-ev'>{ev_html}</div></div>"))
    if not rows:
        return ""
    rows.sort(key=lambda r: (r[0], r[1]))
    return (f"<div class='atk'><div class='atk-h'>이 {_SECTION_TITLE.get(section, '')} 활동에 해당하는 ATT&amp;CK 기법 "
            f"({len(rows)})</div>{''.join(r[2] for r in rows)}</div>")
