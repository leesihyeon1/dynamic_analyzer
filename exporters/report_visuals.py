"""
report_visuals.py — 리포트 개요 화면의 판정 요약 · 위험 지표 · 행위 그래프

세 가지 상용 샌드박스 리포트의 읽는 방식을 가져왔다.

  * Hybrid Analysis — 판정(악성/의심) + 점수 링 + "악성 / 의심 / 정보성 지표" 목록.
    리포트를 열자마자 "그래서 악성인가, 근거가 뭔가"에 답한다.
  * Joe Sandbox     — 행위 그래프(exporters/behavior_graph.py). 판정 카드에서 이어지는 프로세스 실행
    흐름에 각 프로세스가 남긴 파일·레지스트리·네트워크 흔적을 붙여 한 장의 그림으로 보여준다.
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
.va .va-tag.va-family{color:#ff9b9b;border-color:#ff6b6b;font-weight:700}
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
             "T1486", "T1490", "T1003", "T1056", "T1113", "T1041", "T1048")
# 이번 실행의 텔레메트리가 아니라 다른 곳(타 샌드박스·정적 분석·AI 추론)이 보고한 기법 출처
_EXTERNAL_SOURCES = {"virustotal", "capa", "ai"}
_TID_RE = __import__("re").compile(r"T\d{4}(?:\.\d{3})?")


def is_external_only(t) -> bool:
    """기법의 출처가 전부 외부(VirusTotal·CAPA·AI)면 True — 이번 실행에서 관측된 근거가 없다."""
    srcs = {str(x).strip().lower() for x in (getattr(t, "sources", None) or []) if str(x).strip()}
    return bool(srcs) and srcs <= _EXTERNAL_SOURCES
_EXE_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk")


def _short(s: str, n: int) -> str:
    """가운데 생략 — 경로는 앞(드라이브)과 뒤(파일명)가 둘 다 의미 있다."""
    s = str(s or "")
    if len(s) <= n:
        return s
    keep = n - 1
    head = keep // 3
    return s[:head] + "…" + s[-(keep - head):]


def _norm_path(p) -> str:
    """비교용 경로 정규화 — 대소문자·구분자·\\??\\ 접두를 무시한다."""
    s = str(p or "").strip().strip('"').replace("/", "\\")
    if s.startswith("\\??\\"):
        s = s[4:]
    return os.path.normcase(os.path.normpath(s)) if s else ""


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

    # ── 악성코드 패밀리 (실행 중 남긴 흔적 — analysis.malware_traits) ──
    for fam in ((getattr(result, "malware_traits", None) or {}).get("families") or []):
        add("mal" if fam.get("confidence") == "HIGH" else "sus", "악성코드 패밀리",
            f"{fam['name']} 특징 확인 — 흔적 {fam.get('matched', '?')}/{fam.get('total', '?')}개 일치",
            " · ".join(fam.get("evidence", [])[:3]))

    # ── 주입 탐지 (신뢰도 판정 결과) ──
    low = 0
    for f in (getattr(result, "injection_findings", None) or []):
        conf = f.get("confidence", "")
        line = f"{f.get('name', '?')} (PID {f.get('pid', '?')})"
        if conf == "HIGH":
            add("mal", "프로세스 주입", f"샘플 프로세스에서 코드 주입 탐지 — {line}", f.get("reason", ""), "T1055")
            covered.add("T1055")
        elif conf == "MEDIUM":
            add("sus", "프로세스 주입", f"샘플이 아닌 프로세스에서 PE 교체·주입 탐지 — {line}", f.get("reason", ""), "T1055")
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
    sample = _norm_path(getattr(getattr(result, "config", None), "sample_path", None) or "")

    def _is_drop(f: str) -> bool:
        # 샘플 자신(분석기가 실행한 원본)과 ADS(파일명:스트림)는 "드롭"이 아니다
        tail = f.replace("/", "\\").rsplit("\\", 1)[-1]
        return (f.lower().endswith(_EXE_EXT) and ":" not in tail
                and (not sample or _norm_path(f) != sample))

    drops = [str(f) for f in (getattr(ioc, "dropped_files", None) or [])]
    d1 = [f for f in drops if tiers.get(f, 2) == 1 and _is_drop(f)]
    d2 = [f for f in drops if tiers.get(f, 2) == 2 and _is_drop(f)]
    if d1:
        add("mal", "파일 드롭", f"샘플 프로세스가 실행 파일 {len(d1)}개 생성",
            ", ".join(_short(f, 70) for f in d1[:5]) + (" …" if len(d1) > 5 else ""))
    if d2:
        add("sus", "파일 드롭",
            f"분석 중 실행 파일 {len(d2)}개 생성 (샘플과의 연결 미확인)" if lineage
            else f"분석 중 실행 파일 {len(d2)}개 생성 (어느 프로세스가 만들었는지 미확인)",
            ", ".join(_short(f, 70) for f in d2[:5]) + (" …" if len(d2) > 5 else ""))

    # ── 네트워크 ──
    pcap = getattr(result, "pcap_result", None)
    for s in (getattr(pcap, "smtp_sessions", None) or [])[:3]:
        add("mal", "유출", "SMTP 메일 전송 확인 — 메일로 데이터 유출 가능", f"{s.dst_ip}:{s.dst_port}", "T1048")
    for s in (getattr(pcap, "ftp_sessions", None) or [])[:3]:
        add("mal", "유출", "FTP 전송 확인 — 파일 업로드 가능", f"{s.dst_ip}:{s.dst_port}", "T1048")
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
        add("sus", "C2 통신", f"샘플 프로세스의 외부 통신 {len(lin_conns)}건", ", ".join(lin_conns[:6]))
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
        tactic = getattr(t, "tactic", "") or "기타"
        name = getattr(t, "technique_name", "") or tid
        if is_external_only(t):
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
        add("info", "외부 분석 결과",
            f"{_TACTIC_KO.get(tactic, tactic)} — 이번 실행에서는 확인되지 않고 AI·정적 분석·다른 샌드박스가 보고한 기법 {len(names)}건",
            ", ".join(names[:6]) + (" …" if len(names) > 6 else ""))

    # ── 실행 진단 ──
    v = getattr(br, "execution_verdict", "") if br else ""
    _VTXT = {"CONFIRMED": "실행과 네트워크 활동이 확인됨", "PARTIAL": "실행됐으나 C2 응답 미확인",
             "EVADED": "분석 환경 탐지 후 조기 종료 의심", "FAILED": "샘플 실행 실패 의심"}
    if v in _VTXT:
        add("sus" if v == "EVADED" else "info", "실행 진단", _VTXT[v])
    return out


def score_indicators(inds: list) -> tuple:
    """(점수 0-100, 판정 키, 판정 문구, 색). 지표 개수에 대한 단순 가중합이다."""
    mal = sum(1 for i in inds if i["level"] == "mal")
    sus = sum(1 for i in inds if i["level"] == "sus")
    info = sum(1 for i in inds if i["level"] == "info")
    score = (40 + 15 * (mal - 1) if mal else 0) + min(30, 6 * sus) + min(5, info)
    score = max(0, min(100, score))
    if mal >= 2 or score >= 70:
        return score, "mal", "악성", C_MAL
    if mal == 1 or score >= 30:
        return score, "sus", "의심", C_SUS
    return score, "ok", "위협 미확인", C_OK


def _stat(label: str, big: str, unit: str, segments: list) -> str:
    """숫자 하나 + 구성비 막대(선) + 범례. segments: [(값, 이름, 색)]."""
    total = sum(v for v, _, _ in segments) or 1
    bar = "".join(f"<i style='width:{100 * v / total:.2f}%;background:{c}'></i>" for v, _, c in segments if v > 0)
    leg = "".join(f"<span style='--c:{c}'>{_e(t)} {v}</span>" for v, t, c in segments if t)
    return (f"<div class='va-stat'><div class='va-stat-label'>{_e(label)}</div>"
            f"<b>{_e(big)}<small>{_e(unit)}</small></b><div class='va-bar'>{bar}</div>"
            f"<div class='va-leg'>{leg}</div></div>")


def _attack_url(tid: str) -> str:
    """ATT&CK 기법 페이지 URL. 형식(T1234 / T1234.001)이 아니면 빈 문자열 — 링크를 만들지 않는다.

    AI·외부 소스가 준 ID 가 href 속성을 깨고 나가지 못하게 하는 관문이다.
    """
    tid = str(tid or "").strip()
    if not _TID_RE.fullmatch(tid):
        return ""
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _attack_link(tid: str) -> str:
    """ID 를 ATT&CK 링크로. 형식이 맞지 않으면 이스케이프된 텍스트만."""
    url = _attack_url(tid)
    if not url:
        return _e(str(tid or ""))
    return f"<a href='{_e(url, quote=True)}' target='_blank' rel='noopener'>{_e(str(tid).strip())}</a>"


def _indicator_block(title: str, color: str, items: list, opened: bool) -> str:
    rows = []
    for i in sorted(items, key=lambda x: x["cat"]):
        tid = _attack_link(i["tid"]) if i["tid"] else ""
        ev = f"<span class='va-ev'>{_e(i['ev'])}</span>" if i["ev"] else ""
        rows.append(f"<div class='va-row'><div class='va-cat'>{_e(i['cat'])}</div>"
                    f"<div>{_e(i['title'])}{ev}</div><div class='va-tid'>{tid}</div></div>")
    if not items:
        rows.append("<div class='va-empty'>해당 지표 없음</div>")
    return (f"<details class='va-block' style='--c:{color}'{' open' if opened else ''}>"
            f"<summary>{_e(title)} <span class='va-count'>{len(items)}</span></summary>"
            f"{''.join(rows)}</details>")


def report_verdict(result) -> dict:
    """판정 요약·헤더·JSON 이 같은 값을 쓰도록 한 번만 계산한다.

    {level: mal|sus|ok, label, score, color, indicators}
    """
    try:
        inds = build_indicators(result)
    except Exception:
        inds = []
    score, key, label, color = score_indicators(inds)
    return {"level": key, "label": label, "score": score, "color": color, "indicators": inds}


def _technique_split(result) -> tuple:
    """(계보, 의심, 배경, 외부) — 외부 출처만 있는 기법은 등급과 무관하게 '외부'로 센다."""
    br = getattr(result, "behavior_report", None)
    techs = getattr(br, "techniques", None) or []
    if not techs:
        counts = (getattr(result, "relevance_counts", {}) or {}).get("techniques") or {}
        return tuple(int(counts.get(k, counts.get(str(k), 0)) or 0) for k in (1, 2, 3)) + (0,)
    c = {1: 0, 2: 0, 3: 0, "ext": 0}
    for t in techs:
        if is_external_only(t):
            c["ext"] += 1
            continue
        tier = getattr(t, "relevance_tier", 0) or 2
        c[tier if tier in (1, 2, 3) else 2] += 1
    return c[1], c[2], c[3], c["ext"]


def verdict_overview_html(result, sample_name: str, sample_sha256: str = "", verdict: dict = None) -> str:
    """개요 탭 최상단 — 판정, 점수 링, 지표 목록.

    verdict: report_verdict(result) 결과를 넘기면 다시 계산하지 않는다 (헤더와 같은 값 보장).
    """
    v = verdict or report_verdict(result)
    inds = v["indicators"]
    score, verdict, vcolor = v["score"], v["label"], v["color"]
    mal = [i for i in inds if i["level"] == "mal"]
    sus = [i for i in inds if i["level"] == "sus"]
    info = [i for i in inds if i["level"] == "info"]

    counts = getattr(result, "relevance_counts", {}) or {}

    def _tc(kind):
        d = counts.get(kind) or {}
        return tuple(int(d.get(k, d.get(str(k), 0)) or 0) for k in (1, 2, 3))

    p1, p2, p3 = _tc("processes")
    t1, t2, t3, tx = _technique_split(result)
    _BG = "#5b6f8c"
    rings = [
        _stat("위협 점수", str(score), "/ 100", [(score, "", vcolor), (100 - score, "", C_MUTE)]),
        _stat("탐지 근거", str(len(inds)), "건",
              [(len(mal), "악성", C_MAL), (len(sus), "의심", C_SUS), (len(info), "정보", C_INFO)]),
        _stat("새 프로세스", str(p1 + p2 + p3), "개", [(p1, "샘플", C_MAL), (p2, "의심", C_SUS), (p3, "평상시", _BG)]),
        _stat("ATT&CK 기법", str(t1 + t2 + t3 + tx), "건",
              [(t1, "샘플", C_MAL), (t2, "의심", C_SUS), (t3, "평상시", _BG), (tx, "외부 분석", C_INFO)]),
    ]

    ext = os.path.splitext(sample_name)[1].lower().lstrip(".")
    tags = "".join(f"<span class='va-tag'>{_e(t)}</span>" for t in (
        [ext.upper()] if ext else []) + (["스크립트"] if ext in ("js", "jse", "vbs", "vbe", "wsf", "hta", "ps1")
                                         else ["문서"] if ext in ("doc", "docx", "docm", "xls", "xlsx", "xlsm", "rtf", "pdf")
                                         else ["실행 파일"] if ext in ("exe", "dll", "scr") else []))
    fams = [f["name"] for f in ((getattr(result, "malware_traits", None) or {}).get("families") or [])
            if f.get("confidence") == "HIGH"]
    tags += "".join(f"<span class='va-tag va-family'>{_e(f)}</span>" for f in fams)
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
        + _indicator_block("악성 근거", C_MAL, mal, len(mal) <= 3)
        + _indicator_block("의심 근거", C_SUS, sus, len(sus) <= 3)
        + _indicator_block("참고 정보", C_INFO, info, False)
        + "</div></section>"
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
    # "DNS: x", "SNI=…", "비콘 …", "고엔트로피 도메인: …" 형식 근거도 네트워크 텔레메트리다
    if low.startswith(("dns:", "dns ", "sni=", "sni:", "tls sni", "비콘", "beacon", "고엔트로피 도메인",
                       "http ", "http:", "smtp", "ftp")):
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
            f"<div class='atk-id'>{_attack_link(tid)}</div>"
            f"<div>{_e(getattr(t, 'technique_name', '') or tid)}</div>"
            f"<div class='atk-tac'>{_e(_TACTIC_KO.get(tactic, tactic))}</div>"
            f"<div class='atk-ev'>{ev_html}</div></div>"))
    if not rows:
        return ""
    rows.sort(key=lambda r: (r[0], r[1]))
    return (f"<div class='atk'><div class='atk-h'>이 {_SECTION_TITLE.get(section, '')} 활동에 해당하는 ATT&amp;CK 기법 "
            f"({len(rows)})</div>{''.join(r[2] for r in rows)}</div>")
