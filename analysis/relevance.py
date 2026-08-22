"""
relevance.py — 관측 항목의 샘플 관련도 3단계 등급

동적 분석은 샘플 행위와 환경 배경 활동을 구분하지 않고 전부 수집한다.
Windows Update 하나가 돌면 프로세스 80개·드롭 파일 170개·HTTP 75건이
리포트에 들어와 정작 샘플이 남긴 두어 개 아티팩트를 덮어버린다.

이 모듈은 **아무것도 버리지 않고** 항목마다 등급만 부여한다.
포렌식 도구에서 "그 이벤트가 왜 없죠?" 는 치명적이므로, 리포트는 등급에
따라 접기만 하고 데이터는 항상 보존한다.

등급
    TIER_SAMPLE (1)      샘플 계보 — 샘플과 그 자손이 직접 만든 것. 기본 펼침
    TIER_CORRELATED (2)  상관 의심 — 계보 밖이지만 배경으로 설명되지 않는 것. 접힘
    TIER_BACKGROUND (3)  환경 배경 — 베이스라인/알려진 OS 활동. 기본 숨김

판정 순서가 중요하다. 계보(Tier 1)를 먼저 확정하고, 배경으로 설명되는
것(Tier 3)을 걸러낸 뒤, **남는 것은 전부 Tier 2** 로 둔다.
"모르면 배경" 이 아니라 "모르면 의심" 이어야 놓치지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from core.baseline import Baseline, normalize_domain, normalize_path


TIER_SAMPLE     = 1
TIER_CORRELATED = 2
TIER_BACKGROUND = 3

TIER_LABELS: dict[int, str] = {
    TIER_SAMPLE:     "샘플 계보",
    TIER_CORRELATED: "상관 의심",
    TIER_BACKGROUND: "환경 배경",
}

TIER_DESCRIPTIONS: dict[int, str] = {
    TIER_SAMPLE:     "샘플 프로세스와 그 자손이 직접 발생시킨 행위",
    TIER_CORRELATED: "샘플 계보 밖이지만 환경 배경으로 설명되지 않는 행위 — 주입·측면 이동 가능성",
    TIER_BACKGROUND: "베이스라인 또는 알려진 OS 배경 활동(Windows Update·Defender·텔레메트리)",
}


# ── 알려진 OS 배경 활동 프로파일 ─────────────────────────────────────────────
# 베이스라인이 없을 때의 폴백. 베이스라인이 있으면 그쪽이 훨씬 정확하다.

OS_BACKGROUND_PROCS: frozenset[str] = frozenset({
    # 콘솔 · 작업 인프라
    "conhost.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe",
    "backgroundtaskhost.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchapp.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
    "useroobebroker.exe", "smartscreen.exe", "wmiprvse.exe", "mofcomp.exe",
    # Windows Update · 서비스
    "wuauclt.exe", "usoclient.exe", "tiworker.exe", "trustedinstaller.exe",
    "sppsvc.exe", "wevtutil.exe", "compattelrunner.exe", "tieringengineservice.exe",
    "updateplatform.amd64fre.exe", "updateplatform.x86fre.exe",
    # Defender
    "msmpeng.exe", "mpcmdrun.exe", "mpsigstub.exe", "mpdefendercoreservice.exe",
    "mprecovery.exe", "nissrv.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe",
    # 텔레메트리
    "diagtrack.exe", "dmclient.exe",
    # Edge / 패키지 자동 업데이트
    "microsoftedgeupdate.exe", "microsoftedgeupdatecore.exe",
    "windowspackagemanagerserver.exe", "winget.exe", "msedge.exe",
    # VM 게스트 도구 (분석 VM 자체의 배경 활동)
    "vmtoolsd.exe", "vmwareresolutionset.exe", "vmwaretray.exe",
    "vmwareuser.exe", "vm3dservice.exe", "vgauthservice.exe",
    "vmacthlp.exe", "internet_detector.exe",
})
# 주의: telemetrydispatcher.exe 는 여기 넣지 않는다.
# 이번 샘플(purple.exe)이 정상 Windows 구성요소를 사칭해
# C:\ProgramData\TelemetryDispatcher\TelemetryDispatcher.exe 를 드롭했다.
# 이름만 보고 배경으로 강등하면 정확히 그 사칭에 속는 셈이 된다.

OS_BACKGROUND_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com",
    "do.dsp.mp.microsoft.com", "events.data.microsoft.com",
    "msftconnecttest.com", "msftncsi.com", "microsoft.com", "windows.com",
    "windows.net", "msedge.net", "office.com", "office.net", "live.com",
    "digicert.com", "verisign.com", "globalsign.com", "sectigo.com",
    "entrust.net", "letsencrypt.org",
)

OS_BACKGROUND_PATH_FRAGMENTS: tuple[str, ...] = (
    r"\windows\softwaredistribution",
    r"\windows\winsxs",
    r"\windows\servicing",
    r"\windows\system32\catroot",
    r"\programdata\microsoft\windows defender",
    r"\programdata\microsoft\network",
    r"\appdata\local\microsoft\windows\explorer",
    r"\appdata\local\microsoft\windows\inetcache",
    r"\appdata\local\microsoft\windows\webcache",
    r"\appdata\local\packages",
    r"\appdata\local\microsoft\edge",
    r"\appdata\local\connecteddevicesplatform",
)

# 분석 도구가 남기는 흔적
_ANALYSIS_ARTIFACT_FRAGMENTS: tuple[str, ...] = (
    "procmon", "pe-sieve", "pe_sieve", "hollows_hunter", "hollows-hunter",
    "systeminformer", "processhacker", "tshark", "dumpcap", "wireshark",
)


def _is_os_background_domain(domain: str) -> bool:
    d = normalize_domain(domain)
    if not d:
        return False
    return any(d == s or d.endswith("." + s) for s in OS_BACKGROUND_DOMAIN_SUFFIXES)


def _is_os_background_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(frag in p for frag in OS_BACKGROUND_PATH_FRAGMENTS)


def _is_analysis_artifact(path_or_name: str) -> bool:
    s = (path_or_name or "").lower()
    return any(frag in s for frag in _ANALYSIS_ARTIFACT_FRAGMENTS)


# ── 판정 컨텍스트 ────────────────────────────────────────────────────────────

@dataclass
class RelevanceContext:
    """한 번의 분석 결과에서 뽑아낸 등급 판정 기준."""

    lineage_pids:     set = field(default_factory=set)   # 샘플 + 실제 자손
    injected_pids:    set = field(default_factory=set)   # HH/pe-sieve 주입 탐지 (오탐 다수)
    lineage_names:    set = field(default_factory=set)   # 계보 프로세스 이름 (소문자)
    lineage_paths:    set = field(default_factory=set)   # 계보가 만든 파일 (정규화)
    lineage_endpoints:set = field(default_factory=set)   # 계보가 접촉한 "ip:port"
    lineage_ips:      set = field(default_factory=set)
    lineage_domains:  set = field(default_factory=set)
    # 목적지 IP → 그 연결을 만든 프로세스 이름 집합 (process_network_map 기준).
    # 도메인이 없는 IP 직결은 소유 프로세스로만 배경 여부를 가릴 수 있다.
    ip_owners:        dict = field(default_factory=dict)
    sample_name:      str = ""
    baseline: Optional[Baseline] = None

    @property
    def has_lineage(self) -> bool:
        return bool(self.lineage_pids)

    @property
    def has_baseline(self) -> bool:
        return self.baseline is not None


def build_context(result, baseline: Optional[Baseline] = None) -> RelevanceContext:
    """AnalysisResult → RelevanceContext."""
    ctx = RelevanceContext(
        lineage_pids  = set(getattr(result, "lineage_pids", None) or set()),
        injected_pids = set(getattr(result, "injected_pids", None) or set()),
        baseline      = baseline,
    )

    cfg = getattr(result, "config", None)
    sp  = getattr(cfg, "sample_path", None) if cfg else None
    if sp is not None:
        ctx.sample_name = str(getattr(sp, "name", "")).lower()

    # 계보 프로세스 이름
    for p in (getattr(result, "process_diff", {}) or {}).get("new_processes", []):
        if getattr(p, "pid", None) in ctx.lineage_pids:
            nm = (getattr(p, "name", "") or "").lower()
            if nm:
                ctx.lineage_names.add(nm)
            exe = getattr(p, "exe", "") or ""
            if exe:
                ctx.lineage_paths.add(normalize_path(exe))
    if ctx.sample_name:
        ctx.lineage_names.add(ctx.sample_name)

    # 네트워크 엔드포인트 귀속 — process_network_map 기준
    for m in (getattr(result, "process_network_map", None) or []):
        _get = (lambda k, d=None: m.get(k, d)) if isinstance(m, dict) else (
            lambda k, d=None: getattr(m, k, d))
        pid   = _get("pid")
        ip    = _get("remote_ip", "") or ""
        port  = _get("remote_port", 0) or 0
        pname = (_get("process", "") or "").lower()
        if not ip:
            continue
        if pname:
            ctx.ip_owners.setdefault(ip, set()).add(pname)
        if pid in ctx.lineage_pids:
            ctx.lineage_ips.add(ip)
            if port:
                ctx.lineage_endpoints.add(f"{ip}:{port}")

    # 계보 프로세스가 만든 파일 — filtered_events 의 쓰기/생성 이벤트
    for ev in (getattr(result, "filtered_events", None) or []):
        try:
            if getattr(ev, "pid", None) not in ctx.lineage_pids:
                continue
            if getattr(ev, "operation", "") not in ("WriteFile", "CreateFile", "SetRenameInformationFile"):
                continue
            path = getattr(ev, "path", "")
            if path:
                ctx.lineage_paths.add(normalize_path(path))
        except Exception:
            continue

    return ctx


# ── 항목별 등급 판정 ─────────────────────────────────────────────────────────

def _is_background_process_name(name: str, ctx: RelevanceContext) -> bool:
    """프로세스 이름이 환경 배경(또는 분석 도구)인지."""
    n = (name or "").lower()
    if not n:
        return False
    if n in ctx.lineage_names:
        return False
    if _is_analysis_artifact(n):
        return True
    if ctx.baseline is not None and ctx.baseline.has_process(n):
        return True
    return n in OS_BACKGROUND_PROCS


def tier_process(proc, ctx: RelevanceContext) -> int:
    """ProcessSnapshot → 등급."""
    pid  = getattr(proc, "pid", None)
    name = (getattr(proc, "name", "") or "").lower()
    exe  = getattr(proc, "exe", "") or ""

    # Tier 1 — 샘플 계보
    if pid is not None and pid in ctx.lineage_pids:
        return TIER_SAMPLE
    if ctx.sample_name and name == ctx.sample_name:
        return TIER_SAMPLE
    # 계보가 드롭한 실행 파일이 실행됐다면 계보로 본다 (프로세스 생성 이벤트 누락 대비)
    if exe and normalize_path(exe) in ctx.lineage_paths:
        return TIER_SAMPLE

    # 분석 도구 자신은 배경
    if _is_analysis_artifact(name) or _is_analysis_artifact(exe):
        return TIER_BACKGROUND

    # Tier 3 — 베이스라인 / 알려진 OS 배경
    if ctx.baseline is not None:
        if ctx.baseline.has_exe(exe) or ctx.baseline.has_process(name):
            return TIER_BACKGROUND
    elif name in OS_BACKGROUND_PROCS or _is_os_background_path(exe):
        return TIER_BACKGROUND

    # Tier 2 — 배경으로 설명되지 않음. 주입 탐지 PID 도 여기(오탐 비중이 높아
    # Tier 1 로 올리지 않지만, 놓치면 안 되므로 배경으로도 내리지 않는다).
    return TIER_CORRELATED


def tier_file(path: str, ctx: RelevanceContext) -> int:
    """드롭 파일 경로 → 등급."""
    if not path:
        return TIER_CORRELATED
    norm = normalize_path(path)

    if norm in ctx.lineage_paths:
        return TIER_SAMPLE
    if _is_analysis_artifact(path):
        return TIER_BACKGROUND
    if ctx.baseline is not None:
        if ctx.baseline.has_file(path):
            return TIER_BACKGROUND
    elif _is_os_background_path(path):
        return TIER_BACKGROUND
    return TIER_CORRELATED


def tier_endpoint(ip: str, port: int = 0, domain: str = "", *,
                  ctx: RelevanceContext) -> int:
    """네트워크 목적지 → 등급."""
    if ip and port and f"{ip}:{port}" in ctx.lineage_endpoints:
        return TIER_SAMPLE
    if ip and ip in ctx.lineage_ips:
        return TIER_SAMPLE
    if domain and normalize_domain(domain) in ctx.lineage_domains:
        return TIER_SAMPLE

    if ctx.baseline is not None:
        if domain and ctx.baseline.has_domain(domain):
            return TIER_BACKGROUND
        if ip and ctx.baseline.has_endpoint(ip, port):
            return TIER_BACKGROUND

    # 알려진 MS 인프라 도메인 (베이스라인 유무와 무관)
    if domain and _is_os_background_domain(domain):
        return TIER_BACKGROUND

    # 도메인이 없는 IP 직결은 소유 프로세스로 판정한다.
    # 이게 없으면 svchost·Defender 의 IP 직결이 전부 '의심'으로 쌓여
    # 진짜 C2 가 수백 건 사이에 묻힌다.
    owners = ctx.ip_owners.get(ip) if ip else None
    if owners:
        # 계보 프로세스가 하나라도 접촉했으면 계보로 승격
        if owners & ctx.lineage_names:
            return TIER_SAMPLE
        if all(_is_background_process_name(o, ctx) for o in owners):
            return TIER_BACKGROUND

    return TIER_CORRELATED


def tier_dns(query, ctx: RelevanceContext) -> int:
    name = getattr(query, "name", "") if not isinstance(query, dict) else query.get("name", "")
    return tier_endpoint("", 0, name, ctx=ctx)


def evidence_tier(ev: str, ctx: RelevanceContext) -> int:
    """근거 문자열 하나의 등급. ``[프로세스명]`` 접두로 판정한다."""
    m = re.match(r"^\[([^\]]+)\]", str(ev))
    if not m:
        # 프로세스 귀속이 없는 근거(CAPA·VT·네트워크) — 판단 보류
        return TIER_CORRELATED
    pname = m.group(1).lower()
    if pname in ctx.lineage_names:
        return TIER_SAMPLE
    if _is_analysis_artifact(pname):
        return TIER_BACKGROUND
    if ctx.baseline is not None and ctx.baseline.has_process(pname):
        return TIER_BACKGROUND
    if ctx.baseline is None and pname in OS_BACKGROUND_PROCS:
        return TIER_BACKGROUND
    return TIER_CORRELATED


def sort_evidence(tech, ctx: RelevanceContext) -> None:
    """기법 근거를 관련도 순으로 재정렬한다 (원본 리스트 제자리 수정).

    리포트는 근거를 앞에서 5건만 보여주므로, 정렬해두지 않으면 Tier 1
    기법인데도 화면에는 배경 프로세스 근거만 뜨는 일이 생긴다.
    삭제하지 않고 순서만 바꾼다 — 전체 근거는 JSON 에 그대로 남는다.
    """
    evidence = getattr(tech, "evidence", None)
    if not evidence:
        return
    try:
        evidence.sort(key=lambda e: evidence_tier(e, ctx))
    except Exception:
        pass


def tier_technique(tech, ctx: RelevanceContext) -> int:
    """MitreTechnique → 등급.

    근거(evidence)에 붙은 ``[프로세스명]`` 접두를 보고 판정한다.
    계보 프로세스 근거가 하나라도 있으면 Tier 1, 전부 배경이면 Tier 3.
    """
    evidence = getattr(tech, "evidence", None)
    if evidence is None and isinstance(tech, dict):
        evidence = tech.get("evidence", [])
    evidence = evidence or []

    tiers: list[int] = []
    for ev in evidence:
        m = re.match(r"^\[([^\]]+)\]", str(ev))
        if not m:
            # 프로세스 귀속이 없는 근거(CAPA·VT·네트워크 등)는 판단 보류
            continue
        pname = m.group(1).lower()
        if pname in ctx.lineage_names:
            tiers.append(TIER_SAMPLE)
        elif _is_analysis_artifact(pname):
            tiers.append(TIER_BACKGROUND)
        elif ctx.baseline is not None and ctx.baseline.has_process(pname):
            tiers.append(TIER_BACKGROUND)
        elif ctx.baseline is None and pname in OS_BACKGROUND_PROCS:
            tiers.append(TIER_BACKGROUND)
        else:
            tiers.append(TIER_CORRELATED)

    if not tiers:
        # 귀속 불가 — 정적 분석(CAPA)·VT·네트워크 유래. 버리지 않고 상관 의심으로.
        return TIER_CORRELATED
    return min(tiers)


def filter_evidence_by_tier(tech, ctx: RelevanceContext, max_tier: int = TIER_CORRELATED) -> list:
    """기법 근거 중 지정 등급 이하만 남긴 리스트를 반환한다 (원본 불변)."""
    evidence = getattr(tech, "evidence", None) or []
    kept = []
    for ev in evidence:
        m = re.match(r"^\[([^\]]+)\]", str(ev))
        if not m:
            kept.append(ev)
            continue
        pname = m.group(1).lower()
        if _is_analysis_artifact(pname):
            continue
        if pname in ctx.lineage_names:
            kept.append(ev)
        elif ctx.baseline is not None and ctx.baseline.has_process(pname):
            if max_tier >= TIER_BACKGROUND:
                kept.append(ev)
        elif ctx.baseline is None and pname in OS_BACKGROUND_PROCS:
            if max_tier >= TIER_BACKGROUND:
                kept.append(ev)
        elif max_tier >= TIER_CORRELATED:
            kept.append(ev)
    return kept


# ── 결과 주석 달기 ───────────────────────────────────────────────────────────

def annotate(result, ctx: RelevanceContext) -> dict:
    """AnalysisResult 의 각 항목에 ``relevance_tier`` 속성을 부여한다.

    항목을 제거하지 않는다. 리포트가 등급에 따라 접을 뿐이다.

    Returns
    -------
    dict
        등급별 집계 — 리포트 헤더와 콘솔 요약에 사용.
    """
    counts: dict[str, dict[int, int]] = {}

    def _bump(kind: str, tier: int) -> None:
        counts.setdefault(kind, {TIER_SAMPLE: 0, TIER_CORRELATED: 0, TIER_BACKGROUND: 0})
        counts[kind][tier] += 1

    # 프로세스
    for p in (getattr(result, "process_diff", {}) or {}).get("new_processes", []):
        try:
            t = tier_process(p, ctx)
            p.relevance_tier = t
            _bump("processes", t)
        except Exception:
            continue

    # 드롭 파일
    iocs = getattr(result, "ioc_report", None)
    if iocs is not None:
        tiers = {}
        for f in (getattr(iocs, "dropped_files", []) or []):
            try:
                path = f if isinstance(f, str) else getattr(f, "path", "")
                t = tier_file(path, ctx)
                tiers[path] = t
                _bump("dropped_files", t)
            except Exception:
                continue
        try:
            iocs.dropped_file_tiers = tiers
        except Exception:
            pass

    # 네트워크
    # ip_to_domain 은 IP 하나에 도메인 "리스트" 가 매달린 구조다 (중복 포함).
    pcap = getattr(result, "pcap_result", None)
    if pcap is not None:
        ip_map = getattr(pcap, "ip_to_domain", {}) or {}

        for c in (getattr(pcap, "connections", []) or []):
            try:
                ip     = getattr(c, "dst_ip", "")
                port   = getattr(c, "dst_port", 0)
                domain = ip_map.get(ip, "") if isinstance(ip_map, dict) else ""
                t = tier_endpoint(ip, port, domain, ctx=ctx)
                c.relevance_tier = t
                _bump("connections", t)
            except Exception:
                continue

        for q in (getattr(pcap, "dns_queries", []) or []):
            try:
                t = tier_dns(q, ctx)
                q.relevance_tier = t
                _bump("dns_queries", t)
            except Exception:
                continue

        for h in (getattr(pcap, "http_requests", []) or []):
            try:
                t = tier_endpoint("", 0, getattr(h, "host", ""), ctx=ctx)
                h.relevance_tier = t
                _bump("http_requests", t)
            except Exception:
                continue

    # MITRE 기법
    br = getattr(result, "behavior_report", None)
    if br is not None:
        for tech in (getattr(br, "techniques", []) or []):
            try:
                t = tier_technique(tech, ctx)
                tech.relevance_tier = t
                # 리포트가 근거를 앞 5건만 보여주므로 계보 근거를 앞으로 당긴다
                sort_evidence(tech, ctx)
                _bump("techniques", t)
            except Exception:
                continue

    return counts


# ── 주입 탐지 신뢰도 판정 ────────────────────────────────────────────────────
# hollows-hunter / pe-sieve 는 정상 프로세스를 자주 오탐한다.
# 대표 사례가 .NET JIT 이 만든 RX 메모리와 ASLR 재배치 영역인데, 둘 다
# "쉘코드(implanted_shc)" 로 잡히고 PE 교체(replaced/implanted_pe)는 0 이다.
# 반대로 진짜 프로세스 할로잉·PE 주입은 replaced/implanted_pe 가 붙는다.
# 이 비대칭이 베이스라인 없이도 쓸 수 있는 1차 판별 기준이다.

# JIT/재배치 오탐이 특히 잦은 프로세스
_JIT_FP_PRONE: frozenset[str] = frozenset({
    "dwm.exe", "explorer.exe", "searchapp.exe", "searchui.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "runtimebroker.exe", "svchost.exe", "taskhostw.exe", "sihost.exe",
    "textinputhost.exe", "applicationframehost.exe", "systemsettings.exe",
    "tieringengineservice.exe", "msedge.exe", "widgets.exe",
    "phoneexperiencehost.exe", "lockapp.exe", "wmiprvse.exe",
})


def classify_injections(result, ctx: RelevanceContext) -> list:
    """hollows-hunter / pe-sieve 탐지에 신뢰도를 매긴다.

    HIGH   샘플 계보 프로세스에서 탐지 — 실제 주입으로 볼 근거가 있음
    MEDIUM 계보 밖이지만 PE 교체/주입 동반 — 확인 필요
    LOW    쉘코드만, JIT 오탐 잦은 프로세스, 또는 베이스라인에서도 탐지됨

    항목을 지우지 않는다. 등급만 매겨 리포트·프롬프트가 다르게 다루게 한다.
    """
    out: list = []
    seen: set = set()

    def _add(r, source: str) -> None:
        pid = getattr(r, "pid", 0)
        if pid in seen:
            return
        seen.add(pid)

        name = (getattr(r, "name", "") or "").lower()
        if _is_analysis_artifact(name):
            return                      # 분석 도구 자기 탐지 제외

        shc      = int(getattr(r, "implanted_shc", 0) or 0)
        pe_inj   = int(getattr(r, "implanted_pe", 0) or 0)
        replaced = int(getattr(r, "replaced", 0) or 0)
        hooked   = int(getattr(r, "hooked", 0) or 0)

        in_lineage  = pid in ctx.lineage_pids
        baseline_fp = bool(ctx.baseline is not None and ctx.baseline.has_injection_fp(name))
        strong_type = (replaced > 0 or pe_inj > 0)   # PE 교체/주입 = 진짜 신호
        jit_prone   = name in _JIT_FP_PRONE

        if in_lineage:
            conf, why = "HIGH", "샘플 계보 프로세스"
        elif baseline_fp:
            conf, why = "LOW", "베이스라인에서도 동일 탐지 (환경 상시 오탐)"
        elif strong_type:
            conf, why = "MEDIUM", "PE 교체/주입 동반 — 확인 필요"
        elif jit_prone and shc > 0:
            conf, why = "LOW", ".NET JIT·ASLR 재배치 오탐 가능성 높음 (쉘코드만 탐지)"
        elif shc > 0:
            conf, why = "MEDIUM", "쉘코드만 탐지 — 확인 필요"
        else:
            conf, why = "LOW", "약한 신호"

        out.append({
            "pid": pid, "name": getattr(r, "name", "") or "?",
            "source": source,
            "implanted_shc": shc, "implanted_pe": pe_inj,
            "replaced": replaced, "hooked": hooked,
            "in_lineage": in_lineage, "baseline_fp": baseline_fp,
            "confidence": conf, "reason": why,
        })

    hh = getattr(result, "hh_result", None)
    if hh is not None and not getattr(hh, "error", ""):
        for r in (getattr(hh, "process_results", []) or []):
            if getattr(r, "suspicious", 0) > 0:
                _add(r, "hollows-hunter")
    for r in (getattr(result, "pe_sieve_results", []) or []):
        if not getattr(r, "error", "") and getattr(r, "suspicious", 0) > 0:
            _add(r, "pe-sieve")

    _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda d: (_order.get(d["confidence"], 3), d["name"].lower()))
    return out


def summarize_counts(counts: dict) -> str:
    """콘솔 한 줄 요약."""
    parts = []
    labels = {
        "processes": "프로세스", "dropped_files": "드롭파일",
        "connections": "커넥션", "dns_queries": "DNS",
        "http_requests": "HTTP", "techniques": "MITRE",
    }
    for kind, label in labels.items():
        c = counts.get(kind)
        if not c:
            continue
        parts.append(
            f"{label} {c[TIER_SAMPLE]}/{c[TIER_CORRELATED]}/{c[TIER_BACKGROUND]}"
        )
    return " · ".join(parts)
