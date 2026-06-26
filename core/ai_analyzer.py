"""
ai_analyzer.py — Ollama 기반 행위 중심 AI 위협 분석

동적 분석 결과(프로세스·파일·레지스트리·네트워크·MITRE ATT&CK)를
행위 중심 프롬프트로 변환해 Ollama에 전송하고, 위협 분석 텍스트를 반환합니다.

사용:
    from core.ai_analyzer import OllamaAnalyzer
    az = OllamaAnalyzer()
    if az.is_available():
        ai_result = az.analyze(result)
"""
from __future__ import annotations

import json
import re as _re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path


OLLAMA_BASE_URL  = "http://localhost:11434"
DEFAULT_MODEL    = "qwen2.5:7b"
# qwen2.5:7b num_ctx=8192, num_predict=1024 → 입력 여유 ~7168 토큰
# 한국어 평균 1.3 chars/token → 안전 상한 약 10,000 자
_MAX_PROMPT_CHARS = 10_000


# ── 결과 ─────────────────────────────────────────────────────────────────────

@dataclass
class AiAnalysisResult:
    model:             str   = DEFAULT_MODEL
    response:          str   = ""    # Ollama 응답 원문 (마크다운)
    elapsed_sec:       float = 0.0
    prompt_chars:      int   = 0
    error:             str   = ""
    mitre_techniques:  list  = field(default_factory=list)  # 파싱된 MITRE 기법 [{id,name,tactic,evidence}]


# ── Ollama 가용성 확인 ────────────────────────────────────────────────────────

def _is_ollama_running(base_url: str, timeout: int = 4) -> bool:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def detect_model(base_url: str, timeout: int = 4) -> Optional[str]:
    """현재 Ollama에 로드된 모델을 자동 감지한다.

    1) /api/ps  → 메모리에 올라와 있는(실행 중인) 모델 우선
    2) /api/tags → 설치된 모델 목록의 첫 번째
    둘 다 없으면 None 반환.
    """
    # 1. 현재 실행 중인 모델 (/api/ps, Ollama 0.1.33+)
    try:
        req = urllib.request.Request(f"{base_url}/api/ps", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        models = data.get("models", [])
        if models:
            return models[0].get("name", "")
    except Exception:
        pass

    # 2. 설치된 모델 목록의 첫 번째
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        models = data.get("models", [])
        if models:
            return models[0].get("name", "")
    except Exception:
        pass

    return None


def _is_model_available(base_url: str, model: str, timeout: int = 4) -> bool:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        names = [m.get("name", "") for m in data.get("models", [])]
        model_base = model.split(":")[0]
        return any(model_base in n for n in names)
    except Exception:
        return False


# ── 내부 유틸 ────────────────────────────────────────────────────────────────

def _trunc(s: str, n: int) -> str:
    s = str(s)
    return s[:n] + "…" if len(s) > n else s


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n/1_048_576:.1f}MB"
    if n >= 1024:
        return f"{n/1024:.1f}KB"
    return f"{n}B"


def _is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or a == 127)
    except Exception:
        return False


_RENAME_DEST_RE = _re.compile(r'FileName:\s*([^,\r\n]+)', _re.IGNORECASE)


# ── 태그 사전 계산 ────────────────────────────────────────────────────────────

_IP_CHECK_DOMAINS = frozenset({
    "ip-api.com", "ipify.org", "api.ipify.org", "checkip.amazonaws.com",
    "ipinfo.io", "myexternalip.com", "wtfismyip.com", "icanhazip.com",
    "ipecho.net", "ifconfig.me", "api.myip.com",
})

_MINING_POOL_DOMAINS = frozenset({
    "pool.hashvault.pro", "pool.minexmr.com", "xmrpool.eu", "supportxmr.com",
    "gulf.moneroocean.stream", "mine.xmrpool.net", "moneropool.com",
    "nanopool.org", "2miners.com", "ethermine.org", "f2pool.com",
    "antpool.com", "nicehash.com", "pool.bitcoin.com",
    "xmr.pool.minergate.com", "xmr-eu1.nanopool.org", "xmr-eu2.nanopool.org",
    "xmr-us-east1.nanopool.org", "monero.herominers.com",
})

_DOMAIN_THREAT_LABELS: dict = {
    "pool.hashvault.pro":          "★Monero 채굴 풀 (XMRig)★",
    "pool.minexmr.com":            "★Monero 채굴 풀★",
    "supportxmr.com":              "★Monero 채굴 풀★",
    "xmrpool.eu":                  "★XMR 채굴 풀★",
    "gulf.moneroocean.stream":     "★Monero 채굴 풀★",
    "mine.xmrpool.net":            "★XMR 채굴 풀★",
    "moneropool.com":              "★Monero 채굴 풀★",
    "nanopool.org":                "★채굴 풀★",
    "xmr.pool.minergate.com":      "★Monero 채굴 풀★",
    "nicehash.com":                "★채굴 브로커★",
    "ethermine.org":               "★ETH 채굴 풀★",
    "monero.herominers.com":       "★Monero 채굴 풀★",
}

_STEALER_IDS = frozenset({
    "T1056", "T1539", "T1555", "T1552", "T1114", "T1113",
})
_EVASION_IDS = frozenset({
    "T1497", "T1562", "T1036", "T1027", "T1070", "T1112",
})
_INJECT_IDS = frozenset({
    "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.011", "T1055.012",
})
_PERSIST_IDS = frozenset({
    "T1053", "T1547", "T1574", "T1543", "T1546", "T1505",
})
_EXFIL_IDS = frozenset({
    "T1041", "T1048", "T1011", "T1020",
})


def _compute_tags(result) -> list[tuple[str, str]]:
    """분석 결과에서 태그(tag, 근거) 목록을 사전 계산한다."""
    tags: list[tuple[str, str]] = []
    technique_ids: set[str] = set()

    br = result.behavior_report
    if br and getattr(br, "techniques", None):
        for t in br.techniques:
            tid = t.technique_id.split(".")[0]
            technique_ids.add(t.technique_id)
            technique_ids.add(tid)

    # 실행 파일 언어/런타임 (프로세스명 기반)
    new_procs = (result.process_diff or {}).get("new_processes", [])
    proc_names = {getattr(p, "name", "").lower() for p in new_procs}
    if any(n in proc_names for n in ("wscript.exe", "cscript.exe")):
        tags.append(("vbs/js", "WScript 또는 CScript 실행 확인"))
    if "powershell.exe" in proc_names or "pwsh.exe" in proc_names:
        tags.append(("powershell", "PowerShell 실행 확인"))
    if any(n in proc_names for n in ("msbuild.exe", "csc.exe")):
        tags.append(("dotnet", ".NET 컴파일러/빌더 실행 확인"))

    # 네트워크 기반
    pcap = result.pcap_result
    if pcap:
        dns_names = {getattr(q, "name", "").lower() for q in getattr(pcap, "dns_queries", [])}
        if dns_names & _IP_CHECK_DOMAINS:
            matched = dns_names & _IP_CHECK_DOMAINS
            tags.append(("ip-check", f"외부 IP 조회 도메인: {', '.join(sorted(matched)[:2])}"))
        if dns_names & _MINING_POOL_DOMAINS:
            matched = dns_names & _MINING_POOL_DOMAINS
            tags.append(("cryptominer", f"채굴 풀 도메인 DNS 쿼리 확인: {', '.join(sorted(matched)[:3])}"))
        if getattr(pcap, "ftp_sessions", []):
            tags.append(("ftp", f"FTP 세션 {len(pcap.ftp_sessions)}개 감지"))
        if getattr(pcap, "smtp_sessions", []):
            _ss0 = pcap.smtp_sessions[0]
            _ss_doms = (getattr(pcap, "ip_to_domain", {}) or {}).get(_ss0.dst_ip, [])
            _ss_host = _ss_doms[0] if _ss_doms else _ss0.dst_ip
            tags.append(("smtp", f"SMTP C2 유출 — {_ss_host}:{_ss0.dst_port} "
                                  f"{'(인증 확인) ' if _ss0.has_auth else ''}"
                                  f"FROM:{_ss0.mail_from or '?'}"))

    # MITRE 기반
    if technique_ids & _STEALER_IDS:
        matched_ids = technique_ids & _STEALER_IDS
        tags.append(("stealer", f"자격증명·데이터 탈취 기법: {', '.join(sorted(matched_ids)[:3])}"))
    if technique_ids & _EVASION_IDS:
        matched_ids = technique_ids & _EVASION_IDS
        tags.append(("evasion", f"방어 회피 기법: {', '.join(sorted(matched_ids)[:3])}"))
    if technique_ids & _INJECT_IDS:
        matched_ids = technique_ids & _INJECT_IDS
        tags.append(("injection", f"프로세스 인젝션 기법: {', '.join(sorted(matched_ids)[:3])}"))
    if technique_ids & _PERSIST_IDS:
        matched_ids = technique_ids & _PERSIST_IDS
        tags.append(("persistence", f"지속성 기법: {', '.join(sorted(matched_ids)[:2])}"))
    if technique_ids & _EXFIL_IDS:
        matched_ids = technique_ids & _EXFIL_IDS
        tags.append(("exfiltration", f"데이터 유출 기법: {', '.join(sorted(matched_ids)[:2])}"))

    # 드롭 파일
    ioc = result.ioc_report
    if ioc and ioc.dropped_files:
        tags.append(("dropper", f"파일 드롭 {len(ioc.dropped_files)}개"))

    # 이메일/피싱 컨텍스트 (T1221 템플릿 인젝션 = 문서 기반 배포)
    if "T1221" in technique_ids:
        tags.append(("phishing", "문서 템플릿 인젝션 (T1221) — 이메일 기반 배포 가능성"))

    return tags


# ── AI MITRE 파싱 + 병합 ─────────────────────────────────────────────────────

def parse_mitre_from_ai(response: str) -> list:
    """AI 응답의 '마이터 기법 목록' 섹션을 파싱해 구조화된 기법 목록을 반환한다.

    형식: T기법ID|기법명(영문)|전술명(영문)|구체적 근거
    """
    results: list = []
    in_section = False
    _NEXT_SECTIONS = frozenset({
        "분석 분류", "핵심 요약", "실행 흐름", "행위 분석", "확인된 IOC", "결론",
        "Analytical classification", "Executive summary",
        "Execution flow", "Behavioral analysis", "Conclusion",
    })
    for line in response.split("\n"):
        stripped = line.strip()
        if stripped == "마이터 기법 목록":
            in_section = True
            continue
        if not in_section:
            continue
        if not stripped:
            break  # 빈 줄 = 섹션 끝
        if stripped == "없음":
            break
        if stripped in _NEXT_SECTIONS:
            break
        parts = [p.strip() for p in stripped.split("|")]
        if len(parts) >= 4:
            tid = parts[0]
            if _re.match(r"^T\d{4}(\.\d{3})?$", tid):
                results.append({
                    "id":       tid,
                    "name":     parts[1],
                    "tactic":   parts[2],
                    "evidence": parts[3],
                })
    return results


def merge_ai_mitre(behavior_report, ai_techniques: list) -> None:
    """AI 분석에서 추출한 MITRE 기법을 behavior_report에 병합한다.

    - 이미 존재하는 technique_id → 'AI' 소스와 증거만 추가
    - 새 기법 → MitreTechnique 생성 후 추가, 전술순 재정렬
    """
    if not behavior_report or not ai_techniques:
        return
    try:
        from analysis.behavior_classifier import MitreTechnique, _tactic_key
    except ImportError:
        return

    existing_map = {t.technique_id: t for t in behavior_report.techniques}
    added = False

    for item in ai_techniques:
        tid    = item.get("id", "")
        tname  = item.get("name", "")
        tactic = item.get("tactic", "")
        tevid  = item.get("evidence", "")
        if not tid or not tname or not tactic:
            continue

        ai_ev = f"[AI] {tevid}" if tevid else "[AI]"

        if tid in existing_map:
            t = existing_map[tid]
            if ai_ev not in t.evidence:
                t.evidence.append(ai_ev)
            if "AI" not in t.sources:
                t.sources.append("AI")
        else:
            ref = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            new_t = MitreTechnique(
                technique_id   = tid,
                technique_name = tname,
                tactic         = tactic,
                evidence       = [ai_ev],
                reference      = ref,
                sources        = ["AI"],
            )
            behavior_report.techniques.append(new_t)
            existing_map[tid] = new_t
            added = True

    if added:
        behavior_report.techniques.sort(key=_tactic_key)


# ── 프롬프트 빌더 ────────────────────────────────────────────────────────────

def _build_prompt(result) -> str:
    """AnalysisResult → 구조화된 위협 분석 프롬프트 (any.run 스타일)."""
    lines: list[str] = [
        "당신은 악성코드 동적 분석 전문가입니다.",
        "아래 동적 분석 데이터를 바탕으로 **한국어**로 구조화된 위협 분석 보고서를 작성하세요.",
        "대응 권고는 절대 작성하지 않습니다. 확인된 사실만 기술하고 추측은 '추정' 표현을 사용하세요.",
        "",
    ]

    # ── 분석 대상 ────────────────────────────────────────────────────────
    sample_name = "전체 시스템 모니터링"
    if getattr(result.config, "sample_path", None):
        sample_name = Path(result.config.sample_path).name
    pid_str = f" (PID: {result.sample_pid})" if result.sample_pid else ""
    all_pids = sorted(result.all_pids) if result.all_pids else []

    lines.append("## 분석 대상")
    lines.append(f"- 파일명: {sample_name}{pid_str}  ← 분석 진입점 (이 파일 자체가 로더/드롭퍼)")
    if all_pids:
        lines.append(f"- 추적 PID: {', '.join(str(p) for p in all_pids[:20])}")
    lines.append("")

    # ── MITRE ATT&CK (전술별 그룹) ──────────────────────────────────────
    br = result.behavior_report
    if br and getattr(br, "techniques", None):
        techs = br.techniques
        tactic_groups: dict[str, list] = {}
        for t in techs:
            tactic_groups.setdefault(t.tactic, []).append(t)
        lines.append(f"## MITRE ATT&CK ({len(techs)}건)")
        for tactic, ts in tactic_groups.items():
            lines.append(f"### {tactic}")
            for t in ts[:5]:
                ev    = t.evidence[:1]
                ev_str = f" → {_trunc(ev[0], 80)}" if ev else ""
                lines.append(f"- [{t.technique_id}] {t.technique_name}{ev_str}")
        lines.append("")

    # ── 프로세스 실행 체인 + 행위 상세 ────────────────────────────────────
    new_procs = (result.process_diff or {}).get("new_processes", [])
    if new_procs:
        # PID→이름 맵: 사후 전체 스냅샷(부모 포함) + 신규 프로세스
        _pid_to_nm: dict[int, str] = {}
        for _pid, _ps in (getattr(result, "proc_after_snapshot", {}) or {}).items():
            _pid_to_nm[_pid] = getattr(_ps, "name", "?")
        for _np in new_procs:
            _pid_to_nm[getattr(_np, "pid", 0)] = getattr(_np, "name", "?")

        # 신규 프로세스 PID 집합
        _new_pids: set[int] = {getattr(p, "pid", 0) for p in new_procs}

        # 부모→자식 관계 구성 (신규 프로세스 내부 관계)
        _children: dict[int, list] = {}
        _roots: list[int] = []
        for _np in new_procs:
            _pp = getattr(_np, "ppid", 0)
            _cp = getattr(_np, "pid", 0)
            if _pp in _new_pids:
                _children.setdefault(_pp, []).append(_cp)
            else:
                _roots.append(_cp)

        # 체인 트리 DFS 출력
        def _chain_lines(pid: int, depth: int = 0) -> list[str]:
            pname  = _pid_to_nm.get(pid, "?")
            prefix = ("  " * depth) + ("→ " if depth else "")
            rows   = [f"{prefix}{pname}({pid})"]
            for child in _children.get(pid, []):
                rows.extend(_chain_lines(child, depth + 1))
            return rows

        chain_rows: list[str] = []
        for rp in _roots:
            chain_rows.extend(_chain_lines(rp))

        lines.append(f"## 프로세스 실행 체인 ← 공격 흐름 파악 핵심 (신규 {len(new_procs)}개)")
        lines.extend(chain_rows[:30])
        lines.append("")

        # 명령줄 상세 (부모 이름 주석 포함)
        lines.append("## 프로세스 행위 상세")
        for p in new_procs[:15]:
            name  = getattr(p, "name", "?")
            pid   = getattr(p, "pid", "?")
            ppid  = getattr(p, "ppid", 0)
            pname = _pid_to_nm.get(ppid, f"PID {ppid}")
            exe   = getattr(p, "exe", "") or ""
            cmd   = " ".join(getattr(p, "cmdline", []) or []) or exe
            lines.append(f"- {name} (PID {pid}, 부모: {pname}): {_trunc(cmd, 100)}")
        lines.append("")

        # ── 프로세스별 악성 행위 요약 ──────────────────────────────────────
        # EventCategory import
        try:
            from parsers.procmon_csv import EventCategory as _EC
            _FILE_CAT = _EC.FILE
            _REG_CAT  = _EC.REGISTRY
            _ec_ok    = True
        except Exception:
            _FILE_CAT = _REG_CAT = None
            _ec_ok = False

        # PID별 파일/레지스트리 이벤트 그룹화
        _pid_fevs: dict[int, list] = {}
        _pid_revs: dict[int, list] = {}
        if _ec_ok:
            _FILE_OPS_PP = {"WriteFile", "CreateFile", "DeleteFile"}
            for _ev in (result.filtered_events or []):
                _evpid = getattr(_ev, "pid", 0)
                if _evpid not in _new_pids:
                    continue
                _evc = getattr(_ev, "category", None)
                _evo = getattr(_ev, "operation", "")
                if _evc == _FILE_CAT and _evo in _FILE_OPS_PP:
                    _pid_fevs.setdefault(_evpid, []).append(_ev)
                elif _evc == _REG_CAT and _evo == "RegSetValue":
                    _pid_revs.setdefault(_evpid, []).append(_ev)

        # PID별 네트워크 연결 그룹화
        _pid_nets: dict[int, list] = {}
        for _pnc in (getattr(result, "process_network_map", []) or []):
            _pncpid = getattr(_pnc, "pid", 0)
            if _pncpid in _new_pids:
                _pid_nets.setdefault(_pncpid, []).append(_pnc)

        # PID별 DNS 귀속 그룹화
        _pid_dns: dict[int, list] = {}
        for _dq in (getattr(result, "dns_attributed", []) or []):
            _dqpid = getattr(_dq, "pid", 0)
            if _dqpid in _new_pids and getattr(_dq, "attributed", False):
                _pid_dns.setdefault(_dqpid, []).append(_dq)

        # PID별 hollows-hunter 인젝션 결과 그룹화
        _pid_hh2: dict[int, object] = {}
        _hhr2 = getattr(result, "hh_result", None)
        if _hhr2 and not getattr(_hhr2, "error", ""):
            for _hr in (getattr(_hhr2, "process_results", []) or []):
                if getattr(_hr, "suspicious", 0) > 0:
                    _pid_hh2[getattr(_hr, "pid", 0)] = _hr

        # 도메인 역조회 맵
        _pcap_pp = getattr(result, "pcap_result", None)
        _ip2dom_pp = getattr(_pcap_pp, "ip_to_domain", {}) or {} if _pcap_pp else {}

        # 의심 경로/확장자 필터
        _SUSP_FRAGS_PP = ("\\temp\\", "\\appdata\\", "\\programdata\\",
                          "\\users\\public\\", "\\windows\\system32\\",
                          "\\windows\\syswow64\\")
        _SUSP_EXTS_PP  = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".tmp"}

        _proc_act_lines: list[str] = []

        for _pp in new_procs[:15]:
            _pp_pid  = getattr(_pp, "pid", 0)
            _pp_name = getattr(_pp, "name", "?")

            _fevs  = _pid_fevs.get(_pp_pid, [])
            _revs  = _pid_revs.get(_pp_pid, [])
            _nets  = _pid_nets.get(_pp_pid, [])
            _dnsl  = _pid_dns.get(_pp_pid, [])
            _hh_r  = _pid_hh2.get(_pp_pid)

            if not (_fevs or _revs or _nets or _dnsl or _hh_r):
                continue

            _proc_act_lines.append(f"### {_pp_name} (PID {_pp_pid})")

            # 파일 행위 (의심 경로/확장자 우선, 중복 제거)
            _seen_paths: set[str] = set()
            _flines: list[str] = []
            for _ev in _fevs:
                _op   = getattr(_ev, "operation", "")
                _path = getattr(_ev, "path", "")
                _low  = _path.lower()
                _ext  = ("." + _low.rsplit(".", 1)[-1]) if "." in _low else ""
                if _path in _seen_paths:
                    continue
                if any(f in _low for f in _SUSP_FRAGS_PP) or _ext in _SUSP_EXTS_PP:
                    _seen_paths.add(_path)
                    _tag = "Write" if "Write" in _op else ("Create" if "Create" in _op else "Delete")
                    _flines.append(f"  파일[{_tag}]: {_trunc(_path, 90)}")
            for _fl in _flines[:5]:
                _proc_act_lines.append(_fl)

            # 레지스트리 쓰기 (중복 제거)
            _seen_regs: set[str] = set()
            _rlines: list[str] = []
            for _ev in _revs:
                _path = getattr(_ev, "path", "")
                if _path not in _seen_regs:
                    _seen_regs.add(_path)
                    _rlines.append(f"  레지스트리[Set]: {_trunc(_path, 90)}")
            for _rl in _rlines[:3]:
                _proc_act_lines.append(_rl)

            # 네트워크 연결
            for _pnc in _nets[:4]:
                _rip   = getattr(_pnc, "remote_ip", "")
                _rport = getattr(_pnc, "remote_port", 0)
                _proto = getattr(_pnc, "proto", "TCP")
                _dir   = str(getattr(_pnc, "direction", "")).lower()
                _doms  = _ip2dom_pp.get(_rip, [])
                _host  = f"{_doms[0]}({_rip})" if _doms else _rip
                _arrow = "→" if "out" in _dir else "↔"
                _proc_act_lines.append(f"  네트워크: {_proto}{_arrow}{_host}:{_rport}")

            # DNS 쿼리
            for _dq in _dnsl[:3]:
                _dom = getattr(_dq, "name", "")
                _ans = getattr(_dq, "answers", [])
                _proc_act_lines.append(f"  DNS: {_dom}→{_ans[0] if _ans else '?'}")

            # hollows-hunter 인젝션 탐지
            if _hh_r:
                _repl  = getattr(_hh_r, "replaced", 0)
                _shc   = getattr(_hh_r, "implanted_shc", 0)
                _pe_inj = getattr(_hh_r, "implanted_pe", 0)
                _iparts = []
                if _repl:   _iparts.append(f"코드교체={_repl}")
                if _shc:    _iparts.append(f"쉘코드={_shc}")
                if _pe_inj: _iparts.append(f"PE인젝션={_pe_inj}")
                _proc_act_lines.append(
                    f"  ⚠ 인젝션: {', '.join(_iparts) if _iparts else '의심항목탐지'}"
                )

        if _proc_act_lines:
            lines.append("## 프로세스별 악성 행위 ← 각 프로세스가 실제로 한 행위 (C2·파일·레지 직접 인용)")
            lines.extend(_proc_act_lines)
            lines.append("")

    # ── 지속성/실행 아티팩트 ─────────────────────────────────────────────
    # schtasks, sc, reg 등의 전체 명령줄을 별도 섹션으로 표시
    # → AI가 /tn, /tr, /sc 등 지속성 파라미터를 직접 인용할 수 있도록
    _PERSIST_NAMES = frozenset({
        "schtasks.exe", "sc.exe", "reg.exe", "at.exe",
        "regsvr32.exe", "mshta.exe",
    })
    persist_procs = [
        p for p in new_procs
        if getattr(p, "name", "").lower() in _PERSIST_NAMES
    ]
    if persist_procs:
        lines.append(f"## 지속성/실행 아티팩트 ({len(persist_procs)}건)")
        for p in persist_procs:
            pname = getattr(p, "name", "?")
            ppid  = getattr(p, "pid", "?")
            cmd   = " ".join(getattr(p, "cmdline", []) or []) or getattr(p, "exe", "")
            lines.append(f"- {pname} (PID {ppid}): {_trunc(cmd, 220)}")
        lines.append("")

    # pe-sieve / hollows-hunter 인젝션
    pe_list = getattr(result, "pe_sieve_results", []) or []
    pe_susp = [r for r in pe_list if not getattr(r, "error", "") and getattr(r, "suspicious", 0) > 0]
    hh_r = getattr(result, "hh_result", None)
    hh_proc_results = []
    if hh_r and not getattr(hh_r, "error", ""):
        hh_proc_results = [
            r for r in (getattr(hh_r, "process_results", []) or [])
            if getattr(r, "suspicious", 0) > 0
        ]

    if pe_susp or hh_proc_results:
        lines.append("## 메모리 인젝션 탐지")
        if hh_proc_results:
            total_shc = sum(getattr(r, "implanted_shc", 0) for r in hh_proc_results)
            total_pe  = sum(getattr(r, "implanted_pe", 0) for r in hh_proc_results)
            lines.append(
                f"hollows-hunter 요약: {len(hh_proc_results)}개 프로세스 의심, "
                f"쉘코드 총 {total_shc}개, PE인젝션 총 {total_pe}개"
            )
        for r in pe_susp[:6]:
            name   = getattr(r, "name", "")
            shc    = getattr(r, "implanted_shc", 0)
            pe_inj = getattr(r, "implanted_pe", 0)
            mods   = getattr(r, "modules", []) or []
            mod_names = [Path(m.module_path).name for m in mods if getattr(m, "module_path", "")]
            mod_str = f" ({', '.join(mod_names[:3])})" if mod_names else ""
            lines.append(
                f"- [pe-sieve] PID {r.pid} {name}: 쉘코드 {shc}개, PE인젝션 {pe_inj}개{mod_str}"
            )
        for r in hh_proc_results[:8]:
            shc    = getattr(r, "implanted_shc", 0)
            pe_inj = getattr(r, "implanted_pe", 0)
            name   = getattr(r, "name", "")
            lines.append(
                f"- [hollows-hunter] PID {r.pid} {name}: 쉘코드 {shc}개, PE인젝션 {pe_inj}개"
            )
        lines.append("")

    # ── 파일 시스템 활동 ─────────────────────────────────────────────────
    _FILE_OPS_SHOW = {"WriteFile", "CreateFile", "RenameFile", "DeleteFile"}
    try:
        from parsers.procmon_csv import EventCategory
        file_evs = [
            e for e in (result.filtered_events or [])
            if e.category == EventCategory.FILE
            and e.operation in _FILE_OPS_SHOW
            and e.result == "SUCCESS"
        ]
        # (pid, op, path) 기준 중복 제거
        seen_fe: set = set()
        uniq_fe = []
        for e in file_evs:
            key = (e.pid, e.operation, e.path.lower())
            if key not in seen_fe:
                seen_fe.add(key)
                uniq_fe.append(e)

        if uniq_fe:
            lines.append(f"## 파일 시스템 활동 ({len(uniq_fe)}건 고유)")
            op_label = {
                "WriteFile": "Write", "CreateFile": "Create",
                "RenameFile": "Rename", "DeleteFile": "Delete",
            }
            for e in uniq_fe[:20]:
                detail = ""
                if e.operation == "RenameFile":
                    m = _RENAME_DEST_RE.search(e.detail or "")
                    detail = f" → {_trunc(m.group(1).strip(), 80)}" if m else ""
                elif e.operation == "CreateFile" and "OpenResult: Created" in (e.detail or ""):
                    detail = " [신규생성]"
                lines.append(
                    f"- [{op_label.get(e.operation, e.operation)}] "
                    f"{e.process}({e.pid}) → {_trunc(e.path, 100)}{detail}"
                )
            lines.append("")
    except Exception:
        pass

    # IOC 드롭 파일
    ioc = result.ioc_report
    if ioc and ioc.dropped_files:
        lines.append(f"## 드롭/생성 파일 ({len(ioc.dropped_files)}개)")
        for f in ioc.dropped_files[:12]:
            lines.append(f"- {_trunc(f, 120)}")
        lines.append("")

    # ── 레지스트리 활동 ──────────────────────────────────────────────────
    _REG_OPS_SHOW = {"RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"}
    try:
        from parsers.procmon_csv import EventCategory
        reg_evs = [
            e for e in (result.filtered_events or [])
            if e.category == EventCategory.REGISTRY
            and e.operation in _REG_OPS_SHOW
            and e.result == "SUCCESS"
        ]
        seen_re: set = set()
        uniq_re = []
        for e in reg_evs:
            key = (e.operation, e.path.lower())
            if key not in seen_re:
                seen_re.add(key)
                uniq_re.append(e)

        if uniq_re:
            lines.append(f"## 레지스트리 활동 ({len(uniq_re)}건 고유)")
            for e in uniq_re[:15]:
                detail_str = _trunc(e.detail or "", 60)
                lines.append(
                    f"- [{e.operation}] {_trunc(e.path, 100)}"
                    + (f"  ({detail_str})" if detail_str else "")
                )
            lines.append("")
    except Exception:
        pass

    # Regshot diff
    reg_diff = result.registry_diff or {}
    added_reg   = reg_diff.get("added",    [])
    modified_reg = reg_diff.get("modified", [])
    if added_reg or modified_reg:
        lines.append(f"## 레지스트리 스냅샷 diff (추가 {len(added_reg)}건 / 변경 {len(modified_reg)}건)")
        for entry in added_reg[:10]:
            k = _trunc(entry[0], 80)
            n = entry[1] if len(entry) > 1 else ""
            v = _trunc(str(entry[2]), 50) if len(entry) > 2 else ""
            lines.append(f"- [추가] {k}\\{n} = {v}")
        for entry in modified_reg[:5]:
            k  = _trunc(entry[0], 80)
            n  = entry[1] if len(entry) > 1 else ""
            nw = _trunc(str(entry[3]), 50) if len(entry) > 3 else ""
            lines.append(f"- [변경] {k}\\{n} → {nw}")
        lines.append("")

    if ioc and ioc.registry_keys:
        lines.append(f"## 레지스트리 IOC ({len(ioc.registry_keys)}개)")
        for r in ioc.registry_keys[:10]:
            lines.append(f"- {_trunc(r, 120)}")
        lines.append("")

    # ── 네트워크 통신 ───────────────────────────────────────────────────
    net_lines: list[str] = []
    pcap = result.pcap_result

    # 프로세스 ↔ IP 매핑 (pnmap)
    pnmap = getattr(result, "process_network_map", []) or []
    ip_proc: dict[str, list[str]] = {}
    for pn in pnmap:
        lbl = f"{pn.process}({pn.pid})"
        lst = ip_proc.setdefault(pn.remote_ip, [])
        if lbl not in lst:
            lst.append(lbl)

    if pcap:
        conns = getattr(pcap, "connections", []) or []
        ext_conns = [c for c in conns if not _is_private_ip(c.dst_ip)]
        if ext_conns:
            net_lines.append(f"### 외부 연결 ({len(ext_conns)}건)")
            for c in ext_conns[:15]:
                procs   = ip_proc.get(c.dst_ip, [])
                proc_str = f" [{', '.join(procs[:2])}]" if procs else ""
                net_lines.append(
                    f"- {c.proto} {c.dst_ip}:{c.dst_port} "
                    f"송신 {_fmt_bytes(c.bytes_out)}{proc_str}"
                )

        tls_list = getattr(pcap, "tls_info", []) or []
        if tls_list:
            seen_tls: set = set()
            net_lines.append("### TLS SNI")
            for t in tls_list:
                k = (getattr(t, "sni", ""), t.dst_ip)
                if k in seen_tls:
                    continue
                seen_tls.add(k)
                sni     = getattr(t, "sni", "")
                ja3_lbl = getattr(t, "ja3_label", "")
                ja3_hash = getattr(t, "ja3", "")
                tls_ver  = getattr(t, "tls_version", "")
                ja3_str  = (f" [JA3:{ja3_lbl}]" if ja3_lbl
                            else (f" [JA3:{ja3_hash[:12]}]" if ja3_hash else ""))
                net_lines.append(f"- {sni} → {t.dst_ip}:{t.dst_port} {tls_ver}{ja3_str}")
                if len(seen_tls) >= 12:
                    break

        dns_q        = getattr(pcap, "dns_queries", []) or []
        dns_attr     = getattr(result, "dns_attributed", []) or []
        dns_attr_ok  = [q for q in dns_attr if q.attributed]

        if dns_attr_ok or dns_q:
            total_dns = len(dns_attr) if dns_attr else len(dns_q)
            attr_cnt  = len(dns_attr_ok)
            net_lines.append(
                f"### DNS 쿼리 ({total_dns}건"
                + (f", 프로세스 귀속 {attr_cnt}건" if attr_cnt else "")
                + ")"
            )
            if dns_attr_ok:
                # 프로세스별로 그룹화해서 표시
                seen_names: set[str] = set()
                for q in dns_attr_ok[:20]:
                    rips = ", ".join(q.answers[:2]) if q.answers else ""
                    proc = f"{q.process}({q.pid})" if q.pid else q.process
                    threat_lbl = _DOMAIN_THREAT_LABELS.get(q.name.lower(), "")
                    net_lines.append(
                        f"- [{proc}] {_trunc(q.name, 65)}"
                        + (f" → {rips}" if rips else " → DNS응답없음(차단추정)")
                        + (f" {threat_lbl}" if threat_lbl else "")
                    )
                    seen_names.add(q.name)
                # 귀속 실패 건 (미상 프로세스)
                unattr = [q for q in dns_attr if not q.attributed]
                if unattr:
                    unattr_parts = []
                    for q in unattr[:5]:
                        threat_lbl = _DOMAIN_THREAT_LABELS.get(
                            getattr(q, "name", "").lower(), ""
                        )
                        unattr_parts.append(
                            _trunc(q.name, 30) + (f" {threat_lbl}" if threat_lbl else "")
                        )
                    net_lines.append(
                        f"- [프로세스 미상 {len(unattr)}건] " + " ".join(unattr_parts)
                    )
            else:
                # ProcMon 없거나 귀속 실패 — 기존 방식
                for q in dns_q[:15]:
                    name = getattr(q, "name", str(q))
                    rips = ", ".join(getattr(q, "response_ips", [])[:2])
                    threat_lbl = _DOMAIN_THREAT_LABELS.get(name.lower(), "")
                    net_lines.append(
                        f"- {_trunc(name, 70)}"
                        + (f" → {rips}" if rips else "")
                        + (f" {threat_lbl}" if threat_lbl else "")
                    )

        http = getattr(pcap, "http_requests", []) or []
        if http:
            net_lines.append(f"### HTTP 요청 ({len(http)}건)")
            for h in http[:15]:
                method   = getattr(h, "method", "")
                host     = getattr(h, "host", "")
                path     = getattr(h, "path", "/")
                ua       = getattr(h, "user_agent", "")
                dst_ip   = getattr(h, "dst_ip", "")
                body_len = getattr(h, "content_length", 0)
                # 프로세스 귀속: dst_ip → pnmap 역조회
                h_procs  = ip_proc.get(dst_ip, [])
                proc_str = f" [{', '.join(h_procs[:2])}]" if h_procs else ""
                ua_str   = f" UA:{_trunc(ua, 35)}" if ua else ""
                # POST body 크기 표시 (C2 유출 크기 파악)
                body_str = f" body:{_fmt_bytes(body_len)}" if (method == "POST" and body_len) else ""
                net_lines.append(
                    f"- {method} http://{host}{_trunc(path, 120)}"
                    f"{body_str}{ua_str}{proc_str}"
                )

        smtp_sessions = getattr(pcap, "smtp_sessions", []) or []
        if smtp_sessions:
            _ip2dom = getattr(pcap, "ip_to_domain", {}) or {}
            net_lines.append(f"### SMTP C2 ({len(smtp_sessions)}건) ← 데이터 유출 주요 채널")
            for s in smtp_sessions[:4]:
                _doms  = _ip2dom.get(s.dst_ip, [])
                _host  = _doms[0] if _doms else s.dst_ip
                _auth  = f" AUTH:{s.auth_user}" if s.auth_user else (" AUTH:확인됨" if s.has_auth else "")
                _ehlo  = f" EHLO:{s.ehlo_domain}" if s.ehlo_domain else ""
                net_lines.append(
                    f"- {_host} ({s.dst_ip}):{s.dst_port}{_ehlo}"
                    f" FROM:{s.mail_from or '-'}"
                    f" TO:{', '.join(s.rcpt_to[:2]) or '-'}"
                    f"{_auth}"
                    + (" [DATA전송완료]" if s.has_data else "")
                )

        ftp_sessions = getattr(pcap, "ftp_sessions", []) or []
        if ftp_sessions:
            net_lines.append(f"### FTP C2 ({len(ftp_sessions)}건)")
            for s in ftp_sessions[:4]:
                net_lines.append(
                    f"- {s.dst_ip}:{s.dst_port} user:{s.username or '-'}"
                    + (f" upload:{', '.join(s.uploaded[:2])}" if s.uploaded else "")
                )

    # HTTPS 복호화
    dr = getattr(result, "decrypted_requests", []) or []
    if dr:
        net_lines.append(f"### HTTPS 복호화 ({len(dr)}건)")
        for req in dr[:8]:
            host   = getattr(req, "host", "")
            method = getattr(req, "method", "")
            path   = getattr(req, "path", "")
            ua     = getattr(req, "user_agent", "")
            status = str(getattr(req, "resp_status", "") or "")
            net_lines.append(
                f"- {method} https://{host}{_trunc(path, 50)}"
                + (f" → HTTP {status}" if status else "")
                + (f" (UA: {_trunc(ua, 40)})" if ua else "")
            )

    # FakeNet-NG
    fn = getattr(result, "fakenet_result", {}) or {}
    fn_dns  = fn.get("dns_queries",   []) or []
    fn_http = fn.get("http_requests", []) or []
    if fn_dns:
        net_lines.append(f"### FakeNet-NG DNS ({len(fn_dns)}건)")
        for d in fn_dns[:10]:
            net_lines.append(f"- {d.get('domain','')}")
    if fn_http:
        net_lines.append(f"### FakeNet-NG HTTP ({len(fn_http)}건)")
        for h in fn_http[:8]:
            net_lines.append(
                f"- [{h.get('proto','')}] {h.get('method','')} "
                f"{h.get('host','')}{_trunc(h.get('path',''), 50)}"
            )

    # IOC 네트워크
    if ioc:
        if ioc.ip_addresses:
            net_lines.append(f"### 외부 IP IOC ({len(ioc.ip_addresses)}개)")
            net_lines += [f"- {ip}" for ip in ioc.ip_addresses[:10]]
        if ioc.domains:
            net_lines.append(f"### 도메인 IOC ({len(ioc.domains)}개)")
            net_lines += [f"- {d}" for d in ioc.domains[:10]]
        if ioc.urls:
            net_lines.append(f"### URL IOC ({len(ioc.urls)}개)")
            net_lines += [f"- {_trunc(u, 100)}" for u in ioc.urls[:8]]
        if ioc.mutexes:
            net_lines.append(f"### Mutex ({len(ioc.mutexes)}개)")
            net_lines += [f"- {m}" for m in ioc.mutexes[:6]]

    if net_lines:
        lines.append("## 네트워크 통신")
        lines.extend(net_lines)
        lines.append("")

    # ── 메모리 포렌식 (Volatility) ───────────────────────────────────────
    mf = getattr(result, "mem_forensics", {}) or {}
    if mf and not mf.get("error"):
        malfind = mf.get("malfind", []) or []
        handles = mf.get("handles", []) or []
        mutants = [h for h in handles if h.get("type") == "Mutant"]
        netscan = mf.get("netscan", []) or []
        if malfind or mutants or netscan:
            lines.append("## 메모리 포렌식 (Volatility)")
            if malfind:
                lines.append(f"### malfind ({len(malfind)}건)")
                for m in malfind[:5]:
                    prot = m.get("protection", "")
                    lines.append(
                        f"- PID {m.get('pid')} {m.get('process')} "
                        f"@ {m.get('start_vpn','?')} [{prot}]"
                    )
            if mutants:
                lines.append(f"### Mutex (Mutant {len(mutants)}개)")
                for h in mutants[:6]:
                    lines.append(f"- {h.get('handle_name','')}")
            if netscan:
                lines.append(f"### netscan ({len(netscan)}건)")
                for n in netscan[:6]:
                    if not _is_private_ip((n.get("foreign", ":0") + ":").split(":")[0]):
                        lines.append(
                            f"- {n.get('proto','')} {n.get('local','')} → "
                            f"{n.get('foreign','')} [{n.get('state','')}] {n.get('owner','')}"
                        )
            lines.append("")

    # ── 사전 계산 태그 힌트 ─────────────────────────────────────────────
    computed_tags = _compute_tags(result)
    tag_hint = ""
    if computed_tags:
        tag_hint = "\n".join(f"  {tag}: {reason}" for tag, reason in computed_tags)

    # ── 분석 지시 ───────────────────────────────────────────────────────
    # 아래 템플릿을 LLM이 그대로 채워 넣도록 지시
    template = """---
아래 템플릿을 **정확히** 따라 한국어로 작성하세요.

[규칙]
- 섹션 제목(분석 분류, 핵심 요약, 실행 흐름, 행위 분석, 확인된 IOC, 결론)은 절대 변경하지 마세요.
- 필드 이름도 절대 변경하지 마세요. 대괄호 [ ] 안 내용만 교체하세요.
- 마크다운(##, **, -, ``` 등) 사용 금지. 순수 텍스트로만 출력하세요.
- 대응 권고는 절대 포함하지 마세요.

[증거 등급 — 항목 기술 전 반드시 판단하세요]
HIGH: 파일명·IP·도메인·레지스트리 키·프로세스명이 데이터에 직접 나타난 경우 → 사실로 기술
MEDIUM: 행위 패턴·간접 증거로 추론 가능한 경우 → 반드시 "추정" 표기
LOW: 데이터에 없는 내용·순수 추측 → 기술 절대 금지

[Abstention 규칙 — 가장 중요]
- 행위 분석 각 항목의 기본값은 "관찰되지 않음"입니다. HIGH 또는 MEDIUM 증거 없이는 절대 기술하지 마세요.
- "자격증명 수집", "파일 탈취", "스크린샷", "키로깅"은 키로거·API 후킹·캡처 프로세스 등 직접 증거(HIGH)가 있어야만 기술 가능합니다.
- "다수의 IP", "시스템 도구", "악성 서버", "특정 경로" 같은 추상 표현은 절대 금지합니다.

[근거 인용 — 각 행위 항목 필수]
- 파일명·도메인·IP 등 구체적 값과 데이터 출처를 함께 기술하세요.
- 예: C:\\ProgramData\\system32\\explorer.exe 드롭 [WriteFile 이벤트]
- 예: pool.hashvault.pro DNS 쿼리 응답없음 [DNS 데이터] / dwm.exe(820) 쉘코드 26개 [hollows-hunter]

{tag_section}

분석 분류
위협 수준: [악성 활동 / 의심 활동 / 정상 중 하나만 선택]
주요 분석 대상: {sample_name} ([실행 맥락 — 실행 디렉터리와 실행 방식을 구체적으로 기술])
설명: [한 문장 — 악성코드 패밀리(추정) 또는 유형, 핵심 기능, C2 또는 채굴 풀 도메인을 직접 포함]
태그 및 해석:
[탐지된 태그 이름]: [HIGH 증거 기반 한 문장 — 파일명·도메인·기술 ID 직접 인용]

핵심 요약
[2~3문장. 악성코드 유형(추정)·실행 진입점·핵심 행위를 구체적 파일명·IP·도메인과 함께 서술. HIGH 증거만 사용.]

실행 흐름
[주의: "프로세스 실행 체인" + "프로세스별 악성 행위" 데이터를 반드시 참조. 부모→자식 순서로 각 단계의 파일·네트워크·인젝션 행위를 구체적으로 포함하세요.]
[사용자 행위] [진입점 파일명과 실행 방법 포함 — 예: wscript.exe로 JS 실행]
[준비 단계] [체인 중간 단계 — 부모→자식 프로세스명, 드롭 파일 경로 포함. "프로세스별 악성 행위"의 파일[Write] 항목 직접 인용]
[자율 실행] [최종 페이로드 행위 — "프로세스별 악성 행위"의 네트워크·인젝션 항목 직접 인용. SMTP C2 있으면 도메인:포트 우선 기재]

행위 분석
로더 / 스테이징: [{sample_name}의 역할과 드롭·로드한 페이로드 파일명·경로 직접 인용. 없으면 "관찰되지 않음"]
실행 및 피벗 (LOLBin / 인터프리터): [사용된 시스템 도구명과 목적. 없으면 "관찰되지 않음"]
지속성: [레지스트리 전체 키 경로·서비스명·스케줄 작업명 직접 인용. 없으면 "관찰되지 않음"]
메모리 인젝션: [hollows-hunter·pe-sieve 탐지 프로세스명·PID·쉘코드 수 직접 인용. 없으면 "관찰되지 않음"]
채굴 활동: [채굴 풀 도메인·연결 IP·포트·추정 알고리즘 인용. 없으면 "관찰되지 않음"]
탐색 / 수집: [키로거·API 후킹·캡처 프로세스 등 직접 확인(HIGH)된 경우에만 기술. 없으면 "관찰되지 않음"]
네트워크 / C2: [SMTP 세션이 있으면 해당 도메인:포트를 C2로 우선 기재. 없으면 외부 TCP 연결. 도메인·IP:포트·프로토콜 직접 인용. 없으면 "활동 없음"]
오류 / 크래시: [실행 중 관찰된 오류·비정상 종료 정보. 없으면 "관찰되지 않음"]

확인된 IOC
C2 / 채굴 서버: [SMTP C2이면 "mail.도메인:포트 (SMTP)" 형식으로 첫 번째 기재. 추가 C2가 있으면 나열. 없으면 "없음"]
드롭 파일: [전체 경로 나열. 없으면 "없음"]
뮤텍스 / 기타: [Mutex명 등. 없으면 "없음"]

결론
[1~2문장. 최종 위협 판단과 공격자 의도를 HIGH 증거와 함께 서술.]

마이터 기법 목록
[행위 데이터 전체를 검토해 식별한 MITRE ATT&CK 기법을 아래 형식으로 한 줄씩 나열.
형식: T기법ID|기법명(영문)|전술명(영문)|구체적 근거(파일명·프로세스·IP 직접 인용)
예시: T1055.012|Process Hollowing|Defense Evasion|aspnet_compiler.exe 5개 인스턴스 hollows-hunter 탐지
규칙: HIGH 근거가 있는 기법만 포함. 없으면 "없음"만 작성. 파이프(|) 구분자 유지.]"""

    tag_section = ""
    if tag_hint:
        tag_section = (
            "데이터 기반 탐지 태그 힌트 (태그 및 해석 섹션에 반드시 포함하세요):\n"
            + tag_hint
        )

    lines.append(template.format(tag_section=tag_section, sample_name=sample_name))

    prompt = "\n".join(lines)
    # 데이터가 초과되면 중간 데이터를 잘라내되 템플릿(지시)은 항상 보존
    if len(prompt) > _MAX_PROMPT_CHARS:
        divider = "\n---\n"
        if divider in prompt:
            data_part, instr_part = prompt.split(divider, 1)
            cutoff = _MAX_PROMPT_CHARS - len(instr_part) - len(divider) - 60
            data_part = data_part[:max(cutoff, 500)]
            prompt = data_part + "\n\n(데이터 초과로 일부 생략됨)" + divider + instr_part
        else:
            prompt = prompt[:_MAX_PROMPT_CHARS]
    return prompt


# ── Ollama 호출 ───────────────────────────────────────────────────────────────

def _call_ollama(
    prompt:   str,
    base_url: str,
    model:    str,
    timeout:  int,
) -> str:
    """Ollama /api/generate 스트리밍 호출 → 응답 텍스트.

    stream=True 로 토큰을 하나씩 수신하므로 소켓 타임아웃(per-read)에
    영향받지 않아 대형 모델(14b+)에서도 타임아웃이 발생하지 않는다.
    """
    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "num_ctx":     8192,
            "num_predict": 4096,   # 마이터 기법 목록 섹션 추가로 3072→4096
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # timeout: prefill(입력처리) + 생성 전 구간 모두 포함한 소켓 대기
    # CPU 추론 시 prefill이 120s를 초과할 수 있으므로 전체 timeout 적용
    parts: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token = chunk.get("response", "")
                if token:
                    parts.append(token)
                if chunk.get("done"):
                    break
    except TimeoutError:
        if parts:
            # 부분 응답이 있으면 그대로 반환 (타임아웃 주석 추가)
            parts.append("\n\n*(타임아웃으로 분석이 중단되었습니다)*")
        else:
            raise
    return "".join(parts)


# ── 공개 API ─────────────────────────────────────────────────────────────────

class OllamaAnalyzer:
    """Ollama 기반 동적 분석 결과 AI 해석기."""

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model:    str = DEFAULT_MODEL,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model    = model

    def is_available(self) -> bool:
        return _is_ollama_running(self.base_url)

    def model_loaded(self) -> bool:
        return _is_model_available(self.base_url, self.model)

    def analyze(
        self,
        result,
        timeout: int = 600,
    ) -> AiAnalysisResult:
        """AnalysisResult → AiAnalysisResult."""
        ai = AiAnalysisResult(model=self.model)

        if not self.is_available():
            ai.error = f"Ollama 서버에 연결할 수 없습니다 ({self.base_url})"
            return ai

        prompt = _build_prompt(result)
        ai.prompt_chars = len(prompt)

        t0 = time.monotonic()
        try:
            ai.response = _call_ollama(prompt, self.base_url, self.model, timeout)
            ai.mitre_techniques = parse_mitre_from_ai(ai.response)
        except urllib.error.URLError as e:
            ai.error = f"Ollama 연결 오류: {e.reason}"
        except TimeoutError:
            ai.error = f"Ollama 타임아웃 ({timeout}s) — 모델이 로드되지 않았거나 응답이 느립니다."
        except Exception as e:
            ai.error = str(e)

        ai.elapsed_sec = round(time.monotonic() - t0, 1)
        return ai


def ai_analysis_to_dict(r: AiAnalysisResult) -> dict:
    return {
        "model":            r.model,
        "response":         r.response,
        "elapsed_sec":      r.elapsed_sec,
        "prompt_chars":     r.prompt_chars,
        "error":            r.error,
        "mitre_techniques": r.mitre_techniques,
    }
