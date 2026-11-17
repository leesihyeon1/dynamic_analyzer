"""저장된 JSON 리포트와 산출물로 GUI 결과 화면을 구성하는 읽기 전용 요약.

샘플이나 HTML 을 실행하지 않고 메타데이터만 읽는다. 오래된 JSON(판정·수집 상태 블록이 없는
이전 버전)도 열 수 있도록 모든 키는 선택적으로 다룬다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PureWindowsPath


def format_size(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024
    return ""


def format_duration(seconds: float) -> str:
    minutes, rest = divmod(max(0, int(seconds)), 60)
    return f"{minutes}분 {rest}초" if minutes else f"{rest}초"


def evidence_sources(evidence: list) -> str:
    """근거의 명시적인 출처만 표시한다. 출처 없는 근거는 미분류로 남긴다."""
    sources = set()
    for value in evidence:
        text = str(value)
        if text.startswith("[AI]"):
            sources.add("AI 해석")
        elif "CAPA" in text.upper():
            sources.add("CAPA")
        elif any(name in text for name in ("Zenbox", "CAPE Sandbox", "VirusTotal")):
            sources.add("외부 분석")
        else:
            sources.add("미분류 근거")
    return " · ".join(sorted(sources)) or "근거 없음"


_VERDICT_LABEL = {"mal": "악성", "sus": "의심", "ok": "특이 위협 미확인"}
_TIER_LEVEL = {1: "mal", 2: "sus", 3: "faint"}
_AI_SECTIONS = ("핵심 요약", "분석 한계", "결론")
_FOLDER_RE = re.compile(r"^(?P<stem>.+)_(?P<ts>\d{8}_\d{6})(?:_\d+)?$")


@dataclass
class ProcRow:
    pid: int
    ppid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    tier: int = 0
    is_sample: bool = False
    injected: bool = False
    files: int = 0
    regs: int = 0
    nets: int = 0
    dns: int = 0
    detail: dict = field(default_factory=dict)


@dataclass
class RecentResult:
    folder: Path
    sample: str
    when: str
    level: str = ""


@dataclass
class ResultSummary:
    folder: Path
    sample: str = "대상 정보 없음"
    sample_path: str = ""
    sha256: str = ""
    title: str = "결과 확인 필요"
    subtitle: str = ""
    html_path: Path | None = None
    json_path: Path | None = None
    report_stage: str = "final"          # final | preliminary (AI 대기 중 먼저 저장된 보고서)
    ai_state: str = "off"                # off | pending | done | error
    ai_model: str = ""
    ai_note: str = ""
    ai_summary: list = field(default_factory=list)   # [(섹션 제목, 본문)]
    verdict_level: str = ""              # mal | sus | ok | "" (판정 정보 없음)
    verdict_label: str = ""
    score: int | None = None
    indicators: list = field(default_factory=list)   # [{level, cat, title, ev, tid}]
    sample_active: bool | None = None
    inactivity: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    collection: list[tuple] = field(default_factory=list)   # (도구, ok|partial|fail|off, 설명)
    errors: list[str] = field(default_factory=list)
    techniques: list[tuple] = field(default_factory=list)   # (ID, 이름, 전술, 출처, 근거, 등급)
    processes: list[ProcRow] = field(default_factory=list)
    connections: list[tuple] = field(default_factory=list)  # (귀속, 프로세스, PID, 원격, 도메인, 이벤트, 색)
    dns: list[tuple] = field(default_factory=list)          # (도메인, 응답, 프로세스, 상태, 색)
    dropped: list[tuple] = field(default_factory=list)      # (경로, 크기, SHA-256, 등급)
    registry: list[tuple] = field(default_factory=list)     # (변경, 키, 값, 데이터, 색)
    iocs: dict = field(default_factory=dict)
    artifacts: list[tuple] = field(default_factory=list)
    log_text: str = "저장된 실행 로그가 없습니다. 다음 GUI 분석부터 run.log가 저장됩니다."


def _cmdline(value) -> str:
    """psutil 명령줄(목록)이나 문자열을 사람이 읽는 한 줄로."""
    if isinstance(value, (list, tuple)):
        import subprocess
        try:
            return subprocess.list2cmdline([str(v) for v in value])
        except Exception:
            return " ".join(str(v) for v in value)
    return str(value or "")


def _split_ai_sections(text: str) -> list:
    """AI 응답에서 핵심 요약·분석 한계·결론 섹션 본문만 뽑는다 (제목 줄의 마크다운 표식 허용)."""
    lines = (text or "").splitlines()
    out, current, buf = [], None, []
    titles = ("분석 분류", "핵심 요약", "실행 흐름", "분석 한계", "행위 분석", "확인된 IOC", "결론", "마이터 기법 목록")

    def flush():
        if current in _AI_SECTIONS and "".join(buf).strip():
            out.append((current, "\n".join(buf).strip()))

    for line in lines:
        bare = re.sub(r"^[#*\s]+|[*:\s]+$", "", line.strip())
        if bare in titles:
            flush()
            current, buf = bare, []
        elif current:
            buf.append(line)
    flush()
    order = {t: i for i, t in enumerate(_AI_SECTIONS)}
    return sorted(out, key=lambda x: order.get(x[0], 99))


def _collection_fallback(data: dict, by_name: dict, warnings: list) -> list:
    """collection_status 블록이 없는 이전 JSON 용 — 산출물과 수치로 수집 상태를 추정한다."""
    rows = []
    tools = data.get("tools_used") or {}
    events = data.get("events_summary") or {}
    network = data.get("network") or {}
    pml, csv = by_name.get("procmon.pml"), by_name.get("procmon.csv")
    if pml or csv or tools.get("procmon"):
        if not csv or csv.stat().st_size == 0:
            detail = f"PML {format_size(pml.stat().st_size)}, 유효한 CSV 없음" if pml else "유효한 PML·CSV 없음"
            warnings.append("ProcMon CSV가 없거나 비어 있어 파일·레지스트리 행위를 충분히 확인할 수 없습니다. 원본 PML과 변환 로그를 확인하세요.")
            rows.append(("ProcMon", "fail", f"변환 결과 없음 — {detail}"))
        elif not events.get("total"):
            warnings.append("ProcMon 이벤트가 0건입니다. 캡처·필터·파싱 상태를 확인하세요.")
            rows.append(("ProcMon", "fail", "CSV 있음 · 파싱된 이벤트 0건"))
        else:
            rows.append(("ProcMon", "ok", f"이벤트 {events.get('total'):,}건 / 필터 후 {events.get('filtered', 0):,}건"))
    else:
        rows.append(("ProcMon", "off", "사용 안 함 또는 수집 정보 없음"))
    packets = int(network.get("packets_loaded") or 0)
    if network.get("parse_error"):
        rows.append(("패킷 캡처", "fail", f"파싱 실패 — {network['parse_error']}"))
        warnings.append(f"네트워크 파싱: {network['parse_error']}")
    elif packets:
        rows.append(("패킷 캡처", "ok", f"패킷 {packets:,}개 · 연결 {len(network.get('connections') or []):,}개"))
    elif tools.get("tshark"):
        rows.append(("패킷 캡처", "fail", "tshark 는 켜졌지만 파싱된 패킷 0개 — 캡처 인터페이스 확인"))
        warnings.append("tshark 사용 기록은 있으나 파싱된 패킷이 없습니다. 캡처 파일과 네트워크 파싱 상태를 확인하세요.")
    else:
        rows.append(("패킷 캡처", "off", "사용 안 함"))
    names = {"registry_snapshot": "레지스트리 스냅샷", "pe_sieve": "pe-sieve", "hollows_hunter": "hollows-hunter",
             "tls_keylog": "TLS 키 로그", "fakenet": "FakeNet-NG", "dns_etw": "DNS ETW", "process_hacker": "Process Hacker",
             "capa": "CAPA", "virustotal": "VirusTotal", "yara": "YARA", "ai": "AI 해석"}
    for key, used in tools.items():
        if key in ("procmon", "tshark"):
            continue
        name = names.get(key, key)
        if isinstance(used, bool):
            rows.append((name, "ok" if used else "off", "사용" if used else "사용 안 함"))
        else:
            text = str(used)
            state = ("fail" if any(w in text for w in ("오류", "실패")) else
                     "off" if any(w in text for w in ("비활성", "미설치", "건너뜀", "없음", "미실행", "샘플 없음")) else "ok")
            rows.append((name, state, text))
    return rows


def _attribution(pid: str, lineage: set, related: set, target: set) -> tuple:
    if pid in lineage:
        return "샘플 계보", "mal"
    if pid in related:
        return "상관 의심", "sus"
    if pid in target:
        return "추적 대상", "sus"
    if pid in ("", "0", "None"):
        return "귀속 미확인", "faint"
    return "배경", "faint"


def load_result(folder: Path) -> ResultSummary:
    """샘플이나 HTML을 실행하지 않고 메타데이터만 읽는다."""
    folder = folder.resolve()
    if not folder.is_dir():
        raise ValueError("결과 폴더를 찾을 수 없습니다.")
    result = ResultSummary(folder)
    files = sorted(folder.iterdir(), key=lambda p: p.name.lower())
    by_name = {p.name.lower(): p for p in files}
    log_path = by_name.get("run.log")
    if log_path and log_path.is_file():
        with log_path.open("rb") as stream:
            stream.seek(max(0, log_path.stat().st_size - 1024 * 1024))
            result.log_text = stream.read(1024 * 1024).decode("utf-8", errors="replace")
    purposes = {".pml": "ProcMon 원본", ".csv": "이벤트 데이터", ".pcap": "네트워크 캡처",
                ".pcapng": "네트워크 캡처", ".html": "상세 보고서", ".json": "분석 결과", ".log": "실행 로그",
                ".txt": "텍스트", ".raw": "메모리 덤프", ".dmp": "메모리 덤프"}
    folders = {"dumps": "pe-sieve 덤프", "evidence": "증거 사본", "hh_dumps": "hollows-hunter 덤프"}
    for path in files:
        result.artifacts.append((path.name + ("\\" if path.is_dir() else ""),
                                 "폴더" if path.is_dir() else format_size(path.stat().st_size),
                                 folders.get(path.name.lower(), "폴더") if path.is_dir()
                                 else purposes.get(path.suffix.lower(), "기타")))
    reports = sorted(folder.glob("*_dynamic_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        htmls = sorted(folder.glob("*_dynamic_report.html"))
        result.html_path = htmls[0] if len(htmls) == 1 else None
        result.sample = folder.name
        result.warnings.append("JSON 리포트가 없어 결과 요약을 구성할 수 없습니다. 산출물 목록과 실행 로그를 확인하세요.")
        result.collection.append(("보고서", "fail", "JSON 리포트 없음 — 분석이 중간에 끝났을 수 있습니다"))
        return result
    report = reports[0]
    if report.stat().st_size > 96 * 1024 * 1024:
        raise ValueError("JSON 리포트가 96MB를 초과합니다. 상세 HTML 리포트로 확인하세요.")
    raw = report.read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("JSON 리포트의 최상위 값이 객체가 아닙니다.")
    for key, expected in {"tools_used": dict, "events_summary": dict, "network": dict,
                          "iocs": dict, "errors": list, "mitre_techniques": list,
                          "process_network_map": list, "all_pids": list}.items():
        if key in data and not isinstance(data[key], expected):
            raise ValueError(f"JSON 리포트의 {key} 형식이 올바르지 않습니다.")
    if len(reports) > 1:
        result.warnings.append(f"리포트가 {len(reports)}개 있어 가장 최근 파일인 {report.name}을 표시합니다.")
    result.json_path = report
    html = report.with_suffix(".html")
    result.html_path = html if html.is_file() else None
    sample = str(data.get("sample") or "")
    result.sample_path = sample if sample not in ("", "None") else ""
    result.sample = PureWindowsPath(sample).name if result.sample_path else "전체 시스템 모니터링"
    result.sha256 = str(data.get("sample_sha256") or "")
    result.report_stage = str(data.get("report_stage") or "final")

    # ── 판정 ──
    verdict = data.get("verdict") or {}
    if isinstance(verdict, dict) and verdict.get("level"):
        result.verdict_level = str(verdict.get("level"))
        result.verdict_label = _VERDICT_LABEL.get(result.verdict_level, str(verdict.get("label") or ""))
        try:
            result.score = int(verdict.get("score"))
        except (TypeError, ValueError):
            result.score = None
        result.indicators = [i for i in (verdict.get("indicators") or []) if isinstance(i, dict) and i.get("title")]
        for ind in result.indicators:
            ind.setdefault("level", "info")
            ind.setdefault("cat", "")
    if "sample_active" in data:
        result.sample_active = bool(data.get("sample_active"))
        result.inactivity = [str(s) for s in (data.get("inactivity_signals") or [])]

    # ── AI ──
    ai = data.get("ai_analysis") or {}
    if isinstance(ai, dict) and ai:
        result.ai_model = str(ai.get("model") or "").split("/")[-1]
        if ai.get("pending"):
            result.ai_state = "pending"
        elif ai.get("error"):
            result.ai_state = "error"
            result.ai_note = str(ai.get("error"))
        elif ai.get("response"):
            result.ai_state = "done"
            result.ai_summary = _split_ai_sections(str(ai.get("response")))
            if ai.get("elapsed_sec"):
                result.ai_model += f" · {ai.get('elapsed_sec')}초"
    tools = data.get("tools_used") or {}
    if result.ai_state == "off" and tools.get("ai"):
        result.ai_state = "error" if "실패" in str(tools.get("ai")) else "done"

    # ── 요약 줄 ──
    duration = format_duration(float(data.get("duration") or 0))
    host = ""
    sample_pid = data.get("sample_pid")
    new_procs = ((data.get("process_diff") or {}).get("new_processes") or [])
    for p in new_procs:
        if isinstance(p, dict) and p.get("pid") == sample_pid and str(p.get("name", "")).lower() != result.sample.lower():
            host = f"호스트 {p.get('name')} PID {sample_pid}"
            break
    parts = [f"관찰 {data.get('timeout', '?')}초", f"전체 소요 {duration}",
             host or f"PID {sample_pid or '미확인'}"]
    try:
        parts.append(datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M"))
    except OSError:
        pass
    if result.report_stage == "preliminary":
        parts.append("1차 보고서 (AI 반영 전)")
    result.subtitle = "  ·  ".join(parts)

    events = data.get("events_summary") or {}
    network = data.get("network") or {}
    techniques = data.get("mitre_techniques") or []
    iocs = data.get("iocs") or {}
    result.iocs = {k: v for k, v in iocs.items() if isinstance(v, list)}
    result.metrics = {
        "ATT&CK 후보": str(len(techniques)),
        "ProcMon 이벤트": f"{int(events.get('total') or 0):,}",
        "네트워크 패킷": f"{int(network.get('packets_loaded') or 0):,}",
        "관찰 IP": str(len(iocs.get("ip_addresses") or [])),
    }

    # ── 수집 상태 ──
    status = data.get("collection_status")
    if isinstance(status, list) and status:
        for row in status:
            if isinstance(row, dict):
                result.collection.append((str(row.get("tool", "")), str(row.get("state", "ok")),
                                          str(row.get("detail", ""))))
                if row.get("state") in ("fail", "partial") and row.get("warn"):
                    result.warnings.append(str(row["warn"]))
    else:
        result.collection = _collection_fallback(data, by_name, result.warnings)
    result.errors = [str(e) for e in (data.get("errors") or [])]
    if "�" in raw:
        result.warnings.append("일부 결과 문자열이 깨져 있습니다. 원본 로그의 인코딩을 확인하세요.")
    if not result.html_path:
        result.warnings.append("상세 HTML 리포트가 없습니다.")

    # ── 기법 ──
    for technique in techniques:
        if not isinstance(technique, dict):
            continue
        evidence = technique.get("evidence") or []
        result.techniques.append((str(technique.get("id", "")), str(technique.get("name", "")),
                                  str(technique.get("tactic", "")),
                                  " · ".join(technique.get("sources") or []) or evidence_sources(evidence),
                                  "\n".join(str(e) for e in evidence),
                                  int(technique.get("relevance_tier") or 0)))
    result.techniques.sort(key=lambda t: (t[5] or 9, t[0]))

    # ── 프로세스 ──
    lineage = {int(p) for p in (data.get("lineage_pids") or []) if str(p).isdigit()}
    injected = {int(p) for p in (data.get("injected_pids") or []) if str(p).isdigit()}
    behaviors = data.get("process_behaviors") or {}
    for p in new_procs:
        if not isinstance(p, dict) or p.get("pid") is None:
            continue
        pid = int(p.get("pid") or 0)
        b = behaviors.get(str(pid)) or {}
        tier = int(p.get("relevance_tier") or 0)
        if pid in lineage:
            tier = 1
        row = ProcRow(pid=pid, ppid=int(p.get("ppid") or 0), name=str(p.get("name") or "?"),
                      exe=str(p.get("exe") or ""), cmdline=_cmdline(p.get("cmdline")), tier=tier,
                      is_sample=pid == sample_pid, injected=pid in injected,
                      files=int(b.get("files_written_count", len(b.get("files_written") or []))),
                      regs=int(b.get("reg_written_count", len(b.get("reg_written") or []))),
                      nets=int(b.get("tcp_conns_count", len(b.get("tcp_conns") or []))),
                      dns=int(b.get("dns_queries_count", len(b.get("dns_queries") or []))),
                      detail=b if isinstance(b, dict) else {})
        result.processes.append(row)
    if sample_pid and not any(p.pid == sample_pid for p in result.processes):
        result.processes.insert(0, ProcRow(pid=int(sample_pid), ppid=0, name=result.sample, tier=1, is_sample=True))

    # ── 네트워크 ──
    related = {str(p.pid) for p in result.processes if p.tier == 2}
    lineage_s = {str(p) for p in lineage}
    target = {str(p) for p in data.get("all_pids") or []}
    if sample_pid:
        target.add(str(sample_pid))
    ip_domains: dict = {}
    for q in (network.get("dns_queries") or []):
        if isinstance(q, dict):
            for ip in q.get("response_ips") or []:
                ip_domains.setdefault(ip, q.get("name", ""))
    rows = []
    for conn in data.get("process_network_map") or []:
        if not isinstance(conn, dict):
            continue
        pid = str(conn.get("pid", ""))
        label, level = _attribution(pid, lineage_s, related, target)
        remote_ip = str(conn.get("remote_ip", ""))
        rows.append((label, str(conn.get("process", "")), pid, f"{remote_ip}:{conn.get('remote_port', '')}",
                     ip_domains.get(remote_ip, ""), str(conn.get("event_count", "")), level))
    order = {"샘플 계보": 0, "상관 의심": 1, "추적 대상": 2, "귀속 미확인": 3, "배경": 4}
    result.connections = sorted(rows, key=lambda r: (order.get(r[0], 9), r[1]))
    if result.connections and not any(r[0] in ("샘플 계보", "추적 대상") for r in result.connections):
        result.warnings.append("프로세스에 연결된 네트워크 기록 중 샘플 계보와 일치하는 항목이 없습니다. 관찰 IP를 샘플의 통신으로 단정하지 마세요.")
    seen = set()
    for q in data.get("dns_attributed") or []:
        if not isinstance(q, dict) or not q.get("name"):
            continue
        key = (q.get("name"), q.get("pid"))
        if key in seen:
            continue
        seen.add(key)
        pid = str(q.get("pid", ""))
        label, level = _attribution(pid if q.get("attributed", True) else "", lineage_s, related, target)
        answers = ", ".join((q.get("answers") or [])[:3])
        proc = f"{q.get('process', '')} ({pid})" if q.get("attributed", True) and q.get("process") else "미확인"
        result.dns.append((str(q.get("name")), answers or "응답 없음", proc, label, level))
    if not result.dns:
        for q in network.get("dns_queries") or []:
            if isinstance(q, dict) and q.get("name") and q.get("name") not in seen:
                seen.add(q.get("name"))
                answers = ", ".join((q.get("response_ips") or [])[:3])
                result.dns.append((str(q["name"]), answers or "응답 없음", "미확인",
                                   "응답 없음" if q.get("no_response") else "관측", "faint"))
    result.dns.sort(key=lambda r: (order.get(r[3], 5), r[0]))

    # ── 파일 · 레지스트리 ──
    tiers = iocs.get("dropped_file_tiers") or {}
    evidence = data.get("evidence") or {}
    ev_files = {}
    for item in (evidence.get("dropped") or []) if isinstance(evidence, dict) else []:
        if isinstance(item, dict) and item.get("source"):
            ev_files[str(item.get("source")).lower()] = item
    for path in iocs.get("dropped_files") or []:
        item = ev_files.get(str(path).lower(), {})
        size = item.get("size")
        result.dropped.append((str(path), format_size(size) if isinstance(size, (int, float)) else "",
                               str(item.get("sha256") or "")[:16] + ("…" if item.get("sha256") else ""),
                               int(tiers.get(str(path)) or 0)))
    reg = data.get("registry_diff") or {}
    for op, rows_ in (("추가", reg.get("added") or []), ("변경", reg.get("modified") or []),
                      ("삭제", reg.get("deleted") or [])):
        for item in rows_:
            if not isinstance(item, list) or len(item) < 2:
                continue
            key, name = str(item[0]), str(item[1])
            value = str(item[-1]) if len(item) > 2 else ""
            if op == "변경" and len(item) >= 4:
                value = f"{item[2]} → {item[3]}"
            persist = any(k in key.lower() for k in ("\\run", "\\services\\", "winlogon", "image file execution",
                                                       "\\schedule\\taskcache", "appinit"))
            result.registry.append((op, key, name, value[:300], "mal" if persist else ""))
    result.registry.sort(key=lambda r: (r[4] != "mal", r[1]))

    partial = any(state in ("fail", "partial") for _t, state, _d in result.collection)
    if result.report_stage == "preliminary":
        result.title = "1차 결과 — AI 해석 대기 중"
    elif partial:
        result.title = "부분 수집 · 확인 필요"
    else:
        result.title = "분석 결과 · 확인 필요" if result.warnings else "분석 결과 확인"
    return result


def list_recent_results(results_dir: Path, limit: int = 30) -> list[RecentResult]:
    """results 아래 분석 폴더를 최신순으로 — 판정은 작은 색인 파일(index.json)이 있을 때만 읽는다."""
    if not results_dir.is_dir():
        return []
    items = []
    for folder in results_dir.iterdir():
        if not folder.is_dir() or folder.name.startswith(".") or folder.name in ("ui-preview",):
            continue
        try:
            mtime = folder.stat().st_mtime
        except OSError:
            continue
        m = _FOLDER_RE.match(folder.name)
        sample = m.group("stem") if m else folder.name
        level = ""
        index = folder / "index.json"
        if index.is_file() and index.stat().st_size < 64 * 1024:
            try:
                meta = json.loads(index.read_text(encoding="utf-8"))
                level = str(meta.get("level") or "")
                sample = str(meta.get("sample") or sample)
            except (OSError, ValueError):
                pass
        items.append((mtime, RecentResult(folder=folder, sample=sample,
                                          when=datetime.fromtimestamp(mtime).strftime("%m-%d %H:%M"), level=level)))
    items.sort(key=lambda x: x[0], reverse=True)
    return [item for _m, item in items[:limit]]
