"""기존 JSON과 산출물로 구성하는 읽기 전용 결과 요약."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath


def format_size(size: int) -> str:
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


@dataclass
class ResultSummary:
    folder: Path
    sample: str = "대상 정보 없음"
    title: str = "결과 확인 필요"
    subtitle: str = ""
    html_path: Path | None = None
    metrics: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    collection: list[tuple] = field(default_factory=list)
    techniques: list[tuple] = field(default_factory=list)
    connections: list[tuple] = field(default_factory=list)
    artifacts: list[tuple] = field(default_factory=list)
    log_text: str = "저장된 실행 로그가 없습니다. 다음 GUI 분석부터 run.log가 저장됩니다."


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
                ".pcapng": "네트워크 캡처", ".html": "상세 리포트", ".json": "분석 결과", ".log": "실행 로그"}
    for path in files:
        result.artifacts.append((path.name, "폴더" if path.is_dir() else format_size(path.stat().st_size),
                                 "덤프 파일" if path.name == "dumps" else purposes.get(path.suffix.lower(), "기타")))
    reports = sorted(folder.glob("*_dynamic_report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        htmls = sorted(folder.glob("*_dynamic_report.html"))
        result.html_path = htmls[0] if len(htmls) == 1 else None
        result.warnings.append("JSON 리포트가 없어 결과 요약을 구성할 수 없습니다. 산출물 목록과 실행 로그를 확인하세요.")
        return result
    report = reports[0]
    if report.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("JSON 리포트가 64MB를 초과합니다. 상세 HTML 리포트로 확인하세요.")
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
    html = report.with_suffix(".html")
    result.html_path = html if html.is_file() else None
    sample = str(data.get("sample") or "")
    result.sample = PureWindowsPath(sample).name if sample not in ("", "None") else "전체 시스템 모니터링"
    duration = format_duration(float(data.get("duration") or 0))
    result.subtitle = f"모니터링 {data.get('timeout', '?')}초  ·  전체 소요 {duration}  ·  PID {data.get('sample_pid') or '미확인'}"
    tools = data.get("tools_used", {})
    events = data.get("events_summary", {})
    network = data.get("network", {})
    techniques = data.get("mitre_techniques", [])
    iocs = data.get("iocs", {})
    result.metrics = {
        "ATT&CK 후보": str(len(techniques)),
        "ProcMon 이벤트": f"{int(events.get('total') or 0):,}",
        "네트워크 패킷": f"{int(network.get('packets_loaded') or 0):,}",
        "관찰 IP": str(len(iocs.get("ip_addresses") or [])),
    }
    pml, csv = by_name.get("procmon.pml"), by_name.get("procmon.csv")
    partial = False
    if pml or csv or tools.get("procmon"):
        if not csv or csv.stat().st_size == 0:
            partial = True
            detail = f"PML {format_size(pml.stat().st_size)}, 유효한 CSV 없음" if pml else "유효한 PML·CSV 없음"
            result.warnings.append("ProcMon CSV가 없거나 비어 있어 파일·레지스트리 행위를 충분히 확인할 수 없습니다. 원본 PML과 변환 로그를 확인하세요.")
            result.collection.append(("ProcMon", "변환 결과 없음", detail))
        elif not events.get("total"):
            partial = True
            result.warnings.append("ProcMon 이벤트가 0건입니다. 캡처·필터·파싱 상태를 확인하세요.")
            result.collection.append(("ProcMon", "이벤트 없음", "CSV 있음 · 파싱된 이벤트 0건"))
        else:
            result.collection.append(("ProcMon", "이벤트 확인", f"전체 {events.get('total'):,}건 / 필터 후 {events.get('filtered', 0):,}건"))
    else:
        result.collection.append(("ProcMon", "결과 없음", "사용 안 함 또는 수집 정보 없음"))
    packets = network.get("packets_loaded") or 0
    result.collection.append(("네트워크", "패킷 확인" if packets else "패킷 없음", f"{packets:,}개 · 연결 {len(network.get('connections') or []):,}개"))
    if tools.get("tshark") and not packets:
        partial = True
        result.warnings.append("tshark 사용 기록은 있으나 파싱된 패킷이 없습니다. 캡처 파일과 네트워크 파싱 상태를 확인하세요.")
    if network.get("parse_error"):
        partial = True
        result.warnings.append(f"네트워크 파싱: {network['parse_error']}")
    for name, used in tools.items():
        if name in ("procmon", "tshark"):
            continue
        result.collection.append((name, "사용 기록 있음" if used else "사용 안 함", str(used) if not isinstance(used, bool) else "개별 성공 여부는 상세 리포트에서 확인"))
    result.warnings.extend(f"실행 오류: {error}" for error in data.get("errors", []))
    if "\ufffd" in raw:
        result.warnings.append("일부 결과 문자열이 깨져 있습니다. 원본 로그의 인코딩을 확인하세요.")
    if not result.html_path:
        result.warnings.append("상세 HTML 리포트가 없습니다.")
    for technique in techniques:
        evidence = technique.get("evidence") or []
        result.techniques.append((str(technique.get("id", "")), str(technique.get("name", "")),
                                  " · ".join(technique.get("sources") or []) or evidence_sources(evidence), "\n".join(str(e) for e in evidence)))
    target_pids = {str(p) for p in data.get("all_pids", [])}
    if data.get("sample_pid"):
        target_pids.add(str(data["sample_pid"]))
    for conn in data.get("process_network_map", []):
        pid = str(conn.get("pid", ""))
        attribution = "추적 대상 PID" if pid in target_pids else ("대상 외 PID" if target_pids else "대상 PID 미확인")
        result.connections.append((conn.get("process", ""), pid, f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}", attribution))
    if result.connections and not any(c[3] == "추적 대상 PID" for c in result.connections):
        result.warnings.append("프로세스에 연결된 네트워크 기록 중 추적 대상 PID와 일치하는 항목이 없습니다. 관찰 IP를 샘플의 통신으로 단정하지 마세요.")
    result.title = "부분 수집 · 확인 필요" if partial else ("분석 결과 · 확인 필요" if result.warnings else "분석 결과 확인")
    return result
