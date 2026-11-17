"""
demo_report.py — 샘플 실행 없이 리포트 UI 를 확인하기 위한 합성 데이터 리포트 생성기

리포트 화면(판정 요약·행위 그래프·프로세스 트리·증거 탭)을 고칠 때마다 VM 에서
악성코드를 다시 돌릴 수는 없다. 이 스크립트는 스크립트 드로퍼 → 사이드로딩 로더 →
브라우저 정보 탈취 → Run 키 지속성 흐름을 흉내 낸 **가짜 ProcMon 이벤트**를 만들어
실제 분석 계층(IOC 추출·행위 분류·관련도 등급)을 그대로 통과시킨 뒤 HTML 을 만든다.

    python tools/demo_report.py              # results/ui-preview/demo_dynamic_report.html
    python tools/demo_report.py --out DIR

관리자 권한·외부 도구가 필요 없다. 여기 나오는 경로·도메인은 전부 가상의 값이다.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from parsers.procmon_csv import ProcMonEvent, EventCategory          # noqa: E402
from parsers.pcap_parser import PcapResult, NetworkConnection, DNSQuery  # noqa: E402
from core.process_tracker import ProcessSnapshot                     # noqa: E402

U = r"C:\Users\analyst"
SAMPLE = U + r"\Desktop\invoice.js"
LOADER = U + r"\Documents\updater.exe"
DLL    = U + r"\Documents\lua51.dll"
BLOB   = U + r"\Documents\payload.dat"
COPY   = U + r"\AppData\Roaming\updater.exe"
STEAL  = U + r"\AppData\Local\Temp\57a2\Chrome\Default\cookies.json"
RUNKEY = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
WEBV   = U + r"\AppData\Local\EBWebView\Default\Preferences.tmp"


def _ev(proc, pid, op, path, cat, detail="", result="SUCCESS"):
    return ProcMonEvent(time_str="04:25:05.1", process=proc, pid=pid, operation=op,
                        path=path, result=result, detail=detail, category=cat)


def _events() -> list:
    F, R, P = EventCategory.FILE, EventCategory.REGISTRY, EventCategory.PROCESS
    created = "OpenResult: Created"
    ev = [
        # 분석기가 wscript 로 샘플을 연다 → 호스트 확정 대상
        _ev("explorer.exe", 900, "Process Create", r"C:\Windows\System32\WScript.exe", P,
            f'PID: 4436, Command line: "C:\\Windows\\System32\\WScript.exe" "{SAMPLE}" , Current directory: {U}\\Desktop\\'),
        _ev("WScript.exe", 4436, "CreateFile", LOADER, F, created),
        _ev("WScript.exe", 4436, "WriteFile", LOADER, F, "Offset: 0, Length: 65536"),
        _ev("WScript.exe", 4436, "CreateFile", DLL, F, created),
        _ev("WScript.exe", 4436, "WriteFile", DLL, F, "Offset: 0, Length: 65536"),
        _ev("WScript.exe", 4436, "WriteFile", BLOB, F, "Offset: 0, Length: 65536"),
        _ev("WScript.exe", 4436, "Process Create", r"C:\Windows\System32\cmd.exe", P,
            f'PID: 6632, Command line: "C:\\Windows\\System32\\cmd.exe" /c echo. > "{SAMPLE}:Zone.Identifier", Current directory: {U}\\'),
        _ev("WScript.exe", 4436, "Process Create", LOADER, P,
            f'PID: 7144, Command line: "{LOADER}" "{BLOB}", Current directory: {U}\\Documents\\'),
        _ev("updater.exe", 7144, "Load Image", DLL, P, "Image Base: 0x7ff900000000"),
        _ev("updater.exe", 7144, "CreateFile", COPY, F, created),
        _ev("updater.exe", 7144, "WriteFile", COPY, F, "Offset: 0, Length: 65536"),
        _ev("updater.exe", 7144, "RegSetValue", RUNKEY + r"\updater", R, f"Type: REG_SZ, Length: 96, Data: {COPY}"),
        _ev("updater.exe", 7144, "Process Create", r"C:\Windows\System32\rundll32.exe", P,
            f'PID: 6628, Command line: "C:\\Windows\\System32\\rundll32.exe" all -k --output-path "{U}\\AppData\\Local\\Temp\\57a2", Current directory: {U}\\'),
        _ev("rundll32.exe", 6628, "Process Create", r"C:\Program Files\Google\Chrome\Application\chrome.exe", P,
            f'PID: 6596, Command line: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --headless, Current directory: {U}\\'),
        _ev("chrome.exe", 6596, "ReadFile", U + r"\AppData\Local\Google\Chrome\User Data\Default\Login Data", F, "Offset: 0"),
        _ev("chrome.exe", 6596, "WriteFile", STEAL, F, "Offset: 0, Length: 4096"),
        # 배경 잡음 — 판정에 섞이면 안 되는 것들
        _ev("msedgewebview2.exe", 3476, "WriteFile", WEBV, F, "Offset: 0, Length: 512"),
        _ev("System", 4, "RegSetValue",
            r"HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1\\Device\HarddiskVolume3\Windows\System32\cmd.exe",
            R, "Type: REG_BINARY"),
        _ev("vmtoolsd.exe", 2204, "ReadFile", r"C:\Program Files\VMware\VMware Tools\vmtools.dll", F, "Offset: 0"),
    ]
    return ev


def build_result(out_dir: Path):
    from core.orchestrator import AnalysisConfig, AnalysisResult
    from parsers.procmon_csv import find_sample_host
    from analysis.ioc_extractor import extract_iocs
    from analysis.behavior_classifier import classify_behaviors
    from analysis.process_behavior_map import build_process_behavior_map
    from analysis.relevance import build_context, annotate, classify_injections
    from analysis.sideload_detector import detect_sideloading, sideload_to_dict, add_sideload_techniques

    cfg = AnalysisConfig(sample_path=Path(SAMPLE), output_dir=out_dir, timeout=60)
    r = AnalysisResult(config=cfg)
    r.start_time, r.end_time = time.time() - 75, time.time()
    r.procmon_events = r.filtered_events = _events()

    host = find_sample_host(r.procmon_events, SAMPLE)
    r.sample_pid = host.child_pid
    r.lineage_pids = {4436, 6632, 7144, 6628, 6596}
    r.all_pids = set(r.lineage_pids) | {3476}

    S = ProcessSnapshot
    r.process_diff = {"terminated_processes": [], "new_processes": [
        S(4436, 900, "WScript.exe", r"C:\Windows\System32\WScript.exe", [r"C:\Windows\System32\WScript.exe", SAMPLE]),
        S(6632, 4436, "cmd.exe", r"C:\Windows\System32\cmd.exe",
          [r"C:\Windows\System32\cmd.exe", "/c", "echo.", ">", SAMPLE + ":Zone.Identifier"]),
        S(7144, 4436, "updater.exe", LOADER, [LOADER, BLOB]),
        S(6628, 7144, "rundll32.exe", r"C:\Windows\System32\rundll32.exe",
          [r"C:\Windows\System32\rundll32.exe", "all", "-k", "--output-path", U + r"\AppData\Local\Temp\57a2"]),
        S(6596, 6628, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
          [r"C:\Program Files\Google\Chrome\Application\chrome.exe", "--headless"]),
        S(5500, 780, "conhost.exe", r"C:\Windows\System32\conhost.exe", ["conhost.exe", "0x4"]),
    ]}
    r.registry_diff = {"added": [(RUNKEY, "updater", COPY)], "modified": [], "deleted": []}

    pc = PcapResult()
    pc.connections = [
        NetworkConnection("TCP", "192.168.133.144", "93.184.216.34", 587, count=6, bytes_out=1800, src_port=49801),
        NetworkConnection("TCP", "192.168.133.144", "150.171.27.11", 443, count=54, bytes_out=23000, src_port=49758),
    ]
    pc.dns_queries = [
        DNSQuery("mail.example-hotel.test", "A", [], no_response=True),
        DNSQuery("edge.microsoft.com", "A", ["150.171.27.11"]),
    ]
    pc.ip_to_domain = {"150.171.27.11": ["edge.microsoft.com"]}
    pc.raw_ips = {"93.184.216.34", "150.171.27.11"}
    pc.raw_domains = {"mail.example-hotel.test", "edge.microsoft.com"}
    r.pcap_result = r.analysis_pcap = pc

    class _Conn:   # ProcNetConnection 대역
        def __init__(s, pid, process, ip, port):
            s.pid, s.process, s.proto, s.remote_ip, s.remote_port = pid, process, "TCP", ip, port
            s.direction, s.event_count, s.local_port = "outbound", 6, 49801
    r.process_network_map = [_Conn(7144, "updater.exe", "93.184.216.34", 587)]

    r.ioc_report = extract_iocs(r.filtered_events, pc, r.registry_diff, r.process_diff)
    r.behavior_report = classify_behaviors(r.filtered_events, pc, r.registry_diff, r.process_diff)
    try:
        sl = detect_sideloading(r.filtered_events, lineage_pids=r.lineage_pids,
                                new_processes=r.process_diff["new_processes"])
        r.sideload_findings = [sideload_to_dict(f) for f in sl]
        add_sideload_techniques(r.behavior_report, sl)
    except Exception as exc:                       # 데모는 일부 실패해도 계속
        print("  (사이드로딩 탐지 생략:", exc, ")")
    r.process_behaviors = build_process_behavior_map(
        r.filtered_events, [], r.process_network_map, r.process_diff["new_processes"])

    ctx = build_context(r, None)
    r.relevance_counts = annotate(r, ctx)
    r.injection_findings = classify_injections(r, ctx)

    # 증거 탭용 — 가상의 경로라 실제 복사는 일어나지 않는다 ("없음"으로 표시됨)
    from core.evidence_collector import collect_evidence
    r.evidence = collect_evidence(r, out_dir)
    return r


def main() -> None:
    ap = argparse.ArgumentParser(description="합성 데이터로 리포트 UI 미리보기 생성")
    ap.add_argument("--out", default=str(ROOT / "results" / "ui-preview"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    from exporters.html_report import generate_html_report
    result = build_result(out)
    html_path = out / "demo_dynamic_report.html"
    generate_html_report(result, str(html_path))
    print(f"HTML → {html_path}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
