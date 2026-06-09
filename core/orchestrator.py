"""
동적 분석 오케스트레이터

전체 워크플로우:
  1. 사전 스냅샷  (레지스트리, 프로세스 목록)
  2. 모니터링 시작 (ProcMon, tshark, Process Hacker)
  3. 샘플 실행
  4. timeout 대기
  5. 샘플·모니터링 종료
  6. 사후 스냅샷 → diff
  7. 파싱 & 분석
  8. 결과 반환
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class AnalysisConfig:
    sample_path:   Optional[Path]        # None → 전체 시스템 모니터링 모드
    output_dir:    Path
    timeout:       int   = 60       # 모니터링 초
    procmon_path:  Optional[str] = None
    tshark_path:   Optional[str] = None
    interface:     Optional[str] = None
    ph_path:       Optional[str] = None   # Process Hacker 경로
    no_procmon:    bool = False
    no_tshark:     bool = False
    no_ph:         bool = False
    external_pcap: Optional[Path] = None  # 외부 PCAP 파일 경로 (Wireshark 등)


@dataclass
class AnalysisResult:
    """전체 분석 결과 컨테이너"""
    config:             AnalysisConfig
    # 원시 데이터
    procmon_events:     list  = field(default_factory=list)   # list[ProcMonEvent]
    filtered_events:    list  = field(default_factory=list)
    pcap_result:        object = None                          # PcapResult
    registry_diff:      dict  = field(default_factory=dict)
    process_diff:       dict  = field(default_factory=dict)
    new_process_snapshots: list = field(default_factory=list)
    # 분석 결과
    behavior_report:    object = None                          # BehaviorReport
    ioc_report:         object = None                          # IOCReport
    # 도구 가용성
    tools_used:         dict  = field(default_factory=dict)
    # 메타
    start_time:         float = 0.0
    end_time:           float = 0.0
    sample_pid:         Optional[int] = None
    all_pids:           set   = field(default_factory=set)    # 샘플 + 자식 PID
    errors:             list  = field(default_factory=list)
    process_network_map: list = field(default_factory=list)  # list[ProcNetConnection]
    yara_result:        object = None                          # YaraScanResult
    pe_sieve_result:    object = None                          # PeSieveResult
    hh_result:          object = None                          # HollowsHunterResult


def run_analysis(
    config: AnalysisConfig,
    on_status: Optional[Callable[[str], None]] = None,
) -> AnalysisResult:
    """
    동적 분석 전체 실행.

    on_status: 진행 상황을 문자열로 콜백받는 함수 (콘솔 출력용)
    """
    def status(msg: str) -> None:
        if on_status:
            on_status(msg)

    result = AnalysisResult(config=config)
    result.start_time = time.time()
    config.output_dir.mkdir(parents=True, exist_ok=True)

    # ── 지연 임포트 (설치 여부 무관하게 로딩) ────────────────────────
    from core.procmon          import ProcMonController, find_procmon
    from core.tshark_capture   import TsharkCapture, find_tshark
    from core.registry_snapshot import take_snapshot, diff_snapshots, AVAILABLE as REG_AVAILABLE
    from core.process_tracker  import (
        take_process_snapshot, diff_process_snapshots,
        find_process_hacker, launch_process_hacker,
    )
    from parsers.procmon_csv   import parse_csv, get_child_pids as pm_child_pids
    from parsers.pcap_parser   import parse_pcap, PcapResult
    from analysis.noise_filter import filter_events
    from analysis.behavior_classifier import classify_behaviors
    from analysis.ioc_extractor       import extract_iocs
    from analysis.process_network_map import build_process_network_map
    from analysis.yara_scanner        import run_yara_scan
    from core.pesieve_scanner         import PeSieveScanner
    from core.hollows_hunter          import HollowsHunter
    from parsers.pesieve_result       import parse_pesieve, parse_hollows_hunter

    # ── 도구 초기화 ──────────────────────────────────────────────────
    pm = ProcMonController(
        config.output_dir,
        procmon_path=config.procmon_path or find_procmon(),
    )
    ts = TsharkCapture(
        config.output_dir,
        tshark_path=config.tshark_path or find_tshark(),
        interface=config.interface,
    )
    ph_path    = config.ph_path or find_process_hacker()
    ps_scanner = PeSieveScanner(config.output_dir / "dumps")
    hh_scanner = HollowsHunter(config.output_dir / "dumps")

    result.tools_used = {
        "procmon":          pm.available and not config.no_procmon,
        "tshark":           ts.available and not config.no_tshark,
        "registry_snapshot": REG_AVAILABLE,
        "process_hacker":   ph_path is not None and not config.no_ph,
        "pe_sieve":         ps_scanner.available,
        "hollows_hunter":   hh_scanner.available,
    }

    status(f"[도구 확인] ProcMon={'✔' if result.tools_used['procmon'] else '✘'}  "
           f"tshark={'✔' if result.tools_used['tshark'] else '✘'}  "
           f"RegSnap={'✔' if result.tools_used['registry_snapshot'] else '✘'}  "
           f"ProcHacker={'✔' if result.tools_used['process_hacker'] else '✘'}  "
           f"pe-sieve={'✔' if result.tools_used['pe_sieve'] else '✘'}  "
           f"HollowsHunter={'✔' if result.tools_used['hollows_hunter'] else '✘'}")

    # ── 1. 사전 스냅샷 ────────────────────────────────────────────────
    status("[1/6] 사전 스냅샷 수집 중...")
    reg_before = take_snapshot() if REG_AVAILABLE else {}
    proc_before = take_process_snapshot()

    # ── 2. 모니터링 시작 ──────────────────────────────────────────────
    status("[2/6] 모니터링 시작...")

    if result.tools_used["procmon"]:
        ok = pm.start()
        if not ok:
            result.errors.append("ProcMon 시작 실패")
            result.tools_used["procmon"] = False

    if result.tools_used["tshark"]:
        ok = ts.start(config.timeout + 10)
        if not ok:
            result.errors.append("tshark 시작 실패")
            result.tools_used["tshark"] = False

    ph_proc = None
    if result.tools_used["process_hacker"]:
        ph_proc = launch_process_hacker(ph_path)
        if ph_proc is None:
            result.tools_used["process_hacker"] = False

    # ── 3. 샘플 실행 (파일 지정 시에만) ─────────────────────────────
    sample_proc = None
    if config.sample_path:
        status(f"[3/6] 샘플 실행: {config.sample_path.name}")
        try:
            sample_proc = subprocess.Popen(
                [str(config.sample_path)],
                cwd=str(config.sample_path.parent),
            )
            result.sample_pid = sample_proc.pid
            result.all_pids.add(sample_proc.pid)
            status(f"      PID: {sample_proc.pid}")
        except Exception as e:
            result.errors.append(f"샘플 실행 실패: {e}")
            status(f"[오류] 샘플 실행 실패: {e}")
    else:
        status(f"[3/6] 전체 시스템 모니터링 모드 — 직접 프로그램을 실행하세요")

    # ── 4. 모니터링 대기 ──────────────────────────────────────────────
    status(f"[4/6] 모니터링 중... ({config.timeout}초)  Ctrl+C로 조기 종료 가능")
    elapsed = 0
    interval = 5
    sample_exited = False
    try:
        while elapsed < config.timeout:
            time.sleep(interval)
            elapsed += interval
            # 샘플 종료 감지 — 자식 프로세스 활동을 위해 타임아웃까지 계속 모니터링
            if sample_proc and not sample_exited and sample_proc.poll() is not None:
                sample_exited = True
                status(f"      샘플 종료 감지 ({elapsed}s) — 자식 프로세스 모니터링 계속...")
            remaining = config.timeout - elapsed
            status(f"      {elapsed}s 경과 / 잔여 {remaining}s...")
    except KeyboardInterrupt:
        status(f"\n[!] Ctrl+C 감지 — {elapsed}s 시점 데이터로 분석을 마무리합니다...")

    # ── 5. 종료 ───────────────────────────────────────────────────────
    status("[5/6] 모니터링 종료...")

    # pe-sieve / hollows-hunter 스캔 (프로세스 종료 전 — 가능한 많은 PID가 살아있을 때)
    if hh_scanner.available:
        status("[분석] hollows-hunter 전체 프로세스 스캔...")
        raw = hh_scanner.scan_all(dump_mode=1, shellcode=True, hooks=True)
        result.hh_result = parse_hollows_hunter(raw)
        if result.hh_result.error:
            result.errors.append(f"hollows-hunter: {result.hh_result.error}")
        else:
            susp_cnt = len(result.hh_result.suspicious_processes)
            shc_cnt  = sum(r.implanted_shc for r in result.hh_result.process_results)
            status(f"      의심 프로세스: {susp_cnt}개  쉘코드 영역: {shc_cnt}개"
                   + (" 🚨" if shc_cnt else " ✅"))
    elif ps_scanner.available and result.sample_pid:
        status(f"[분석] pe-sieve 스캔 (PID {result.sample_pid})...")
        raw = ps_scanner.scan_pid(result.sample_pid, dump_mode=1, shellcode=True, hooks=True)
        result.pe_sieve_result = parse_pesieve(raw)
        if result.pe_sieve_result.error:
            result.errors.append(f"pe-sieve: {result.pe_sieve_result.error}")
        else:
            status(f"      의심 모듈: {result.pe_sieve_result.suspicious}개  "
                   f"쉘코드: {result.pe_sieve_result.implanted_shc}개"
                   + (" 🚨" if result.pe_sieve_result.implanted_shc else " ✅"))
    else:
        status("      [알림] pe-sieve / hollows-hunter 없음 — 메모리 스캔 생략")

    # 샘플 강제 종료
    if sample_proc and sample_proc.poll() is None:
        try:
            sample_proc.terminate()
            sample_proc.wait(timeout=5)
        except Exception:
            try:
                sample_proc.kill()
            except Exception:
                pass

    # ProcMon 중지 + CSV 변환
    if result.tools_used["procmon"]:
        pm.stop()
        status("      ProcMon 로그 변환 중...")
        pm.export_csv()

    # tshark 중지 (duration으로 자동 종료됐을 수 있음)
    if result.tools_used["tshark"]:
        ts.stop()

    # Process Hacker / System Informer 종료
    if ph_proc is not None and ph_proc.poll() is None:
        try:
            ph_proc.terminate()
            ph_proc.wait(timeout=5)
            status("      Process Hacker 종료됨")
        except Exception:
            try:
                ph_proc.kill()
            except Exception:
                pass

    # ── 6. 사후 스냅샷 ────────────────────────────────────────────────
    status("[6/6] 사후 스냅샷 수집 중...")
    reg_after  = take_snapshot() if REG_AVAILABLE else {}
    proc_after = take_process_snapshot()

    result.registry_diff = diff_snapshots(reg_before, reg_after) if REG_AVAILABLE else {}
    result.process_diff  = diff_process_snapshots(proc_before, proc_after)

    # ── 7. 파싱 ─────────────────────────────────────────────────────
    status("[분석] ProcMon CSV 파싱...")
    if pm.csv_path.exists():
        result.procmon_events = parse_csv(pm.csv_path)
        # 자식 PID 추적
        if result.sample_pid:
            child_pids = pm_child_pids(result.procmon_events, result.sample_pid)
            result.all_pids.update(child_pids)
        # 포커스 PID 기반 필터
        result.filtered_events = filter_events(
            result.procmon_events,
            focus_pids=result.all_pids if result.all_pids else None,
        )
        status(f"      이벤트 {len(result.procmon_events):,}개 → 필터 후 {len(result.filtered_events):,}개")

    status("[분석] PCAP 파싱...")
    from parsers.pcap_parser import SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        if ts.tshark_path:
            status("      scapy 없음 → tshark 파서로 대체 분석")
        else:
            status("      [경고] scapy·tshark 모두 없음 — 네트워크 분석 불가 (pip install scapy)")

    # 우선순위: 외부 PCAP(--pcap) > tshark 캡처 파일
    pcap_target = None
    if config.external_pcap and config.external_pcap.exists():
        pcap_target = config.external_pcap
        status(f"      외부 PCAP 사용: {config.external_pcap.name}  "
               f"({config.external_pcap.stat().st_size:,} bytes)")
    elif ts.pcap_path.exists():
        pcap_target = ts.pcap_path
        status(f"      캡처 파일: {ts.pcap_path.name}  "
               f"({ts.pcap_path.stat().st_size:,} bytes)")

    tshark_bin = str(ts.tshark_path) if ts.tshark_path else None
    if pcap_target:
        result.pcap_result = parse_pcap(pcap_target, tshark_path=tshark_bin)
        pr = result.pcap_result
        if pr.parse_error:
            status(f"      [오류] {pr.parse_error}")
            result.errors.append(f"PCAP 파싱 오류: {pr.parse_error}")
        else:
            ip_only = pr.packets_loaded - pr.packets_skipped
            status(f"      패킷 {pr.packets_loaded:,}개 로드  "
                   f"(IP/TCP/UDP {ip_only:,}개, 건너뜀 {pr.packets_skipped:,}개)")
            status(f"      연결 {len(pr.connections)}개  "
                   f"DNS {len(pr.dns_queries)}건  "
                   f"TLS SNI {len(pr.tls_info)}건  "
                   f"HTTP {len(pr.http_requests)}건")
            if pr.beacon_candidates:
                status(f"      [!] 비콘 의심 {len(pr.beacon_candidates)}개 탐지")
            if pr.suspicious_domains:
                status(f"      [!] 의심 도메인 {len(pr.suspicious_domains)}개 (DGA/터널링)")
    else:
        from parsers.pcap_parser import PcapResult as _PR
        result.pcap_result = _PR()
        if not config.no_tshark:
            status("      PCAP 파일 없음 (tshark 미실행 또는 캡처 실패)")

    # ── 8. 행동 분류 + IOC ──────────────────────────────────────────
    status("[분석] 행동 분류 및 MITRE ATT&CK 매핑...")
    result.behavior_report = classify_behaviors(
        result.filtered_events,
        result.pcap_result,
        result.registry_diff,
        result.process_diff,
    )
    result.ioc_report = extract_iocs(
        result.filtered_events,
        result.pcap_result,
        result.registry_diff,
        result.process_diff,
    )

    status("[분석] 프로세스↔네트워크 연결 매핑...")
    result.process_network_map = build_process_network_map(result.filtered_events)
    if result.process_network_map:
        status(f"      {len(result.process_network_map)}개 연결 집계")

    status("[분석] YARA 룰 스캔...")
    dropped = result.ioc_report.dropped_files if result.ioc_report else []
    result.yara_result = run_yara_scan(config.sample_path, dropped)
    yr = result.yara_result
    if yr.available:
        status(f"      룰 {yr.rules_loaded:,}개 로드"
               + (f" / {yr.rules_failed}개 실패" if yr.rules_failed else ""))
        status(f"      파일 {len(yr.files_scanned)}개 스캔 → 탐지 {len(yr.matches)}건"
               + (" 🚨" if yr.matches else " ✅"))
    else:
        status(f"      [경고] {yr.error}")

    result.end_time = time.time()
    elapsed_total = result.end_time - result.start_time
    status(f"[완료] 총 소요 {elapsed_total:.1f}초")

    return result
