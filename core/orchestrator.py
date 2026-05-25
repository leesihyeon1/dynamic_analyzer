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
    sample_path:   Path
    output_dir:    Path
    timeout:       int   = 60       # 모니터링 초
    procmon_path:  Optional[str] = None
    tshark_path:   Optional[str] = None
    interface:     Optional[str] = None
    ph_path:       Optional[str] = None   # Process Hacker 경로
    no_procmon:    bool = False
    no_tshark:     bool = False
    no_ph:         bool = False


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
        get_child_pids, find_process_hacker, launch_process_hacker,
    )
    from parsers.procmon_csv   import parse_csv, get_child_pids as pm_child_pids
    from parsers.pcap_parser   import parse_pcap, PcapResult
    from analysis.noise_filter import filter_events
    from analysis.behavior_classifier import classify_behaviors
    from analysis.ioc_extractor import extract_iocs

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
    ph_path = config.ph_path or find_process_hacker()

    result.tools_used = {
        "procmon":          pm.available and not config.no_procmon,
        "tshark":           ts.available and not config.no_tshark,
        "registry_snapshot": REG_AVAILABLE,
        "process_hacker":   ph_path is not None and not config.no_ph,
    }

    status(f"[도구 확인] ProcMon={'✔' if result.tools_used['procmon'] else '✘'}  "
           f"tshark={'✔' if result.tools_used['tshark'] else '✘'}  "
           f"RegSnap={'✔' if result.tools_used['registry_snapshot'] else '✘'}  "
           f"ProcHacker={'✔' if result.tools_used['process_hacker'] else '✘'}")

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

    if result.tools_used["process_hacker"]:
        ph_proc = launch_process_hacker(ph_path)
        if ph_proc is None:
            result.tools_used["process_hacker"] = False

    # ── 3. 샘플 실행 ──────────────────────────────────────────────────
    status(f"[3/6] 샘플 실행: {config.sample_path.name}")
    sample_proc = None
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

    # ── 4. 모니터링 대기 ──────────────────────────────────────────────
    status(f"[4/6] 모니터링 중... ({config.timeout}초)")
    elapsed = 0
    interval = 5
    while elapsed < config.timeout:
        time.sleep(interval)
        elapsed += interval
        # 프로세스가 이미 종료됐으면 중간 스냅샷
        if sample_proc and sample_proc.poll() is not None:
            status(f"      샘플 종료 감지 ({elapsed}s)")
            break
        remaining = config.timeout - elapsed
        status(f"      {elapsed}s 경과 / 잔여 {remaining}s...")

    # ── 5. 종료 ───────────────────────────────────────────────────────
    status("[5/6] 모니터링 종료...")

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
    if ts.pcap_path.exists():
        result.pcap_result = parse_pcap(ts.pcap_path)
        status(f"      연결 {len(result.pcap_result.connections)}개  "
               f"DNS {len(result.pcap_result.dns_queries)}건")
    else:
        from parsers.pcap_parser import PcapResult as _PR
        result.pcap_result = _PR()

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

    result.end_time = time.time()
    elapsed_total = result.end_time - result.start_time
    status(f"[완료] 총 소요 {elapsed_total:.1f}초")

    return result
