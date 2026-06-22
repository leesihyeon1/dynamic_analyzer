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

import ctypes
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


def _kill_analysis_tool(
    proc,
    exe_names: list,
    status,
    label: str = "분석 도구",
) -> None:
    """
    GUI 분석 도구를 3단계로 확실하게 종료합니다.

    1. Popen 핸들로 terminate → kill
       (UAC self-elevate 케이스에서는 핸들이 이미 죽어있을 수 있음)
    2. psutil 프로세스 이름 검색 → kill
       (실제 실행 중인 프로세스를 이름으로 찾아 종료)
    3. taskkill /F /IM 폴백
       (psutil 도 없거나 권한 문제일 때)
    """
    import subprocess as _sp

    killed_via_handle = False

    # ── Step 1: Popen 핸들 ─────────────────────────────────────────
    if proc is not None:
        try:
            if proc.poll() is None:          # 아직 살아있을 때만
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                    killed_via_handle = True
                except Exception:
                    try:
                        proc.kill()
                        killed_via_handle = True
                    except Exception:
                        pass
        except Exception:
            pass

    # ── Step 2: psutil 이름 검색 ───────────────────────────────────
    names_lower = {n.lower() for n in exe_names}
    psutil_killed: list[str] = []
    try:
        import psutil as _ps
        for p in _ps.process_iter(["pid", "name"]):
            try:
                if (p.info["name"] or "").lower() in names_lower:
                    p.kill()
                    psutil_killed.append(p.info["name"])
            except (_ps.NoSuchProcess, _ps.AccessDenied, _ps.ZombieProcess):
                pass
    except ImportError:
        pass
    except Exception:
        pass

    if psutil_killed:
        status(f"      {label} 종료됨 (psutil: {', '.join(set(psutil_killed))})")
        return

    if killed_via_handle:
        status(f"      {label} 종료됨")
        return

    # ── Step 3: taskkill /F 폴백 ────────────────────────────────────
    for name in exe_names:
        try:
            r = _sp.run(
                ["taskkill", "/F", "/IM", name, "/T"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                status(f"      {label} 종료됨 (taskkill: {name})")
                return
        except Exception:
            pass


# ── 의심 DLL 로드 경로 ────────────────────────────────────────────────────
# 거의 항상 악성: Temp 계열 디렉터리에서 DLL을 로드하는 기존 프로세스
# 주의: 백슬래시를 이중 이스케이프(\\)로 표기해야 path.lower() in 비교가 정확히 동작함
_INJECT_SUSP: tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\recycle",              # 휴지통 경유 은닉
)

# 시스템 정상 경로 — 여기서 로드되면 무시
_INJECT_SAFE: tuple[str, ...] = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\",
    "\\windows\\fonts\\",
)


def _find_injection_targets(
    events:          list,
    already_scanned: set[int],
    sample_pids:     set[int],
) -> set[int]:
    """ProcMon 전체 이벤트에서 의심 경로 DLL을 로드한 기존 프로세스 PID를 반환합니다."""
    from parsers.procmon_csv import EventCategory

    target_pids: set[int] = set()
    for ev in events:
        if ev.category != EventCategory.PROCESS or ev.operation != "Load Image" or ev.pid == 0:
            continue
        if ev.pid in already_scanned or ev.pid in sample_pids:
            continue
        path_lower = ev.path.lower()
        if any(safe in path_lower for safe in _INJECT_SAFE):
            continue
        if any(susp in path_lower for susp in _INJECT_SUSP):
            target_pids.add(ev.pid)
    return target_pids


def _scan_procmon_once(
    events:          list,
    already_scanned: set[int],
    sample_pids:     set[int],
) -> "tuple[set[int], list]":
    """procmon_events 를 단일 패스로 순회해 두 결과를 동시 수집합니다.

    Returns
    -------
    (injection_pids, process_network_map)
        injection_pids      — _find_injection_targets 와 동일
        process_network_map — build_process_network_map 과 동일
    """
    from parsers.procmon_csv import EventCategory
    from analysis.process_network_map import (
        ProcNetConnection,
        _OUTBOUND_OPS, _INBOUND_OPS, _parse_path, _is_private,
    )

    inject_pids: set[int] = set()
    net_agg: dict = {}

    for ev in events:
        cat = ev.category

        # ── 인젝션 탐지 (PROCESS / Load Image) ──────────────────────
        if cat == EventCategory.PROCESS and ev.operation == "Load Image" and ev.pid != 0:
            if ev.pid not in already_scanned and ev.pid not in sample_pids:
                pl = ev.path.lower()
                if not any(s in pl for s in _INJECT_SAFE) and any(s in pl for s in _INJECT_SUSP):
                    inject_pids.add(ev.pid)

        # ── 네트워크 맵 (TCP/UDP outbound/inbound) ───────────────────
        elif cat == EventCategory.NETWORK:
            op = ev.operation
            if op in _OUTBOUND_OPS:
                direction = "outbound"
            elif op in _INBOUND_OPS:
                direction = "inbound"
            else:
                continue
            proto = "TCP" if op.startswith("TCP") else "UDP"
            _, _, remote_ip, remote_port = _parse_path(ev.path)
            if remote_ip is None or remote_port is None or _is_private(remote_ip):
                continue
            key = (ev.pid, ev.process, proto, remote_ip, remote_port, direction)
            if key in net_agg:
                net_agg[key].event_count += 1
            else:
                net_agg[key] = ProcNetConnection(
                    pid=ev.pid, process=ev.process, proto=proto,
                    remote_ip=remote_ip, remote_port=remote_port,
                    direction=direction, event_count=1,
                )

    net_map = sorted(
        net_agg.values(),
        key=lambda c: (-c.event_count, c.process.lower(), c.remote_ip),
    )
    return inject_pids, net_map


def _merge_external_techniques(report, new_techs: list) -> None:
    """
    외부 도구(CAPA, VT) 기법을 BehaviorReport 에 병합합니다.

    - 이미 존재하는 technique_id: evidence + sources 만 보완
    - 신규 technique_id: 목록 끝에 추가 후 전술 우선순위로 재정렬
    """
    from analysis.behavior_classifier import _tactic_key

    existing = {t.technique_id: t for t in report.techniques}
    added: list = []

    for nt in new_techs:
        if nt.technique_id in existing:
            et = existing[nt.technique_id]
            for ev in nt.evidence:
                if ev not in et.evidence:
                    et.evidence.append(ev)
            for src in (nt.sources or []):
                if src not in et.sources:
                    et.sources.append(src)
        else:
            added.append(nt)
            existing[nt.technique_id] = nt

    report.techniques.extend(added)
    report.techniques.sort(key=_tactic_key)


def _pid_alive(pid: int) -> bool:
    """프로세스가 현재 살아있는지 확인 (Windows 전용)."""
    try:
        # PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — 최소 권한
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        # GetExitCodeProcess → STILL_ACTIVE(259) 이면 살아있음
        code = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    except Exception:
        return False


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
    # ── TLS 복호화 옵션 ──────────────────────────────────────────────
    use_keylog:   bool = True             # SSLKEYLOGFILE 환경변수 주입
    use_fakenet:  bool = False            # FakeNet-NG 실행 (tshark 대체)
    fakenet_path: Optional[str] = None   # FakeNet-NG 실행파일 명시 경로
    # ── 메모리 포렌식 옵션 ───────────────────────────────────────────
    use_memdump:      bool = False        # 물리 메모리 덤프 + Volatility3 실행
    winpmem_path:     Optional[str] = None
    volatility_path:  Optional[str] = None
    dump_timeout:     int  = 600          # 메모리 덤프 타임아웃 (초)
    vol_plugin_timeout: int = 300         # 플러그인당 타임아웃 (초)
    existing_dump:    Optional[str] = None  # 기존 덤프 재사용
    # ── AI 분석 옵션 ─────────────────────────────────────────────────
    use_ai:       bool = True               # Ollama AI 분석 사용
    ai_model:     str  = "qwen2.5:7b"      # Ollama 모델 이름
    ollama_url:   str  = "http://localhost:11434"
    ai_timeout:   int  = 600               # AI 응답 타임아웃 (초)


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
    pe_sieve_results:   list  = field(default_factory=list)    # list[PeSieveResult] — 신규 프로세스별 스캔
    hh_result:          object = None                          # HollowsHunterResult — 전체 시스템 스캔
    proc_after_snapshot: dict = field(default_factory=dict)   # dict[int, ProcessSnapshot] — 사후 스냅샷 (트리 빌드용)
    # ── TLS 복호화 결과 ──────────────────────────────────────────────
    decrypted_requests: list  = field(default_factory=list)   # list[DecryptedRequest] — SSLKEYLOGFILE 복호화
    tls_key_count:      int   = 0                              # 기록된 TLS 세션 키 수
    fakenet_result:     dict  = field(default_factory=dict)   # FakeNet-NG 결과 dict
    # ── 메모리 포렌식 결과 ───────────────────────────────────────────
    mem_forensics:      dict  = field(default_factory=dict)   # MemForensicsResult dict
    # ── AI 분석 결과 ─────────────────────────────────────────────────
    ai_analysis:        dict  = field(default_factory=dict)   # AiAnalysisResult dict


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
    from core.pesieve_scanner         import PeSieveScanner
    from core.hollows_hunter          import HollowsHunter
    from parsers.pesieve_result       import parse_pesieve, parse_hollows_hunter
    from core.config_loader           import load_config as _load_cfg_early
    from core.tls_keylog              import TLSKeyLogger
    from core.fakenet_integrator      import FakeNetIntegrator, fakenet_result_to_dict
    from core.memory_forensics        import run_memory_forensics, memforensics_to_dict, find_winpmem, find_volatility3
    from core.ai_analyzer             import OllamaAnalyzer, ai_analysis_to_dict

    # ── 도구 초기화 ──────────────────────────────────────────────────
    _early_cfg  = _load_cfg_early()
    _tools_cfg  = _early_cfg.get("tools", {})

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
    ps_scanner = PeSieveScanner(
        config.output_dir / "dumps",
        config_path=_tools_cfg.get("pe_sieve") or None,
    )
    hh_scanner = HollowsHunter(
        config.output_dir / "dumps",
        config_path=_tools_cfg.get("hollows_hunter") or None,
    )

    # ── TLS 복호화 도구 초기화 ────────────────────────────────────────
    tls_keylogger = TLSKeyLogger(config.output_dir) if config.use_keylog else None
    fakenet = FakeNetIntegrator(
        config.output_dir,
        fakenet_path=Path(config.fakenet_path) if config.fakenet_path else None,
    ) if config.use_fakenet else None

    result.tools_used = {
        "procmon":          pm.available and not config.no_procmon,
        "tshark":           ts.available and not config.no_tshark,
        "registry_snapshot": REG_AVAILABLE,
        "process_hacker":   ph_path is not None and not config.no_ph,
        "pe_sieve":         ps_scanner.available,
        "hollows_hunter":   hh_scanner.available,
        "tls_keylog":       tls_keylogger is not None,
        "fakenet":          fakenet is not None and (fakenet.is_available() if fakenet else False),
        "memdump":          config.use_memdump and (find_winpmem() is not None or bool(config.existing_dump)),
        "volatility3":      config.use_memdump and find_volatility3() is not None,
    }

    status(f"[도구 확인] ProcMon={'✔' if result.tools_used['procmon'] else '✘'}  "
           f"tshark={'✔' if result.tools_used['tshark'] else '✘'}  "
           f"RegSnap={'✔' if result.tools_used['registry_snapshot'] else '✘'}  "
           f"ProcHacker={'✔' if result.tools_used['process_hacker'] else '✘'}  "
           f"pe-sieve={'✔' if result.tools_used['pe_sieve'] else '✘'}  "
           f"HollowsHunter={'✔' if result.tools_used['hollows_hunter'] else '✘'}  "
           f"TLS-keylog={'✔' if result.tools_used['tls_keylog'] else '✘'}  "
           f"FakeNet={'✔' if result.tools_used['fakenet'] else '✘'}")

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

    if result.tools_used["tshark"] and not config.use_fakenet:
        ok = ts.start(config.timeout + 10)
        if not ok:
            result.errors.append("tshark 시작 실패")
            result.tools_used["tshark"] = False

    # FakeNet-NG 시작 (tshark 대신 사용 — DNS 리다이렉트 + 프로토콜 가로채기)
    if fakenet and result.tools_used["fakenet"]:
        ok = fakenet.start()
        if not ok:
            result.errors.append("FakeNet-NG 시작 실패")
            result.tools_used["fakenet"] = False
        else:
            status("      FakeNet-NG 실행 중 (DNS 리다이렉션 + 프로토콜 인터셉트)")

    ph_proc = None
    if result.tools_used["process_hacker"]:
        ph_proc = launch_process_hacker(ph_path)
        if ph_proc is None:
            result.tools_used["process_hacker"] = False

    # ── 3. 샘플 실행 (파일 지정 시에만) ─────────────────────────────
    # 확장자별 실행 방법 분기:
    #   Office 문서 / 스크립트 / PDF → os.startfile (ShellExecute, 연관 앱으로 열기)
    #   실행 파일 (.exe / .dll 등)   → subprocess.Popen (직접 실행, PID 추적 가능)
    _SHELL_EXEC_SUFFIXES: frozenset[str] = frozenset({
        # Office 문서
        ".doc", ".docx", ".docm", ".dot", ".dotm",
        ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
        ".ppt", ".pptx", ".pptm", ".pot", ".potm",
        ".rtf", ".pdf", ".odt", ".ods", ".odp",
        # 스크립트 / 웹 기반 실행 파일
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
        ".hta", ".ps1", ".psm1", ".psd1",
        # 링크 / URL
        ".url", ".lnk",
    })

    sample_proc = None
    if config.sample_path:
        status(f"[3/6] 샘플 실행: {config.sample_path.name}")
        ext = config.sample_path.suffix.lower()
        try:
            if ext in _SHELL_EXEC_SUFFIXES:
                # Office/스크립트/PDF 등 — 연관 앱(Word, wscript 등)으로 ShellExecute
                # 기존 인스턴스가 살아있으면 DDE 핸드오프로 새 PID 가 즉시 종료됨.
                # → startfile 전에 호스트 앱을 종료해 추적 가능한 새 PID 를 생성.
                _OFFICE_HOSTS: list[tuple[frozenset, str, list[str]]] = [
                    (frozenset({".doc", ".docx", ".docm", ".dot", ".dotm", ".rtf"}),
                     "기존 Word 인스턴스", ["winword.exe"]),
                    (frozenset({".xls", ".xlsx", ".xlsm", ".xlt", ".xltm"}),
                     "기존 Excel 인스턴스", ["excel.exe"]),
                    (frozenset({".ppt", ".pptx", ".pptm", ".pot", ".potm"}),
                     "기존 PowerPoint 인스턴스", ["powerpnt.exe"]),
                ]
                for _exts, _label, _exes in _OFFICE_HOSTS:
                    if ext in _exts:
                        _kill_analysis_tool(None, exe_names=_exes, status=status, label=_label)
                        break
                import os as _os
                _os.startfile(str(config.sample_path))
                result.sample_pid = None   # 호스트 앱 PID는 procmon/process_diff 로 추적
                status(f"      ShellExecute 실행 ({ext}) — 호스트 앱 PID는 procmon이 추적")
            else:
                _sample_env = tls_keylogger.get_env() if tls_keylogger else None
                sample_proc = subprocess.Popen(
                    [str(config.sample_path)],
                    cwd=str(config.sample_path.parent),
                    env=_sample_env,
                )
                result.sample_pid = sample_proc.pid
                result.all_pids.add(sample_proc.pid)
                _klog_note = f" + SSLKEYLOGFILE 주입" if tls_keylogger else ""
                status(f"      PID: {sample_proc.pid}{_klog_note}")
        except Exception as e:
            result.errors.append(f"샘플 실행 실패: {e}")
            status(f"[오류] 샘플 실행 실패: {e}")
    else:
        status(f"[3/6] 전체 시스템 모니터링 모드 — 직접 프로그램을 실행하세요")

    # ── 4. 모니터링 대기 ──────────────────────────────────────────────
    status(f"[4/6] 모니터링 중... ({config.timeout}초)  Ctrl+C로 조기 종료 가능")
    _netstat_snaps: list[list[tuple[str, int, int]]] = []  # KeyboardInterrupt 전 참조 방지

    # ── 실시간 프로세스 감시 시작 (신규 PID → 즉시 pe-sieve 스캔)
    # proc_before에 없는 PID가 생성되면 1초 이내에 자동 스캔하여
    # 단명 프로세스(loader, injector 등)도 포착할 수 있도록 함
    _rt_results: list[tuple[int, dict]] = []
    _rt_lock    = threading.Lock()

    def _rt_callback(pid: int, raw: dict) -> None:
        with _rt_lock:
            _rt_results.append((pid, raw))

    from core.process_watcher import ProcessWatcher
    watcher = ProcessWatcher(
        initial_pids  = set(proc_before.keys()),
        scanner       = ps_scanner,
        on_result     = _rt_callback,
        dump_mode     = 3,   # raw dump — PE + 쉘코드 모두 추출
        poll_interval = 1.0,
    )
    watcher.start()
    if watcher.available:
        _mode_label = (
            "WMI ETW (즉시 감지)"
            if watcher.detection_mode == "wmi_etw"
            else "psutil 폴링 (1초 간격)"
        )
        status(f"      [실시간] 신규 프로세스 감시 시작 — {_mode_label}")

    elapsed = 0
    interval = 5
    sample_exited = False
    _snap_tick = 0
    from analysis.process_network_map import capture_netstat_snapshot as _ns_snap
    try:
        while elapsed < config.timeout:
            time.sleep(interval)
            elapsed += interval
            _snap_tick += 1
            # 10초마다 netstat 스냅샷 수집
            if _snap_tick % 2 == 0:
                _snap = _ns_snap()
                if _snap:
                    _netstat_snaps.append(_snap)
            # 샘플 종료 감지 — 자식 프로세스 활동을 위해 타임아웃까지 계속 모니터링
            if sample_proc and not sample_exited and sample_proc.poll() is not None:
                sample_exited = True
                status(f"      샘플 종료 감지 ({elapsed}s) — 자식 프로세스 모니터링 계속...")
            remaining = config.timeout - elapsed
            status(f"      {elapsed}s 경과 / 잔여 {remaining}s...")
    except KeyboardInterrupt:
        status(f"\n[!] Ctrl+C 감지 — {elapsed}s 시점 데이터로 분석을 마무리합니다...")
    # 타임아웃 종료 직후 최종 스냅샷 (연결이 살아있는 마지막 순간 포착)
    try:
        _final_snap = _ns_snap()
        if _final_snap:
            _netstat_snaps.append(_final_snap)
    except Exception:
        pass

    # ── 5. 종료 ───────────────────────────────────────────────────────
    status("[5/6] 모니터링 종료...")

    # ── 실시간 감시 중지 + 결과 병합 ────────────────────────────────────
    # watcher가 스캔한 PID 집합 확보 (중복 스캔 방지에 사용)
    rt_scanned_pids: set[int] = watcher.stop()
    if watcher.available and rt_scanned_pids:
        status(f"      [실시간] 스캔된 PID {len(rt_scanned_pids)}개 — 결과 취합 중...")

    with _rt_lock:
        rt_snapshot = list(_rt_results)

    rt_suspicious = 0
    for pid, raw in rt_snapshot:
        pr = parse_pesieve(raw)
        result.pe_sieve_results.append(pr)
        if pr.suspicious > 0:
            rt_suspicious += 1
            inj_parts = []
            if pr.implanted_pe:
                inj_parts.append(f"PE인젝션 {pr.implanted_pe}개")
            if pr.implanted_shc:
                inj_parts.append(f"쉘코드 {pr.implanted_shc}개")
            inj_str = "  ".join(inj_parts) if inj_parts else f"의심모듈 {pr.suspicious}개"
            status(f"      [실시간] PID {pid}: 의심 {pr.suspicious}개  {inj_str} 🚨")

    if watcher.available:
        status(f"      [실시간] 완료: 의심 {rt_suspicious}개 PID"
               + (" 🚨" if rt_suspicious else " ✅"))

    # ── 중간 프로세스 스냅샷 → 아직 살아있는 신규 PID 보완 스캔
    # 실시간 감시에서 놓친 PID(감시 시작 전 생성됐거나 스캔 실패)를 추가 포착
    proc_mid  = take_process_snapshot()
    mid_diff  = diff_process_snapshots(proc_before, proc_mid)
    # 이미 실시간 스캔된 PID는 제외 (중복 방지)
    already_scanned = rt_scanned_pids | {r.pid for r in result.pe_sieve_results}
    scan_pids: list = [
        p.pid for p in mid_diff.get("new_processes", [])
        if p.pid not in already_scanned
    ]
    if result.sample_pid and result.sample_pid not in already_scanned:
        scan_pids.insert(0, result.sample_pid)
    if scan_pids:
        status(f"      [보완] 추가 스캔 대상 PID: {scan_pids}")

    # pe-sieve / hollows-hunter 스캔 (프로세스 종료 전 — 가능한 많은 PID가 살아있을 때)
    if hh_scanner.available:
        status("[분석] hollows-hunter 전체 프로세스 스캔...")
        raw = hh_scanner.scan_all(dump_mode=3, shellcode=1, hooks=True)
        result.hh_result = parse_hollows_hunter(raw)
        if result.hh_result.error:
            status(f"      [hollows-hunter] {result.hh_result.error}")
            hh_out = (raw.get("stdout") or "").strip()
            hh_err = (raw.get("stderr") or "").strip()
            if hh_out:
                status(f"        [hh stdout] {hh_out[:200]}")
            elif hh_err:
                status(f"        [hh stderr] {hh_err[:200]}")
        else:
            # total_scanned=0 은 JSON 키 불일치 가능성 — 실제 키 목록을 진단용으로 출력
            if result.hh_result.total_scanned == 0 and not result.hh_result.error:
                hh_keys = [k for k in raw if not k.startswith("_") and k != "dump_dir"]
                status(f"      [hollows-hunter 진단] JSON 최상위 키: {hh_keys}")
            susp_cnt = len(result.hh_result.suspicious_processes)
            shc_cnt  = sum(r.implanted_shc for r in result.hh_result.process_results)
            status(f"      의심 프로세스: {susp_cnt}개  쉘코드 영역: {shc_cnt}개"
                   + (" 🚨" if shc_cnt else " ✅"))

    if ps_scanner.available and scan_pids:
        # hollows-hunter 실행 후 일부 PID가 이미 종료됐을 수 있으므로 생존 여부 확인
        alive_pids = [p for p in scan_pids if _pid_alive(p)]
        dead_pids  = [p for p in scan_pids if p not in alive_pids]
        if dead_pids:
            status(f"      [알림] 이미 종료된 PID (스캔 생략): {dead_pids}")
        status(f"[분석] pe-sieve 신규 프로세스 스캔 ({len(alive_pids)}개 PID)...")
        _ps_workers = min(3, len(alive_pids)) if alive_pids else 1
        with ThreadPoolExecutor(max_workers=_ps_workers) as _ps_pool:
            _ps_futures = {
                _ps_pool.submit(ps_scanner.scan_pid, pid, dump_mode=3, shellcode=1): pid
                for pid in alive_pids
            }
            for _fut in as_completed(_ps_futures):
                pid = _ps_futures[_fut]
                try:
                    raw = _fut.result()
                except Exception as _e:
                    status(f"      PID {pid}: 스캔 오류 {_e}")
                    continue
                pr  = parse_pesieve(raw)
                result.pe_sieve_results.append(pr)
                if pr.error:
                    status(f"      PID {pid}: {pr.error[:80]}")
                    raw_out = (raw.get("stdout") or "").strip()
                    raw_err = (raw.get("stderr") or "").strip()
                    if raw_out:
                        status(f"        [pe-sieve stdout] {raw_out[:200]}")
                    elif raw_err:
                        status(f"        [pe-sieve stderr] {raw_err[:200]}")
                elif pr.suspicious > 0:
                    inj_parts = []
                    if pr.implanted_pe:
                        inj_parts.append(f"PE인젝션 {pr.implanted_pe}개")
                    if pr.implanted_shc:
                        inj_parts.append(f"쉘코드 {pr.implanted_shc}개")
                    inj_str = "  ".join(inj_parts) if inj_parts else f"의심모듈 {pr.suspicious}개"
                    status(f"      PID {pid}: 의심 {pr.suspicious}개  {inj_str} 🚨")
        susp_sum = sum(1 for r in result.pe_sieve_results if r.suspicious > 0)
        pe_inj   = sum(r.implanted_pe  for r in result.pe_sieve_results if not r.error)
        shc_sum  = sum(r.implanted_shc for r in result.pe_sieve_results if not r.error)
        dead_note = f"  (종료된 PID {len(dead_pids)}개 생략)" if dead_pids else ""
        status(f"      pe-sieve 완료: 의심 {susp_sum}개 PID"
               + (f"  PE인젝션 {pe_inj}개" if pe_inj else "")
               + (f"  쉘코드 {shc_sum}개" if shc_sum else "")
               + dead_note
               + (" 🚨" if susp_sum else " ✅"))
    elif not hh_scanner.available:
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
    # ─ System Informer 는 UAC 자동 상승(self-elevate) 시 원래 Popen 핸들이
    #   즉시 종료되고 실제 프로세스는 별도 PID 로 뜨므로 핸들만으로는 잡히지 않음.
    #   1단계: Popen 핸들 시도, 2단계: psutil 이름 검색, 3단계: taskkill /F 폴백
    _kill_analysis_tool(
        ph_proc,
        exe_names=["systeminformer.exe", "processhacker.exe"],
        status=status,
        label="System Informer / Process Hacker",
    )

    # ── 6. 사후 스냅샷 ────────────────────────────────────────────────
    status("[6/6] 사후 스냅샷 수집 중...")
    reg_after  = take_snapshot() if REG_AVAILABLE else {}
    proc_after = take_process_snapshot()

    result.registry_diff     = diff_snapshots(reg_before, reg_after) if REG_AVAILABLE else {}
    result.process_diff      = diff_process_snapshots(proc_before, proc_after)
    result.proc_after_snapshot = proc_after   # 프로세스 트리 시각화용

    # ── proc_after 기반 추가 스캔 ─────────────────────────────────────
    # 샘플 종료 후에도 살아있는 신규 프로세스 = 인젝션된 호스트 프로세스(RegSvcs.exe 등)
    # 앞선 스캔에서 놓쳤거나 실시간 감지에서 오류가 난 경우를 보완
    if ps_scanner.available:
        already = {r.pid for r in result.pe_sieve_results}
        after_new = [
            p.pid
            for p in result.process_diff.get("new_processes", [])
            if p.pid not in already and _pid_alive(p.pid)
        ]
        if after_new:
            status(f"[분석] pe-sieve 잔존 신규 프로세스 스캔 ({len(after_new)}개 PID)...")
            _ps2_workers = min(3, len(after_new)) if after_new else 1
            with ThreadPoolExecutor(max_workers=_ps2_workers) as _ps2_pool:
                _ps2_futures = {
                    _ps2_pool.submit(ps_scanner.scan_pid, pid, dump_mode=3, shellcode=1): pid
                    for pid in after_new
                }
                for _fut2 in as_completed(_ps2_futures):
                    pid = _ps2_futures[_fut2]
                    try:
                        raw = _fut2.result()
                    except Exception as _e:
                        status(f"      PID {pid}: 스캔 오류 {_e}")
                        continue
                    pr  = parse_pesieve(raw)
                    result.pe_sieve_results.append(pr)
                    if pr.error:
                        status(f"      PID {pid}: {pr.error[:80]}")
                    elif pr.suspicious > 0:
                        inj_parts = []
                        if pr.implanted_pe:
                            inj_parts.append(f"PE인젝션 {pr.implanted_pe}개")
                        if pr.implanted_shc:
                            inj_parts.append(f"쉘코드 {pr.implanted_shc}개")
                        inj_str = "  ".join(inj_parts) if inj_parts else f"의심모듈 {pr.suspicious}개"
                        status(f"      PID {pid}: 의심 {pr.suspicious}개  {inj_str} 🚨")
                    else:
                        status(f"      PID {pid}: 이상 없음 ✅")

    # ── 조기 종료 프로세스 보완 ───────────────────────────────────────
    # pe-sieve 결과는 메모리 탭(result.pe_sieve_results)에서 표시합니다.
    # 프로세스 트리는 OS 스냅샷(psutil) 기반으로만 구성하므로
    # pe-sieve 스캔 PID를 new_processes에 보완하지 않습니다.

    # ── 7. 파싱 ─────────────────────────────────────────────────────
    status("[분석] ProcMon CSV 파싱...")
    if pm.csv_path.exists():
        result.procmon_events = parse_csv(pm.csv_path)
        # 자식 PID 추적
        if result.sample_pid:
            child_pids = pm_child_pids(result.procmon_events, result.sample_pid)
            result.all_pids.update(child_pids)
        # HH / pe-sieve 가 탐지한 인젝션 대상 프로세스 PID 도 포커스에 포함
        # (악성코드가 기존 프로세스에 쉘코드를 주입하면 그 PID 의 파일·레지스트리
        #  이벤트가 focus_pids 에서 제외되어 탭에 아무것도 안 보이는 문제 방지)
        if result.hh_result and not result.hh_result.error:
            for _hpr in result.hh_result.suspicious_processes:
                if _hpr.implanted_shc > 0 or _hpr.implanted_pe > 0:
                    result.all_pids.add(_hpr.pid)
        for _psr in result.pe_sieve_results:
            if not _psr.error and (_psr.implanted_shc > 0 or _psr.implanted_pe > 0):
                result.all_pids.add(_psr.pid)
        # ProcessWatcher 가 실시간 감지한 PID 를 all_pids 에 추가.
        # after-snapshot 이전에 종료된 단명 프로세스(PowerShell 로더, 인젝터 등)는
        # process_diff["new_processes"] 에 포함되지 않으므로 여기서 보완.
        if rt_scanned_pids:
            result.all_pids.update(rt_scanned_pids)
            status(f"      [실시간] 감지 PID {len(rt_scanned_pids)}개 추적 추가")
        # ShellExecute (doc/xls/js 등) 모드: sample_pid = None 이므로
        # 분석 중 새로 생성된 모든 프로세스 PID 를 추적 대상에 포함합니다.
        # → 호스트 앱(WINWORD.EXE, wscript.exe 등)의 네트워크·파일 이벤트 누락 방지
        if result.sample_pid is None:
            _new_proc_pids = {
                p.pid for p in result.process_diff.get("new_processes", [])
            }
            if _new_proc_pids:
                result.all_pids.update(_new_proc_pids)
                status(f"      [ShellExecute] 신규 프로세스 {len(_new_proc_pids)}개 PID 추적 추가")
        # ── 단명 프로세스 보완 ────────────────────────────────────────
        # 두 단계로 구성:
        #
        # [Step 1] all_pids 에 있지만 new_processes 에 없는 PID 보완
        #   ProcessWatcher 또는 pe-sieve 가 탐지했으나 스냅샷 전에 종료된 프로세스
        #   (DDE handoff 기존 WINWORD, 단발 PowerShell 등)
        #   → ProcMon Process Create 이벤트에서 child_pid 로 등장하면 신규 프로세스로 확정
        #
        # [Step 2] BFS 로 새 자손 발굴
        #   보완된 프로세스(Step 1 포함)의 자식 중 new_processes 에 없는 것 추가
        #
        # filter_events 호출 전에 실행해야 보완된 PID 의 이벤트도 포함됩니다.
        from parsers.procmon_csv import get_child_proc_infos, ChildProcInfo
        from core.process_tracker import ProcessSnapshot as _ProcSnap

        _child_infos: list[ChildProcInfo] = get_child_proc_infos(result.procmon_events)
        # child_pid → ChildProcInfo (Step 1 보완용)
        _child_by_pid: dict[int, ChildProcInfo] = {
            _ci.child_pid: _ci for _ci in _child_infos
        }
        # 부모 PID → 자식 목록 (Step 2 BFS 용)
        _parent_idx: dict[int, list[ChildProcInfo]] = {}
        for _ci in _child_infos:
            _parent_idx.setdefault(_ci.parent_pid, []).append(_ci)

        _new_proc_pids: set[int] = {
            p.pid for p in result.process_diff.get("new_processes", [])
        }
        _added: int = 0

        def _add_proc(_ci: ChildProcInfo) -> None:
            """합성 ProcessSnapshot을 new_processes / all_pids 에 추가."""
            nonlocal _added
            result.process_diff["new_processes"].append(_ProcSnap(
                pid         = _ci.child_pid,
                ppid        = _ci.parent_pid,
                name        = _ci.name,
                exe         = _ci.exe,
                cmdline     = _ci.cmdline,
                create_time = 0.0,
                note        = "단명 프로세스 (ProcMon Process Create 보완)",
            ))
            result.all_pids.add(_ci.child_pid)
            _new_proc_pids.add(_ci.child_pid)
            _added += 1

        # Step 1: all_pids 중 new_processes 에 없는 PID를 직접 보완
        # ProcessWatcher 가 감지했으나 스냅샷 전에 종료된 단명 프로세스
        # (ProcMon Process Create 이벤트에 child_pid 로 등장 = 분석 중 신규 생성 확정)
        for _pid in list(result.all_pids):
            if _pid in _new_proc_pids:
                continue
            if _pid in _child_by_pid:
                _add_proc(_child_by_pid[_pid])

        # Step 2: 보완된 프로세스를 포함한 all_pids 에서 BFS로 추가 자손 발굴
        # _visited 는 new_proc_pids 기준으로 초기화 (all_pids 를 넣으면 Step 1 이후
        # 보완된 PID 를 BFS 가 다시 건너뛰는 문제가 생기므로 분리)
        _visited: set[int] = set(_new_proc_pids)
        _queue: list[int]  = list(result.all_pids)

        while _queue:
            _pid = _queue.pop()
            for _ci in _parent_idx.get(_pid, []):
                if _ci.child_pid in _visited:
                    continue
                _visited.add(_ci.child_pid)
                _queue.append(_ci.child_pid)
                if _ci.child_pid not in _new_proc_pids:
                    _add_proc(_ci)

        if _added:
            status(f"      [ProcMon] 단명 프로세스 {_added}개 보완 (스냅샷 누락)")

        # 포커스 PID 기반 필터 (단명 프로세스 보완 후 실행)
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

    # ── TLS keylog 복호화 ─────────────────────────────────────────────
    if tls_keylogger and tshark_bin and pcap_target:
        result.tls_key_count = tls_keylogger.key_count()
        if tls_keylogger.has_keys():
            status(f"[TLS] SSLKEYLOGFILE 키 {result.tls_key_count}개 — PCAP 복호화 중...")
            try:
                result.decrypted_requests = tls_keylogger.decrypt_pcap(
                    pcap_target, Path(tshark_bin)
                )
                if result.decrypted_requests:
                    status(f"      복호화 성공: HTTP(S) 요청 {len(result.decrypted_requests)}개")
                else:
                    status("      복호화된 HTTP 요청 없음 (Schannel 기반 또는 커스텀 TLS 가능성)")
            except Exception as _ke:
                result.errors.append(f"TLS 복호화 실패: {_ke}")
        else:
            status(f"[TLS] {tls_keylogger.summary()}")

    # ── FakeNet-NG 결과 수집 ──────────────────────────────────────────
    if fakenet and result.tools_used.get("fakenet"):
        status("[FakeNet] 결과 수집 중...")
        _fn_result = fakenet.stop()
        result.fakenet_result = fakenet_result_to_dict(_fn_result)
        dns_cnt  = len(_fn_result.dns_queries)
        http_cnt = len(_fn_result.http_requests)
        tcp_cnt  = len(_fn_result.tcp_sessions)
        status(f"      DNS {dns_cnt}건  HTTP(S) {http_cnt}건  TCP {tcp_cnt}건")
        # FakeNet PCAP도 파싱 대상에 추가 (tshark 없이 캡처된 경우)
        if _fn_result.pcap_path and not pcap_target:
            try:
                result.pcap_result = parse_pcap(_fn_result.pcap_path, tshark_path=tshark_bin)
                status(f"      FakeNet PCAP 파싱 완료: {_fn_result.pcap_path.name}")
            except Exception as _fe:
                result.errors.append(f"FakeNet PCAP 파싱 실패: {_fe}")

    # ── 7.5 의심 DLL 로드 기존 프로세스 pe-sieve 추가 스캔 ──────────────
    # procmon_events 를 단일 패스로 순회해 인젝션 PID와 네트워크 맵을 동시 수집.
    _precomp_inject_pids: set[int] = set()
    _precomp_net_map: list = []
    if result.procmon_events:
        _already_pre = {r.pid for r in result.pe_sieve_results}
        _precomp_inject_pids, _precomp_net_map = _scan_procmon_once(
            result.procmon_events,
            already_scanned=_already_pre,
            sample_pids=result.all_pids,
        )

    if ps_scanner.available and _precomp_inject_pids:
        _inject_pids = _precomp_inject_pids
        _alive_inject  = [p for p in _inject_pids if _pid_alive(p)]
        _dead_inject   = _inject_pids - set(_alive_inject)
        if _inject_pids:
            status(
                f"[분석] 의심 DLL 로드 감지 — 기존 프로세스 {len(_inject_pids)}개 "
                f"(생존 {len(_alive_inject)}개, 종료 {len(_dead_inject)}개) pe-sieve 추가 스캔..."
            )
            _ps3_workers = min(3, len(_alive_inject)) if _alive_inject else 1
            with ThreadPoolExecutor(max_workers=_ps3_workers) as _ps3_pool:
                _ps3_futures = {
                    _ps3_pool.submit(
                        ps_scanner.scan_pid, _pid, dump_mode=3, shellcode=True, hooks=True
                    ): _pid
                    for _pid in _alive_inject
                }
                for _fut3 in as_completed(_ps3_futures):
                    _pid = _ps3_futures[_fut3]
                    try:
                        _raw = _fut3.result()
                    except Exception as _e:
                        status(f"      PID {_pid}: 스캔 오류 {_e}")
                        continue
                    _pr = parse_pesieve(_raw)
                    result.pe_sieve_results.append(_pr)
                    if _pr.error:
                        status(f"      PID {_pid}: {_pr.error[:80]}")
                    elif _pr.suspicious > 0:
                        _inj_parts = []
                        if _pr.implanted_pe:
                            _inj_parts.append(f"PE인젝션 {_pr.implanted_pe}개")
                        if _pr.implanted_shc:
                            _inj_parts.append(f"쉘코드 {_pr.implanted_shc}개")
                        _inj_str = "  ".join(_inj_parts) if _inj_parts else f"의심모듈 {_pr.suspicious}개"
                        status(f"      PID {_pid}: 의심 {_pr.suspicious}개  {_inj_str} 🚨")
                    else:
                        status(f"      PID {_pid}: 이상 없음 ✅")
            if _dead_inject:
                status(f"      [알림] 종료된 PID (스캔 불가): {sorted(_dead_inject)}")
        # else: 의심 DLL 로드 없음 — 상태 로그 불필요

    # step 7.5 에서 새로 추가된 pe-sieve 결과(DLL 인젝션 대상 기존 프로세스)를
    # all_pids 에 반영. filter_events 이후에 발견된 PID 이므로 filtered_events 에는
    # 포함되지 않지만, 프로세스↔네트워크 매핑에서는 포함되어야 한다.
    _injection_pids: set[int] = set()
    for _psr2 in result.pe_sieve_results:
        if not _psr2.error and (_psr2.implanted_shc > 0 or _psr2.implanted_pe > 0):
            result.all_pids.add(_psr2.pid)
            _injection_pids.add(_psr2.pid)

    # injection 대상 프로세스가 드롭한 파일 추출을 위해
    # procmon_events 에서 해당 PID 이벤트만 별도 수집 (filter_events 미적용)
    _injection_events: list = []
    if _injection_pids and result.procmon_events:
        _injection_events = [
            ev for ev in result.procmon_events
            if ev.pid in _injection_pids
        ]

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
        injection_events=_injection_events or None,
    )

    # ── CAPA 정적 분석 (선택적) ──────────────────────────────────────
    from core.config_loader import load_config as _load_cfg
    _cfg = _load_cfg()

    _capa_cfg = _cfg.get("capa", {})
    _PE_EXTS  = frozenset({".exe", ".dll", ".sys", ".scr", ".drv", ".ocx", ".cpl"})
    if not _capa_cfg.get("enabled", True):
        result.tools_used["capa"] = "비활성 (config.json > capa.enabled: false)"
    elif not config.sample_path:
        result.tools_used["capa"] = "샘플 없음"
    elif config.sample_path.suffix.lower() not in _PE_EXTS:
        _ext = config.sample_path.suffix or "(확장자 없음)"
        result.tools_used["capa"] = f"비PE 샘플 건너뜀 ({_ext})"
        status(f"[분석] CAPA: 비PE 샘플({_ext}) — 정적 분석 건너뜀")
    else:
        _capa_exe     = _capa_cfg.get("path", "capa.exe")
        _capa_timeout = int(_capa_cfg.get("timeout", 120))
        status(f"[분석] CAPA 정적 분석 중... (최대 {_capa_timeout}초, Ctrl+C로 건너뜀)")
        try:
            from analysis.capa_analyzer import run_capa, find_capa as _find_capa
            if not (_find_capa() or __import__("shutil").which(_capa_exe)):
                result.tools_used["capa"] = f"미설치 (경로: {_capa_exe})"
                status(f"      CAPA: 실행 파일 미발견 ({_capa_exe}) — config.json > capa.path 확인")
            else:
                _capa_techs = run_capa(config.sample_path, _capa_exe, _capa_timeout)
                if _capa_techs:
                    _merge_external_techniques(result.behavior_report, _capa_techs)
                    _capa_new = sum(1 for t in result.behavior_report.techniques
                                    if "CAPA" in (t.sources or []))
                    result.tools_used["capa"] = f"{len(_capa_techs)}건 기여"
                    status(f"      CAPA 완료: 기법 {len(_capa_techs)}개 탐지  "
                           f"(누적 {_capa_new}개)")
                else:
                    result.tools_used["capa"] = "결과 없음"
                    status("      CAPA: 탐지 없음 / 실행 불가 (config.json > capa.path 확인)")
        except KeyboardInterrupt:
            result.tools_used["capa"] = "건너뜀 (Ctrl+C)"
            status("      CAPA 건너뜀 (Ctrl+C)")
        except Exception as _e:
            result.tools_used["capa"] = f"오류: {_e}"
            status(f"      CAPA 오류: {_e}")

    # ── VirusTotal API 쿼리 (선택적) ─────────────────────────────────
    _vt_cfg = _cfg.get("virustotal", {})
    if not _vt_cfg.get("enabled"):
        result.tools_used["virustotal"] = "비활성 (config.json > virustotal.enabled: true 필요)"
    elif not _vt_cfg.get("api_key", ""):
        result.tools_used["virustotal"] = "API 키 없음 (config.json > virustotal.api_key 설정 필요)"
    else:
        _vt_key     = _vt_cfg["api_key"]
        _vt_timeout = int(_vt_cfg.get("timeout", 20))
        _sha256 = ""
        if config.sample_path:
            try:
                import hashlib as _hl
                _h = _hl.sha256()
                with open(config.sample_path, "rb") as _f:
                    for _chunk in iter(lambda: _f.read(65536), b""):
                        _h.update(_chunk)
                _sha256 = _h.hexdigest()
            except Exception:
                pass

        if _sha256:
            status(f"[분석] VirusTotal 쿼리 중... ({_sha256[:16]}…)")
            try:
                from analysis.vt_analyzer import query_vt
                _vt_techs = query_vt(_sha256, _vt_key, _vt_timeout)
                if _vt_techs:
                    _merge_external_techniques(result.behavior_report, _vt_techs)
                    _vt_new = sum(1 for t in result.behavior_report.techniques
                                  if "VirusTotal" in (t.sources or []))
                    result.tools_used["virustotal"] = f"{len(_vt_techs)}건 기여"
                    status(f"      VT 완료: 기법 {len(_vt_techs)}개 탐지  "
                           f"(누적 {_vt_new}개)")
                else:
                    result.tools_used["virustotal"] = "결과 없음 (미등록 샘플)"
                    status("      VT: 탐지 없음 (미등록 샘플이거나 API 오류)")
            except Exception as _e:
                result.tools_used["virustotal"] = f"오류: {_e}"
                status(f"      VT 오류: {_e}")
        else:
            result.tools_used["virustotal"] = "SHA256 계산 실패"
            status("      VT: SHA256 계산 실패 또는 샘플 경로 없음")

    status("[분석] 프로세스↔네트워크 연결 매핑...")
    # _scan_procmon_once 에서 이미 단일 패스로 수집한 결과를 재사용합니다.
    result.process_network_map = _precomp_net_map

    # ── netstat 스냅샷으로 보완 (ProcMon Network 이벤트가 없을 때 fallback) ──
    # ProcMon 필터 설정으로 인해 TCP/UDP 이벤트가 CSV에 없는 경우
    # 분석 중 수집한 netstat 스냅샷으로 프로세스↔IP 매핑을 보완합니다.
    if _netstat_snaps:
        try:
            from analysis.process_network_map import build_netstat_proc_map
            _ns_map = build_netstat_proc_map(
                _netstat_snaps,
                proc_snapshots=result.proc_after_snapshot,
            )
            if _ns_map:
                # 중복 제거: ProcMon에 이미 있는 (pid, remote_ip, remote_port) 제외
                _existing = {
                    (_pn.pid, _pn.remote_ip, _pn.remote_port)
                    for _pn in result.process_network_map
                }
                _added = [
                    c for c in _ns_map
                    if (c.pid, c.remote_ip, c.remote_port) not in _existing
                ]
                result.process_network_map = list(result.process_network_map) + _added
                if _added:
                    status(f"      netstat 보완: {len(_added)}개 추가 "
                           f"(ProcMon {len(_precomp_net_map)}개 + netstat {len(_added)}개)")
        except Exception as _ns_err:
            status(f"      netstat 보완 실패: {_ns_err}")

    if result.process_network_map:
        status(f"      총 {len(result.process_network_map)}개 연결 집계")

    # ── 메모리 포렌식 (Volatility3) ──────────────────────────────────
    if config.use_memdump:
        status("[메모리 포렌식] 시작 (winpmem + Volatility3)...")
        _mem_winpmem = Path(config.winpmem_path) if config.winpmem_path else None
        _mem_vol     = Path(config.volatility_path) if config.volatility_path else None
        _mem_dump    = Path(config.existing_dump) if config.existing_dump else None
        try:
            mem_result = run_memory_forensics(
                output_dir=config.output_dir,
                sample_pids=result.all_pids or None,
                winpmem_path=_mem_winpmem,
                vol_path=_mem_vol,
                dump_timeout=config.dump_timeout,
                plugin_timeout=config.vol_plugin_timeout,
                on_status=status,
                skip_dump=bool(_mem_dump),
                existing_dump=_mem_dump,
            )
            result.mem_forensics = memforensics_to_dict(mem_result)
            if mem_result.error:
                status(f"      [오류] {mem_result.error}")
                result.errors.append(f"메모리 포렌식: {mem_result.error}")
            else:
                mf_cnt = len(mem_result.malfind)
                ns_cnt = len(mem_result.netscan)
                hd_cnt = len(mem_result.handles)
                status(f"      malfind {mf_cnt}건  netscan {ns_cnt}건  "
                       f"handles(Mutant) {hd_cnt}건")
                if mf_cnt:
                    status(f"      [!] 주입 코드 탐지 — malfind {mf_cnt}건 (메모리 탭 확인)")
        except Exception as _me:
            result.errors.append(f"메모리 포렌식 예외: {_me}")
            status(f"      [오류] {_me}")
            result.mem_forensics = {"error": f"실행 예외: {_me}"}

    # ── AI 분석 (Ollama qwen2.5:7b) ──────────────────────────────────
    if config.use_ai:
        _az = OllamaAnalyzer(base_url=config.ollama_url, model=config.ai_model)
        if _az.is_available():
            status(f"[AI 분석] Ollama {config.ai_model} 호출 중…")
            try:
                _ai = _az.analyze(result, timeout=config.ai_timeout)
                result.ai_analysis = ai_analysis_to_dict(_ai)
                if _ai.error:
                    status(f"      [오류] {_ai.error}")
                    result.errors.append(f"AI 분석: {_ai.error}")
                else:
                    status(f"      AI 분석 완료 ({_ai.elapsed_sec}s, {_ai.prompt_chars}자 입력)")
            except Exception as _ae:
                result.errors.append(f"AI 분석 예외: {_ae}")
                status(f"      [오류] {_ae}")
        else:
            status(f"[AI 분석] Ollama 서버 미실행 — 건너뜀 ({config.ollama_url})")

    result.end_time = time.time()
    elapsed_total = result.end_time - result.start_time
    status(f"[완료] 총 소요 {elapsed_total:.1f}초")

    return result
