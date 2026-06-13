"""
process_watcher.py — 모니터링 중 실시간 신규 프로세스 감지 및 pe-sieve 즉시 스캔

감지 전략 (우선순위 순)
-----------------------
1. WMI Win32_ProcessStartTrace (ETW 기반)
   - Windows 커널이 프로세스 생성 즉시 이벤트를 전달 → 폴링 지연 없음
   - 수십 ms 만에 종료하는 단명 프로세스(PowerShell 로더, 인젝터 등)도 캡처
   - 요구사항: wmi 패키지 (pip install wmi) + 관리자 권한

2. psutil 폴링 (폴백)
   - wmi 패키지 없거나 WMI 초기화 실패 시 자동 사용
   - 1초 간격 폴링 — 1초 이내 종료 프로세스는 놓칠 수 있음

기존 방식(모니터링 종료 후 스캔)의 문제:
  [모니터링 시작] → [HH 스캔 30-60초] → [pe-sieve 시도] → [PID 이미 종료됨]

주요 특성
---------
- psutil / wmi 미설치 시 자동으로 비활성화 (예외 없음)
- pe-sieve 스캔은 별도 스레드로 실행 — 감지 루프를 차단하지 않음
- 분석 도구(ProcMon, tshark 등)는 자동 제외
- dump_mode=3 (raw dump) 으로 쉘코드 바이트도 디스크에 추출
"""
from __future__ import annotations

import threading
from typing import Callable

try:
    import psutil as _psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

# 분석 도구 프로세스 — 스캔 불필요
_SKIP_NAMES: frozenset[str] = frozenset({
    "procmon.exe", "procmon64.exe",
    "processhacker.exe", "systeminformer.exe",
    "procexp.exe", "procexp64.exe",
    "tshark.exe", "dumpcap.exe",
    "pe-sieve.exe", "pe-sieve64.exe",
    "hollows_hunter.exe", "hollows_hunter64.exe",
})


class ProcessWatcher:
    """모니터링 기간 동안 신규 프로세스를 실시간 감지해 pe-sieve로 즉시 스캔.

    Parameters
    ----------
    initial_pids:
        분석 시작 전 이미 실행 중인 PID 집합 (proc_before.keys()).
    scanner:
        PeSieveScanner 인스턴스.
    on_result:
        스캔 완료 시 호출되는 콜백. 서명: ``on_result(pid: int, raw: dict)``.
    dump_mode:
        pe-sieve /dmode 값.
        3 = raw dump (PE + shellcode 모두 추출, 기본값).
    poll_interval:
        psutil 폴백 모드의 폴링 간격 (초). WMI ETW 모드에서는 사용되지 않음.
    """

    def __init__(
        self,
        initial_pids: set[int],
        scanner,
        on_result: Callable[[int, dict], None],
        dump_mode: int = 3,
        poll_interval: float = 1.0,
    ) -> None:
        self._known    = set(initial_pids)
        self._scanned: set[int] = set()   # 이미 스캔 요청된 PID (중복 방지)
        self._scanner  = scanner
        self._callback = on_result
        self._dmode    = dump_mode
        self._poll     = poll_interval
        self._stop     = threading.Event()
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name="ProcessWatcher"
        )
        self._scan_threads: list[threading.Thread] = []
        self._lock     = threading.Lock()
        # 감지 방식 미리 판단 (import 가능 여부만 확인, 실제 연결은 _run에서)
        try:
            import wmi as _w  # noqa: F401
            self._mode = "wmi_etw"
        except ImportError:
            self._mode = "psutil_poll"

    # ── public API ────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """psutil 설치 여부 + scanner 사용 가능 여부."""
        return _PSUTIL_OK and self._scanner.available

    @property
    def detection_mode(self) -> str:
        """실제 사용된 감지 방식 ('wmi_etw' 또는 'psutil_poll')."""
        return self._mode

    def start(self) -> None:
        """백그라운드 감지 스레드 시작."""
        if self.available:
            self._thread.start()

    def stop(self) -> set[int]:
        """감지를 중지하고, 진행 중인 스캔이 모두 끝날 때까지 대기.

        Returns
        -------
        set[int]
            실시간 스캔을 시도한 PID 집합.
        """
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)

        # 진행 중인 개별 스캔 스레드 완료 대기 (최대 30초)
        with self._lock:
            pending = list(self._scan_threads)
        for t in pending:
            t.join(timeout=30)

        return set(self._scanned)

    # ── internal ──────────────────────────────────────────────────────

    def _run(self) -> None:
        """감지 루프 진입점. WMI ETW 우선, 실패 시 psutil 폴링으로 폴백."""
        if not self._run_wmi_etw():
            self._run_polling()

    def _run_wmi_etw(self) -> bool:
        """Win32_ProcessStartTrace (ETW 기반) 즉시 알림으로 신규 프로세스 감지.

        Windows 커널이 프로세스 생성 즉시 이벤트를 전달하므로
        psutil 폴링(1초 간격)과 달리 단명 프로세스를 놓치지 않습니다.

        Returns
        -------
        bool
            WMI 초기화 성공 여부. False 면 폴링 폴백으로 전환.
        """
        try:
            import wmi as _wmi_mod
        except ImportError:
            return False

        try:
            _c  = _wmi_mod.WMI()
            _wt = _c.Win32_ProcessStartTrace.watch_for()
        except Exception:
            self._mode = "psutil_poll"   # WMI 연결 실패 → 폴링 폴백
            return False

        while not self._stop.is_set():
            try:
                ev  = _wt(timeout_ms=200)   # 200ms 대기 — stop 신호 감지 주기
                pid = int(ev.ProcessID)
                with self._lock:
                    is_new = pid not in self._known and pid not in self._scanned
                    if is_new:
                        self._known.add(pid)
                if is_new:
                    self._launch_scan(pid)
            except _wmi_mod.x_wmi_timed_out:
                pass   # 정상 타임아웃 — stop 플래그 재확인 후 계속 대기
            except Exception:
                break  # WMI 런타임 오류 — ETW 루프 종료 (폴링으로 재시작 안함)

        return True

    def _run_polling(self) -> None:
        """psutil 폴링 감지 (WMI ETW 불가 시 폴백).

        poll_interval 간격으로 프로세스 목록을 조회합니다.
        단명 프로세스(< poll_interval)는 누락될 수 있으며,
        ProcMon BFS가 이를 보완합니다.
        """
        self._mode = "psutil_poll"
        while not self._stop.is_set():
            try:
                current: set[int] = {
                    p.pid
                    for p in _psutil.process_iter(["pid"])
                }
                with self._lock:
                    new_pids = current - self._known - self._scanned
                    self._known.update(current)

                for pid in new_pids:
                    self._launch_scan(pid)

            except Exception:
                pass

            self._stop.wait(self._poll)

    def _launch_scan(self, pid: int) -> None:
        """신규 PID 스캔 스레드를 시작 (비차단)."""
        # 프로세스 이름 확인 — 분석 도구는 스킵
        try:
            proc = _psutil.Process(pid)
            if proc.name().lower() in _SKIP_NAMES:
                return
        except Exception:
            pass  # 이미 종료됐거나 접근 불가 → 스캔 시도는 함

        with self._lock:
            if pid in self._scanned:
                return
            self._scanned.add(pid)

        t = threading.Thread(
            target=self._scan_one, args=(pid,), daemon=True
        )
        with self._lock:
            self._scan_threads.append(t)
        t.start()

    def _scan_one(self, pid: int) -> None:
        """단일 PID pe-sieve 스캔 (스레드 실행 대상)."""
        try:
            raw = self._scanner.scan_pid(
                pid,
                dump_mode=self._dmode,
                shellcode=1,   # 패턴 기반 쉘코드 탐지
            )
            self._callback(pid, raw)
        except Exception:
            pass
