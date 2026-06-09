"""
process_watcher.py — 모니터링 중 실시간 신규 프로세스 감지 및 pe-sieve 즉시 스캔

동작 원리
---------
백그라운드 스레드가 1초 간격으로 psutil 프로세스 목록을 폴링해서
새로 나타난 PID를 즉시 pe-sieve로 스캔합니다.

일반적인 프로세스 타임라인:
  [모니터링 시작]  --->  [신규 PID 출현]  --->  [1초 이내 스캔 시작]
                                                      ↕
                                              [PID 아직 살아있음]

기존 방식(모니터링 종료 후 스캔)의 문제:
  [모니터링 시작] → [HH 스캔 30-60초] → [pe-sieve 시도] → [PID 이미 종료됨]

주요 특성
---------
- psutil 미설치 시 자동으로 비활성화(예외 없음)
- pe-sieve 스캔은 별도 스레드로 실행 — 모니터링 루프를 차단하지 않음
- 분석 도구(ProcMon, tshark 등)는 자동 제외
- dump_mode=3 (raw dump) 으로 쉘코드 바이트도 디스크에 추출
"""
from __future__ import annotations

import threading
import time
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
        프로세스 목록 폴링 간격 (초).
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

    # ── public API ────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """psutil 설치 여부 + scanner 사용 가능 여부."""
        return _PSUTIL_OK and self._scanner.available

    def start(self) -> None:
        """백그라운드 폴링 스레드 시작."""
        if self.available:
            self._thread.start()

    def stop(self) -> set[int]:
        """폴링을 중지하고, 진행 중인 스캔이 모두 끝날 때까지 대기.

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
                shellcode=True,
                hooks=True,
            )
            self._callback(pid, raw)
        except Exception:
            pass
