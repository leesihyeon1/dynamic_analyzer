"""
process_watcher.py — 모니터링 중 실시간 신규 프로세스 감지 + injection 신호 기반 pe-sieve 스캔

배경: pe-sieve 덤프 타이밍 문제
--------------------------------
pe-sieve /dmode 는 살아있는 프로세스의 가상 메모리를 읽어 덤프하므로,
종료된 프로세스는 덤프할 수 없다. 그런데 프로세스 "생성 즉시" 1회만 스캔하면
악성 페이로드가 아직 언패킹·인젝션되기 전(깨끗한 상태)을 보게 되고,
"모니터링 종료 후" 스캔하면 단명 프로세스는 이미 죽어 덤프가 불가능하다.

  프로세스 생성 → (언패킹/인젝션) → 페이로드 전개 → 활동 → 종료
     ↑ 너무 이름                    ↑ 여기서 덤프해야 함    ↑ 너무 늦음

이 모듈은 그 최적 윈도우("페이로드 전개 직후 && 종료 전")를 노리기 위해
두 개의 스레드로 동작한다.

[스레드 A] 신규 프로세스 감지
  1. WMI Win32_ProcessStartTrace (ETW 기반) — 커널이 프로세스 생성 즉시 알림
  2. psutil 폴링 (폴백) — poll_interval(기본 1초) 간격
  신규 PID → 즉시 pe-sieve 스캔(scan #1) + 추적 목록 등록

[스레드 B] injection 신호 + 재스캔  (rescan_interval 간격, 기본 5초)
  (1) injection 신호 실시간 감지:
      실행 중 전체 프로세스의 로드 모듈(psutil memory_maps)을 검사해
      의심 경로(Temp·Public 등) DLL이 "새로" 로드되면 그 PID 를 즉시 재스캔.
      → 기존 프로세스에 대한 원격 인젝션·DLL 인젝션을 라이브에서 포착
        (ProcMon 은 실시간 스트림을 노출하지 않으므로 memory_maps 로 대체)
  (2) 신규 프로세스 시간차 재스캔:
      추적 중인 신규 프로세스를 max_rescans 회까지 주기적으로 재스캔.
      → 생성 직후엔 깨끗하다가 나중에 언패킹/인젝션되는 로더를 포착
  suspicious 가 확인된 PID 는 재스캔을 중단한다(이미 덤프 확보).

주요 특성
---------
- psutil 미설치 또는 scanner 불가 시 자동 비활성화 (예외 없음)
- pe-sieve 스캔은 개별 스레드로 실행 — 감지/재스캔 루프를 차단하지 않음
- 분석 도구(ProcMon, tshark, pe-sieve 등) 프로세스는 자동 제외
- dump_mode=3 (/dmode 3 = realigned 덤프). 쉘코드 영역 덤프 여부는 /shellc 와
  탐지 결과가 정한다 (dmode 는 PE 덤프 방식만 바꾼다)
- 프로세스 식별은 (PID, 생성 시각) 쌍으로 한다 — 분석 전 프로세스가 끝나고
  같은 PID 가 재사용돼도 새 프로세스를 놓치지 않는다
- 시작 시점에 이미 의심 경로 모듈을 로드한 기존 프로세스는 기준선으로 기록해
  '새 injection 신호' 로 오인하지 않는다
"""
from __future__ import annotations

import threading
import time
from typing import Callable

from analysis.injection_paths import is_suspicious_module_path
from parsers.pesieve_result import raw_suspicious_count

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
    "pe_sieve.exe", "pe_sieve64.exe",
    "hollows_hunter.exe", "hollows_hunter64.exe",
    "hollows-hunter.exe", "hollows-hunter64.exe",
})


class ProcessWatcher:
    """모니터링 기간 동안 신규 프로세스·injection 신호를 실시간 감지해 pe-sieve 스캔.

    Parameters
    ----------
    initial_pids:
        분석 시작 전 이미 실행 중인 PID 집합 (proc_before.keys()).
    scanner:
        PeSieveScanner 인스턴스.
    on_result:
        스캔 완료 시 호출되는 콜백. 서명: ``on_result(pid: int, raw: dict)``.
        같은 PID 가 재스캔되면 여러 번 호출될 수 있다(호출부에서 dedupe).
    dump_mode:
        pe-sieve /dmode 값 (0=자동, 1=virtual, 2=unmapped, 3=realigned).
    poll_interval:
        psutil 폴백 모드의 신규 프로세스 폴링 간격 (초). WMI ETW 모드에선 미사용.
    rescan_interval:
        injection 신호 검사 및 주기 재스캔 간격 (초).
    max_rescans:
        clean 판정 신규 프로세스의 최대 (재)스캔 횟수. 무한 재스캔 방지용.
    initial_create_times:
        {PID: 생성 시각} — 기존 프로세스의 생성 시각. 주어지면 PID 가 재사용된
        새 프로세스를 생성 시각 차이로 구별한다.
    """

    def __init__(
        self,
        initial_pids: set[int],
        scanner,
        on_result: Callable[[int, dict], None],
        dump_mode: int = 3,
        poll_interval: float = 1.0,
        rescan_interval: float = 5.0,
        max_rescans: int = 3,
        initial_create_times: dict | None = None,
    ) -> None:
        self._known    = set(initial_pids)
        # PID → 생성 시각 (0.0 = 모름 → PID 만으로 비교)
        self._known_ctime: dict[int, float] = {}
        for _k, _v in (initial_create_times or {}).items():
            try:
                self._known_ctime[int(_k)] = float(_v or 0.0)
            except (TypeError, ValueError):
                continue
        for _pid in self._known:
            self._known_ctime.setdefault(_pid, 0.0)
        self._scanner  = scanner
        self._callback = on_result
        self._dmode    = dump_mode
        self._poll     = poll_interval
        self._rescan_interval = rescan_interval
        self._max_rescans     = max_rescans

        self._stop = threading.Event()
        self._lock = threading.Lock()

        # ── 추적 상태 (모두 _lock 보호) ──────────────────────────────
        self._scanned:     set[int]            = set()   # 스캔 1회 이상 시도한 PID (반환값)
        self._scan_counts: dict[int, int]      = {}      # PID별 (재)스캔 횟수
        self._last_scan:   dict[int, float]    = {}      # PID별 마지막 스캔 시각(monotonic)
        self._found:       set[int]            = set()   # suspicious 확인 → 재스캔 중단
        self._new_pids:    set[int]            = set()   # 신규 생성 프로세스(주기 재스캔 대상)
        self._seen_susp:   dict[int, set[str]] = {}      # PID별 이미 신호 처리한 의심 모듈 경로
        self._scanning:    set[int]            = set()   # 진행 중 스캔(동시 중복 방지)
        self._scan_threads: list[threading.Thread] = []
        self._seen_keys:   set[tuple]          = set()   # 신규로 처리한 (PID, 생성 시각)
        self._signal_pids: set[int]            = set()   # injection 신호로 스캔한 기존 프로세스
        self._new_ctime:   dict[int, float]    = {}      # 신규 PID → 생성 시각

        self._detect_thread = threading.Thread(
            target=self._run_detect, daemon=True, name="PW-detect"
        )
        self._rescan_thread = threading.Thread(
            target=self._run_rescan, daemon=True, name="PW-rescan"
        )

        # 감지 방식 미리 판단 (import 가능 여부만 확인, 실제 연결은 스레드에서)
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
        """실제 사용된 신규 프로세스 감지 방식 ('wmi_etw' 또는 'psutil_poll')."""
        return self._mode

    @property
    def new_pids(self) -> set[int]:
        """분석 중 새로 생성된 것으로 감지된 PID 집합."""
        with self._lock:
            return set(self._new_pids)

    @property
    def inject_signal_pids(self) -> set[int]:
        """의심 모듈 신규 로드(injection 신호)로 스캔한 기존 프로세스 PID 집합."""
        with self._lock:
            return set(self._signal_pids) - set(self._new_pids)

    def start(self, baseline_modules: bool = True, baseline_budget: float = 15.0) -> None:
        """백그라운드 감지 + 재스캔 스레드 시작.

        baseline_modules 가 True 면 기존 프로세스의 의심 경로 모듈을 먼저 기준선으로
        기록한다(최대 baseline_budget 초). 분석 전부터 Temp 경로 DLL 을 쓰던
        프로세스(PyInstaller _MEI, 설치기 등)를 첫 주기에서 '새 신호' 로 오인하지 않게 한다.
        """
        if not self.available:
            return
        if baseline_modules:
            try:
                self.prime_module_baseline(budget=baseline_budget)
            except Exception:
                pass
        self._detect_thread.start()
        self._rescan_thread.start()

    def prime_module_baseline(self, budget: float = 15.0) -> int:
        """기존 프로세스의 의심 경로 모듈을 _seen_susp 기준선으로 채운다.

        Returns
        -------
        int
            기준선에 기록된 프로세스 수.
        """
        deadline = time.monotonic() + max(0.0, budget)
        n = 0
        with self._lock:
            pids = sorted(self._known)
        for pid in pids:
            if time.monotonic() > deadline:
                break
            mods = self._suspicious_modules(pid)
            if mods:
                with self._lock:
                    self._seen_susp.setdefault(pid, set()).update(mods)
                n += 1
        return n

    def stop(self) -> set[int]:
        """감지를 중지하고, 진행 중인 스캔이 모두 끝날 때까지 대기.

        Returns
        -------
        set[int]
            (재)스캔을 시도한 모든 PID 집합 (하위 호환).
            신규 프로세스만 필요하면 :attr:`new_pids`, injection 신호로 스캔한
            기존 프로세스는 :attr:`inject_signal_pids` 를 쓴다.
        """
        self._stop.set()
        for t in (self._detect_thread, self._rescan_thread):
            if t.is_alive():
                t.join(timeout=10)

        # 진행 중인 개별 스캔 스레드 완료 대기 (최대 30초)
        with self._lock:
            pending = list(self._scan_threads)
        for t in pending:
            t.join(timeout=30)

        with self._lock:
            return set(self._scanned)

    # ── 스레드 A: 신규 프로세스 감지 ────────────────────────────────────

    def _run_detect(self) -> None:
        """신규 프로세스 감지 루프. WMI ETW 우선, 실패 시 psutil 폴링 폴백."""
        if not self._run_wmi_etw():
            self._run_polling()

    def _run_wmi_etw(self) -> bool:
        """Win32_ProcessStartTrace (ETW 기반) 즉시 알림으로 신규 프로세스 감지.

        Returns
        -------
        bool
            WMI 초기화·런타임 성공 여부. False 면 폴링 폴백으로 전환.
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
                # ETW 시작 이벤트 자체가 '생성' 이므로 _known(기존 PID) 검사는 하지 않는다.
                # PID 가 재사용된 프로세스도 새 프로세스다. 중복은 (PID, 생성 시각)으로만 막는다.
                if self._register_new(pid, _create_time(pid)):
                    self._on_new_pid(pid)
            except _wmi_mod.x_wmi_timed_out:
                pass   # 정상 타임아웃 — stop 플래그 재확인 후 계속 대기
            except Exception:
                # WMI 런타임 오류 — 감시가 조용히 죽지 않도록 폴링으로 전환
                self._mode = "psutil_poll"
                return False

        return True

    def _run_polling(self) -> None:
        """psutil 폴링 신규 프로세스 감지 (WMI ETW 불가 시 폴백)."""
        self._mode = "psutil_poll"
        while not self._stop.is_set():
            try:
                current: dict[int, float] = {}
                for p in _psutil.process_iter(["pid", "create_time"]):
                    try:
                        current[p.info["pid"]] = float(p.info.get("create_time") or 0.0)
                    except Exception:
                        continue
                new_list: list[int] = []
                for pid, ctime in current.items():
                    if self._is_new_identity(pid, ctime) and self._register_new(pid, ctime):
                        new_list.append(pid)
                for pid in new_list:
                    self._on_new_pid(pid)
            except Exception:
                pass
            self._stop.wait(self._poll)

    def _is_new_identity(self, pid: int, ctime: float) -> bool:
        """폴링에서 본 (PID, 생성 시각)이 이미 아는 프로세스와 다른가."""
        with self._lock:
            if pid not in self._known_ctime:
                return True
            known = self._known_ctime.get(pid, 0.0)
        # 생성 시각을 모르면 PID 만으로 판단 (같은 프로세스로 간주)
        if not known or not ctime:
            return False
        return abs(known - ctime) > 0.01

    def _register_new(self, pid: int, ctime: float) -> bool:
        """(PID, 생성 시각)을 신규로 등록. 이미 처리한 조합이면 False.

        PID 가 재사용된 경우 이전 프로세스의 스캔 상태(_found·_scan_counts 등)를
        초기화해 새 프로세스가 스캔에서 빠지지 않게 한다.
        """
        ctime = float(ctime or 0.0)
        key = (pid, round(ctime, 2))
        with self._lock:
            if key in self._seen_keys:
                return False
            if not ctime and pid in self._new_pids:
                return False          # 생성 시각을 모르는 중복 알림
            self._seen_keys.add(key)
            prev_new = self._new_ctime.get(pid)
            reused = pid in self._known_ctime or prev_new is not None
            if reused:
                self._found.discard(pid)
                self._scan_counts.pop(pid, None)
                self._last_scan.pop(pid, None)
                self._seen_susp.pop(pid, None)
                self._signal_pids.discard(pid)
            self._known.add(pid)
            self._known_ctime[pid] = ctime
            self._new_ctime[pid] = ctime
            return True

    def _on_new_pid(self, pid: int) -> None:
        """신규 PID 를 추적 목록에 등록하고 즉시 1회 스캔."""
        with self._lock:
            self._new_pids.add(pid)
        self._launch_scan(pid, reason="new")

    # ── 스레드 B: injection 신호 + 재스캔 ──────────────────────────────

    def _run_rescan(self) -> None:
        """rescan_interval 간격으로 injection 신호 검사 + 신규 프로세스 재스캔."""
        while not self._stop.is_set():
            self._stop.wait(self._rescan_interval)
            if self._stop.is_set():
                break
            try:
                self._rescan_tick()
            except Exception:
                pass

    def _rescan_tick(self) -> None:
        """한 주기 검사: 실행 중 전체 프로세스에 대해
        (1) 의심 모듈 신규 로드 → 즉시 스캔, (2) 신규 프로세스 주기 재스캔."""
        now = time.monotonic()
        try:
            procs = list(_psutil.process_iter(["pid", "name"]))
        except Exception:
            return

        for p in procs:
            if self._stop.is_set():
                return
            try:
                pid  = p.info["pid"]
                name = (p.info["name"] or "").lower()
            except Exception:
                continue
            if name in _SKIP_NAMES:
                continue

            with self._lock:
                if pid in self._found or pid in self._scanning:
                    continue
                is_new = pid in self._new_pids
                count  = self._scan_counts.get(pid, 0)
                last   = self._last_scan.get(pid, 0.0)
                seen   = set(self._seen_susp.get(pid, ()))

            # (1) injection 신호: 의심 경로 모듈이 "새로" 로드됐는가
            new_susp = self._suspicious_modules(pid) - seen
            if new_susp:
                with self._lock:
                    self._seen_susp.setdefault(pid, set()).update(new_susp)
                    if not is_new:
                        self._signal_pids.add(pid)
                self._launch_scan(pid, reason="inject-signal")
                continue

            # (2) 주기 재스캔: 신규 프로세스만, max_rescans 한도 내에서
            if is_new and count < self._max_rescans and (now - last) >= self._rescan_interval:
                self._launch_scan(pid, reason="periodic")

    def _suspicious_modules(self, pid: int) -> set[str]:
        """프로세스가 현재 로드 중인 모듈 중 injection 의심 경로 집합(소문자)."""
        out: set[str] = set()
        try:
            proc = _psutil.Process(pid)
            for m in proc.memory_maps():
                path = getattr(m, "path", "") or ""
                if is_suspicious_module_path(path):
                    out.add(path.lower())
        except Exception:
            pass  # AccessDenied / NoSuchProcess 등 — 조용히 무시
        return out

    # ── 스캔 실행 ──────────────────────────────────────────────────────

    def _launch_scan(self, pid: int, reason: str = "new") -> None:
        """신규/재스캔 대상 PID 스캔 스레드를 시작 (비차단, 동시 중복 방지)."""
        # 분석 도구는 스킵
        try:
            if _psutil.Process(pid).name().lower() in _SKIP_NAMES:
                return
        except Exception:
            pass  # 이미 종료됐거나 접근 불가 → 스캔 시도는 함

        with self._lock:
            if pid in self._scanning or pid in self._found:
                return
            self._scanning.add(pid)
            self._scanned.add(pid)
            self._scan_counts[pid] = self._scan_counts.get(pid, 0) + 1
            self._last_scan[pid]   = time.monotonic()
            t = threading.Thread(
                target=self._scan_one, args=(pid, reason), daemon=True
            )
            self._scan_threads.append(t)
        t.start()

    def _scan_one(self, pid: int, reason: str) -> None:
        """단일 PID pe-sieve 스캔 (스레드 실행 대상)."""
        try:
            raw = self._scanner.scan_pid(
                pid,
                dump_mode=self._dmode,
                shellcode=1,   # 패턴 기반 쉘코드 탐지
            )
            # suspicious 확인 시 이후 재스캔 중단 (이미 덤프 확보)
            if _raw_suspicious(raw) > 0:
                with self._lock:
                    self._found.add(pid)
            self._callback(pid, raw)
        except Exception as exc:
            # 스캔 예외를 조용히 버리지 않고 오류 결과로 넘긴다 (호출부 집계용)
            try:
                self._callback(pid, {"error": f"실시간 스캔 예외 ({reason}): {exc}", "pid": pid})
            except Exception:
                pass
        finally:
            with self._lock:
                self._scanning.discard(pid)


def _raw_suspicious(raw: dict) -> int:
    """pe-sieve raw JSON 에서 suspicious 카운트를 추출 (현재·구버전 형식 모두)."""
    return raw_suspicious_count(raw)


def _create_time(pid: int) -> float:
    """psutil 로 프로세스 생성 시각을 읽는다 (실패 시 0.0)."""
    if not _PSUTIL_OK:
        return 0.0
    try:
        return float(_psutil.Process(pid).create_time())
    except Exception:
        return 0.0
