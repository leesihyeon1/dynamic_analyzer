"""
shellcode_analyzer.py — 덤프된 쉘코드 파일 재분석 (YARA + CAPA)

pe-sieve / hollows-hunter 가 process_{pid}/ 에 덤프한
.shc / .bin 파일을 대상으로:
  1. YARA 룰 스캔  — 패밀리·시그니처 식별
  2. CAPA --shellcode — ATT&CK 기법 매핑

오탐 필터링 기준
-----------------
* 시스템 프로세스 화이트리스트 (dwm, explorer, chrome 등): 무조건 제외
* suspicion_score < 30: shc 단독 탐지는 JIT/시스템 메모리 아티팩트로 간주
* new_pids (분석 중 신규 생성 PID): 위 기준 관계없이 분석 대상 포함

    score 계산 규칙
    ───────────────
    implanted_pe  > 0 → +40  (PE 인젝션 — 강력한 신호)
    replaced      > 0 → +40  (프로세스 할로잉)
    hooked        > 0 → +20  (IAT/인라인 훅)
    implanted_shc > 0 → +10  (쉘코드 단독 — JIT 오탐 많음)

    점수 30 이상이어야 분석 대상.
    즉, shc 단독(10점) 또는 patched 단독(20점)은 제외됨.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# 오탐 필터 상수
# ---------------------------------------------------------------------------

_SYSTEM_PROC_WHITELIST: frozenset[str] = frozenset({
    # Windows 핵심 시스템 프로세스
    "dwm.exe", "explorer.exe", "searchapp.exe", "textinputhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "spoolsv.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
    "audiodg.exe", "fontdrvhost.exe", "smss.exe", "wininit.exe",
    "services.exe", "registry", "system",
    # 브라우저 (JIT로 인한 shc 오탐 다수)
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "opera.exe", "brave.exe",
    # .NET / JIT 관련
    "mscorsvw.exe", "ngentask.exe",
    # 분석 도구 자체 (HH 가 자기 자신을 탐지하는 케이스 방지)
    "hollows_hunter.exe", "pe-sieve64.exe", "pe-sieve.exe",
    "processhacker.exe", "systeminformer.exe",
    "wireshark.exe", "dumpcap.exe", "tshark.exe",
    "procmon.exe", "procmon64.exe",
})

_SCORE_THRESHOLD: int = 30


# ---------------------------------------------------------------------------
# 의심도 점수 + 필터
# ---------------------------------------------------------------------------

def suspicion_score(r) -> int:
    """PeSieveResult → 의심도 점수.

    shc 단독(10점)은 오탐 가능성이 높으므로 임계값(30) 미만으로 설정.
    PE 인젝션이나 프로세스 할로잉이 함께 탐지돼야 진짜 인젝션으로 간주.
    """
    score = 0
    if getattr(r, "implanted_pe",  0) > 0: score += 40
    if getattr(r, "replaced",      0) > 0: score += 40
    if getattr(r, "hooked",        0) > 0: score += 20
    if getattr(r, "implanted_shc", 0) > 0: score += 10
    return score


def should_reanalyze(r, new_pids: set[int]) -> bool:
    """덤프 재분석 대상 여부 판별.

    반환 True 조건 (둘 중 하나):
      A) 분석 시작 후 새로 생성된 PID   → 점수 무관하게 포함
      B) 화이트리스트 外 + 점수 ≥ 30   → 복합 탐지 신호

    Parameters
    ----------
    r        : PeSieveResult
    new_pids : 분석 기간 중 새로 생성된 PID 집합
    """
    # 화이트리스트 프로세스는 점수와 무관하게 제외
    if getattr(r, "name", "").lower() in _SYSTEM_PROC_WHITELIST:
        return False
    # 신규 PID 이거나 복합 탐지 점수 기준 통과
    return r.pid in new_pids or suspicion_score(r) >= _SCORE_THRESHOLD


# ---------------------------------------------------------------------------
# 결과 데이터클래스
# ---------------------------------------------------------------------------

@dataclass
class ShellcodeAnalysis:
    """단일 덤프 파일에 대한 쉘코드 재분석 결과."""
    dump_file:    str
    pid:          int
    proc_name:    str
    proc_exe:     str       = ""    # 프로세스 실행 파일 경로
    proc_cmdline: str       = ""    # 프로세스 명령줄
    size_bytes:   int       = 0
    md5:          str       = ""    # 덤프 파일 MD5
    sha256:       str       = ""    # 덤프 파일 SHA256
    yara_matches: list[str] = field(default_factory=list)  # 매칭된 YARA 룰 이름
    capa_techs:   list      = field(default_factory=list)  # list[MitreTechnique]
    vt_detections: int      = -1   # -1 = 미조회/미등록, 0+ = 탐지 수
    vt_total:      int      = 0    # 전체 VT 스캔 엔진 수
    vt_label:      str      = ""   # VT 위협 레이블
    error:        str       = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.yara_matches or self.capa_techs)


# ---------------------------------------------------------------------------
# CAPA 쉘코드 모드 래퍼
# ---------------------------------------------------------------------------

def run_capa_shellcode(
    dump_path: Path,
    capa_exe:  str | None = None,
    timeout:   int = 60,
) -> list:
    """CAPA --shellcode 플래그로 raw 쉘코드 파일을 분석합니다.

    기존 run_capa() 와 달리 --shellcode 플래그를 추가합니다.
    capa 가 없거나 실패하면 빈 리스트를 반환합니다.

    Returns
    -------
    list[MitreTechnique]
    """
    from analysis.capa_analyzer import find_capa, _parse_capa_json

    exe = capa_exe or find_capa()
    if not exe or not dump_path.exists():
        return []

    try:
        proc = subprocess.run(
            [exe, str(dump_path), "--shellcode", "-j"],
            capture_output=True,
            timeout=timeout,
        )
        # returncode: 0 = 탐지 없음, 1 = 탐지 있음, 기타 = 오류
        if proc.returncode not in (0, 1):
            return []
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return []
        data = json.loads(stdout)
        return _parse_capa_json(data)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# YARA 쉘코드 스캔 래퍼
# ---------------------------------------------------------------------------

def run_yara_on_dump(dump_path: Path, rules_dir: Path | None = None) -> list[str]:
    """단일 덤프 파일에 YARA 룰을 적용하고 매칭된 룰 이름 목록을 반환합니다.

    yara-python 미설치 또는 룰 디렉터리 없으면 빈 리스트 반환.
    """
    from analysis.yara_scanner import _load_compiled_rules, _scan_single, _RULES_DIR

    _dir = rules_dir or _RULES_DIR
    compiled, _, _ = _load_compiled_rules(_dir)
    if compiled is None:
        return []

    matches = _scan_single(compiled, dump_path, timeout=30)
    return [m.rule_name for m in matches]


# ---------------------------------------------------------------------------
# 덤프 파일 수집 헬퍼
# ---------------------------------------------------------------------------

def _is_pe_file(path: Path) -> bool:
    """MZ 헤더 확인으로 PE 파일 여부를 반환합니다."""
    try:
        return path.read_bytes()[:2] == b"MZ"
    except Exception:
        return False


def _collect_all_dump_files(dump_dir_str: str) -> list[Path]:
    """dump_dir 내 모든 파일(.json 제외) 목록을 반환합니다."""
    if not dump_dir_str:
        return []
    dump_dir = Path(dump_dir_str)
    if not dump_dir.exists():
        return []
    return [p for p in dump_dir.iterdir() if p.is_file() and p.suffix != ".json"]


def _lookup_proc_info(pid: int, proc_snapshots: dict | None) -> tuple[str, str, str]:
    """proc_snapshots 에서 (proc_name, proc_exe, proc_cmdline) 를 반환합니다."""
    if proc_snapshots and pid in proc_snapshots:
        snap = proc_snapshots[pid]
        name = getattr(snap, "name", "") or ""
        exe  = getattr(snap, "exe", "") or ""
        cmdline_list = getattr(snap, "cmdline", []) or []
        cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
        return name or f"pid_{pid}", exe, cmdline
    return f"pid_{pid}", "", ""


# ---------------------------------------------------------------------------
# 메인 진입점
# ---------------------------------------------------------------------------

def analyze_shellcode_dumps(
    pe_sieve_results: list,
    hh_result,
    new_pids:       set[int],
    dumps_root:     "Path | str | None" = None,
    proc_snapshots: dict | None = None,
    capa_exe:       str | None = None,
    rules_dir:      Path | None = None,
    timeout:        int = 60,
) -> list[ShellcodeAnalysis]:
    """pe-sieve / HH 덤프 디렉터리 전체에 YARA + CAPA 를 수행합니다.

    두 경로로 파일을 수집합니다:
    1. pe-sieve / HH 결과 중 오탐 필터(화이트리스트 + 점수 + 신규PID)를 통과한 프로세스
    2. dumps_root 하위 모든 폴더의 모든 파일 (화이트리스트만 제외)

    Parameters
    ----------
    pe_sieve_results : list[PeSieveResult]
    hh_result        : HollowsHunterResult | None
    new_pids         : 분석 중 새로 생성된 PID 집합
    dumps_root       : dumps 최상위 디렉터리 (None 이면 추가 스캔 없음)
    proc_snapshots   : dict[int, ProcessSnapshot] — 프로세스 정보 조회용
    capa_exe         : capa 실행 파일 경로 (None = 자동 탐색)
    rules_dir        : YARA 룰 디렉터리 (None = 기본)
    timeout          : CAPA 타임아웃(초), 파일당 적용
    """
    import re as _re

    results: list[ShellcodeAnalysis] = []
    seen_files: set[str] = set()

    def _analyze_file(dump_path: Path, pid: int, proc_name: str,
                      proc_exe: str, proc_cmdline: str) -> "ShellcodeAnalysis":
        sa = ShellcodeAnalysis(
            dump_file    = str(dump_path.resolve()),
            pid          = pid,
            proc_name    = proc_name,
            proc_exe     = proc_exe,
            proc_cmdline = proc_cmdline,
        )
        try:
            sa.size_bytes = dump_path.stat().st_size
        except Exception:
            pass
        try:
            import hashlib as _hl
            _md5    = _hl.md5()
            _sha256 = _hl.sha256()
            with open(dump_path, "rb") as _fh:
                for _chunk in iter(lambda: _fh.read(65536), b""):
                    _md5.update(_chunk)
                    _sha256.update(_chunk)
            sa.md5    = _md5.hexdigest()
            sa.sha256 = _sha256.hexdigest()
        except Exception:
            pass
        try:
            sa.yara_matches = run_yara_on_dump(dump_path, rules_dir)
        except Exception as exc:
            sa.error += f"YARA: {exc}  "
        # PE 덤프는 CAPA 생략 — pe-sieve 가 이미 분석했고 CAPA PE 모드는 파일당 수십 초 소요
        if not _is_pe_file(dump_path):
            try:
                sa.capa_techs = run_capa_shellcode(dump_path, capa_exe, timeout)
            except Exception as exc:
                sa.error += f"CAPA: {exc}"
        return sa

    # ── 1. pe-sieve / HH 오탐 필터 통과 프로세스 ──────────────────────
    candidates: list = []
    for pr in pe_sieve_results or []:
        if should_reanalyze(pr, new_pids):
            candidates.append(pr)
    if hh_result and not getattr(hh_result, "error", ""):
        for pr in getattr(hh_result, "process_results", []) or []:
            if getattr(pr, "suspicious", 0) > 0 and should_reanalyze(pr, new_pids):
                candidates.append(pr)

    for pr in candidates:
        _snap_name, _snap_exe, _snap_cmdline = _lookup_proc_info(pr.pid, proc_snapshots)
        proc_name = getattr(pr, "name", "") or _snap_name
        proc_exe  = _snap_exe
        proc_cmdline = _snap_cmdline

        for dump_path in _collect_all_dump_files(getattr(pr, "dump_dir", "")):
            abs_path = str(dump_path.resolve())
            if abs_path in seen_files:
                continue
            seen_files.add(abs_path)
            results.append(_analyze_file(dump_path, pr.pid, proc_name, proc_exe, proc_cmdline))

    # ── 2. dumps_root 전체 폴더 순회 (화이트리스트만 제외) ───────────────
    if dumps_root is not None:
        _dr = Path(dumps_root)
        if _dr.exists():
            for subdir in sorted(_dr.iterdir()):
                if not subdir.is_dir():
                    continue
                _m = _re.search(r'(\d+)', subdir.name)
                if not _m:
                    continue
                _pid = int(_m.group(1))

                _snap_name, _snap_exe, _snap_cmdline = _lookup_proc_info(_pid, proc_snapshots)
                if _snap_name.lower() in _SYSTEM_PROC_WHITELIST:
                    continue

                # dumps_root 전체 스캔: non-PE 만 — PE 는 pe-sieve 결과에서 이미 처리
                for dump_path in [p for p in subdir.iterdir()
                                  if p.is_file() and p.suffix != ".json" and not _is_pe_file(p)]:
                    abs_path = str(dump_path.resolve())
                    if abs_path in seen_files:
                        continue
                    seen_files.add(abs_path)
                    results.append(_analyze_file(dump_path, _pid, _snap_name, _snap_exe, _snap_cmdline))

    return results
