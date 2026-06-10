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
    size_bytes:   int       = 0
    md5:          str       = ""    # 덤프 파일 MD5
    sha256:       str       = ""    # 덤프 파일 SHA256
    yara_matches: list[str] = field(default_factory=list)  # 매칭된 YARA 룰 이름
    capa_techs:   list      = field(default_factory=list)  # list[MitreTechnique]
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

def _collect_shellcode_files(dump_dir_str: str) -> list[Path]:
    """dump_dir 내 쉘코드 파일(.shc / .bin 등 non-PE) 목록을 반환합니다."""
    from parsers.pesieve_result import classify_dump_files

    if not dump_dir_str:
        return []
    dump_dir = Path(dump_dir_str)
    if not dump_dir.exists():
        return []

    all_files = [p for p in dump_dir.iterdir() if p.is_file() and p.suffix != ".json"]
    if not all_files:
        return []

    return classify_dump_files(all_files)["shellcode"]


# ---------------------------------------------------------------------------
# 메인 진입점
# ---------------------------------------------------------------------------

def analyze_shellcode_dumps(
    pe_sieve_results: list,
    hh_result,
    new_pids:   set[int],
    capa_exe:   str | None = None,
    rules_dir:  Path | None = None,
    timeout:    int = 60,
) -> list[ShellcodeAnalysis]:
    """필터링된 PeSieveResult 의 쉘코드 덤프에 YARA + CAPA 를 수행합니다.

    오탐 필터링(화이트리스트 + 점수 기준 + 신규 PID)을 적용한 뒤
    실제 쉘코드 파일이 있는 경우에만 YARA + CAPA 로 분석합니다.

    Parameters
    ----------
    pe_sieve_results : list[PeSieveResult]  pe-sieve 스캔 결과
    hh_result        : HollowsHunterResult | None
    new_pids         : 분석 중 새로 생성된 PID 집합 (오탐 필터용)
    capa_exe         : capa 실행 파일 경로 (None = 자동 탐색)
    rules_dir        : YARA 룰 디렉터리 (None = 기본 rules/yaraify/)
    timeout          : CAPA 타임아웃(초), 파일당 적용

    Returns
    -------
    list[ShellcodeAnalysis]
        분석 결과 목록. 필터에 걸려 제외된 경우 포함되지 않음.
    """
    results: list[ShellcodeAnalysis] = []
    seen_files: set[str] = set()   # 동일 파일 중복 분석 방지

    # ── 분석 대상 PeSieveResult 수집 ──────────────────────────────────
    candidates: list = []

    for pr in pe_sieve_results or []:
        if should_reanalyze(pr, new_pids):
            candidates.append(pr)

    # hollows-hunter 의심 프로세스도 포함 (pe-sieve 와 dump_dir 이 겹칠 수 있으므로 seen_files 로 중복 방지)
    if hh_result and not getattr(hh_result, "error", ""):
        for pr in getattr(hh_result, "process_results", []) or []:
            if getattr(pr, "suspicious", 0) > 0 and should_reanalyze(pr, new_pids):
                candidates.append(pr)

    if not candidates:
        return results

    # ── 파일별 YARA + CAPA 수행 ────────────────────────────────────────
    for pr in candidates:
        shc_files = _collect_shellcode_files(getattr(pr, "dump_dir", ""))

        for dump_path in shc_files:
            abs_path = str(dump_path.resolve())
            if abs_path in seen_files:
                continue
            seen_files.add(abs_path)

            sa = ShellcodeAnalysis(
                dump_file = abs_path,
                pid       = pr.pid,
                proc_name = getattr(pr, "name", "") or f"pid_{pr.pid}",
            )

            try:
                sa.size_bytes = dump_path.stat().st_size
            except Exception:
                pass

            # 해시 계산 (MD5 + SHA256)
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

            # YARA 스캔
            try:
                sa.yara_matches = run_yara_on_dump(dump_path, rules_dir)
            except Exception as exc:
                sa.error += f"YARA: {exc}  "

            # CAPA --shellcode
            try:
                sa.capa_techs = run_capa_shellcode(dump_path, capa_exe, timeout)
            except Exception as exc:
                sa.error += f"CAPA: {exc}"

            results.append(sa)

    return results
