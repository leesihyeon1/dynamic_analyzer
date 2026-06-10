"""
pesieve_result.py - Parse pe-sieve and hollows-hunter JSON output.

pe-sieve JSON 구조 (요약):
    {
      "pid": 1234,
      "is_64bit": 1,
      "scanned": {"total": 15, "suspicious": 2, "replaced": 1,
                  "implanted": 1, "implanted_pe": 1, "implanted_shc": 0},
      "scans": [
        {
          "module": "C:\\Windows\\notepad.exe",
          "status": 1,
          "dump_file": "notepad.exe_0x400000.dll",
          "suspicious_count": 2,
          "patches_count": 3,
          "implanted_count": 1
        }, ...
      ]
    }

hollows-hunter JSON 구조 (요약):
    {
      "total_scanned": 100,
      "suspicious": 3,
      "processes": [
        {"pid": 1234, "name": "notepad.exe", "suspicious": 2,
         "scanned": {...}, "scans": [...]}
      ]
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InjectedModule:
    """단일 프로세스 모듈에서 탐지된 이상 징후."""
    module_path:     str
    suspicious_count: int = 0
    patches_count:   int  = 0
    implanted_count: int  = 0
    dump_file:       str  = ""    # pe-sieve가 덤프한 파일 경로 (상대)
    is_shellcode:    bool = False  # PE가 아닌 실행 가능 메모리 (shellcode)
    status:          int  = 0     # pe-sieve status code


@dataclass
class PeSieveResult:
    """단일 PID에 대한 pe-sieve 스캔 결과."""
    pid:            int
    name:           str               = ""    # 프로세스 이름 (hollows-hunter summary 포함)
    is_64bit:       bool              = False
    total_scanned:  int               = 0
    suspicious:     int               = 0
    replaced:       int               = 0
    implanted:      int               = 0
    implanted_pe:   int               = 0
    implanted_shc:  int               = 0   # 쉘코드 (non-PE RX 메모리)
    hooked:         int               = 0
    modules:        list[InjectedModule] = field(default_factory=list)
    dump_dir:       str               = ""
    error:          str               = ""

    @property
    def has_findings(self) -> bool:
        return self.suspicious > 0 or bool(self.error) is False and self.suspicious > 0


@dataclass
class HollowsHunterResult:
    """hollows-hunter 전체 시스템 스캔 결과."""
    total_scanned:   int                  = 0
    suspicious_count: int                 = 0
    process_results: list[PeSieveResult]  = field(default_factory=list)
    dump_dir:        str                  = ""
    error:           str                  = ""

    @property
    def suspicious_processes(self) -> list[PeSieveResult]:
        return [r for r in self.process_results if r.suspicious > 0]


# ---------------------------------------------------------------------------
# pe-sieve JSON → PeSieveResult
# ---------------------------------------------------------------------------

def parse_pesieve(raw: dict, dump_dir: str = "") -> PeSieveResult:
    """Convert a raw pe-sieve JSON dict to a PeSieveResult.

    Parameters
    ----------
    raw:
        Dict as returned by json.loads() of pe-sieve output.
    dump_dir:
        Directory where dump files are stored (used to build full paths).
    """
    if "error" in raw:
        return PeSieveResult(
            pid=raw.get("pid", 0),
            error=raw["error"],
            dump_dir=raw.get("dump_dir", dump_dir),
        )

    scanned = raw.get("scanned", {}) or {}

    # ── HH summary 형식 감지 ──────────────────────────────────────────
    # hollows-hunter summary.json 은 anomaly 필드를 중첩 없이 최상위에 씁니다:
    #   {"pid": 476, "name": "dwm.exe", "implanted_shc": 60, ...}
    # pe-sieve JSON 은 "scanned" 딕셔너리 아래에 씁니다:
    #   {"pid": 476, "scanned": {"implanted_shc": 60, ...}}
    # scanned 딕셔너리가 없고 최상위에 anomaly 필드가 있으면 HH summary 형식으로 처리.
    hh_summary_fmt = (not scanned) and ("implanted_shc" in raw or "implanted_pe" in raw
                                        or "replaced" in raw or "patched" in raw)

    def _top(key: str, *alt: str) -> int:
        """최상위 필드에서 정수값을 읽습니다 (HH summary 전용)."""
        for k in (key,) + alt:
            v = raw.get(k, 0)
            if isinstance(v, int):
                return v
        return 0

    if hh_summary_fmt:
        shc   = _top("implanted_shc")
        pe_i  = _top("implanted_pe")
        repl  = _top("replaced")
        patch = _top("patched")
        hdr   = _top("hdr_modified")
        other = _top("other")
        total_susp = shc + pe_i + repl + patch + hdr + other
        result = PeSieveResult(
            pid           = raw.get("pid", 0),
            name          = raw.get("name", ""),
            is_64bit      = bool(raw.get("is_64bit", 0)),
            total_scanned = 1,           # HH summary 는 프로세스 단위, scanned=1
            suspicious    = total_susp,
            replaced      = repl,
            implanted_pe  = pe_i,
            implanted_shc = shc,
            hooked        = patch + hdr,
            dump_dir      = raw.get("dump_dir", dump_dir),
        )
        # 의심 항목이 있으면 모듈 항목 1개 생성 (프로세스 이름으로)
        if total_susp > 0:
            result.modules.append(InjectedModule(
                module_path      = raw.get("name", f"pid_{raw.get('pid',0)}"),
                suspicious_count = total_susp,
                patches_count    = patch + hdr,
                implanted_count  = shc + pe_i,
                is_shellcode     = shc > 0 and pe_i == 0,
                status           = 1,
            ))
        return result

    result = PeSieveResult(
        pid          = raw.get("pid", 0),
        name         = raw.get("name", ""),
        is_64bit     = bool(raw.get("is_64bit", 0)),
        total_scanned = scanned.get("total", 0),
        suspicious   = scanned.get("suspicious", 0),
        replaced     = scanned.get("replaced", 0),
        implanted    = scanned.get("implanted", 0),
        implanted_pe = scanned.get("implanted_pe", 0),
        implanted_shc= scanned.get("implanted_shc", 0),
        hooked       = scanned.get("hooked", 0),
        dump_dir     = raw.get("dump_dir", dump_dir),
    )

    for scan in raw.get("scans") or []:
        if not isinstance(scan, dict):
            continue
        status = scan.get("status", 0)
        if status == 0:
            continue  # clean

        dump_rel = scan.get("dump_file", "")
        dump_abs = ""
        if dump_rel and result.dump_dir:
            candidate = Path(result.dump_dir) / dump_rel
            dump_abs  = str(candidate) if candidate.exists() else dump_rel

        # Heuristic: implanted_shc > 0 or dump_file ends with .shc/.bin = shellcode
        is_shc = (
            scan.get("implanted_shc", 0) > 0
            or (dump_rel.lower().endswith((".shc", ".bin")))
        )

        result.modules.append(InjectedModule(
            module_path      = scan.get("module", ""),
            suspicious_count = scan.get("suspicious_count", 0),
            patches_count    = scan.get("patches_count", 0),
            implanted_count  = scan.get("implanted_count", 0),
            dump_file        = dump_abs or dump_rel,
            is_shellcode     = is_shc,
            status           = status,
        ))

    return result


# ---------------------------------------------------------------------------
# hollows-hunter JSON → HollowsHunterResult
# ---------------------------------------------------------------------------

def parse_hollows_hunter(raw: dict) -> HollowsHunterResult:
    """Convert a raw hollows-hunter JSON dict to a HollowsHunterResult.

    hollows-hunter 버전에 따라 JSON 키 이름이 다를 수 있으므로
    여러 후보 키를 순서대로 시도합니다.
    """
    if "error" in raw:
        return HollowsHunterResult(error=raw["error"], dump_dir=raw.get("dump_dir", ""))

    dump_dir = raw.get("dump_dir", "")

    def _get_int(*keys: str, default: int = 0) -> int:
        """여러 키 이름을 시도해 정수값을 반환. int가 아니면(dict 등) 스킵."""
        for k in keys:
            v = raw.get(k)
            if isinstance(v, int):
                return v
        return default

    # ── 프로세스 목록 키 후보 ─────────────────────────────────────────
    # HH summary.json: "suspicious" 키에 의심 프로세스 목록만 있음
    # HH full output:  "processes" 키에 전체 스캔 결과
    proc_list = (
        raw.get("processes")
        or raw.get("scanned_processes")
        or raw.get("results")
        or raw.get("suspicious")   # HH summary.json 형식
        or []
    )
    if not isinstance(proc_list, list):
        proc_list = []

    # ── 스캔된 프로세스 수 ────────────────────────────────────────────
    # HH summary.json: "scanned_count"
    # HH full output:  "total_scanned" 또는 "scanned" (int)
    scanned_raw = raw.get("scanned")
    if isinstance(scanned_raw, int):
        total_sc = scanned_raw
    elif isinstance(scanned_raw, dict):
        total_sc = scanned_raw.get("total", 0)
    else:
        total_sc = _get_int("scanned_count", "total_scanned", "scanned_total",
                            "total", default=len(proc_list))

    # ── 의심 프로세스 수 ──────────────────────────────────────────────
    # HH summary.json: "suspicious_count"
    # HH full output:  "suspicious" (int, dict가 아닌 경우)
    suspicious_raw = raw.get("suspicious")
    if isinstance(suspicious_raw, int):
        susp_cnt = suspicious_raw
    else:
        susp_cnt = _get_int("suspicious_count", "total_suspicious",
                            "suspicious_total", default=len(proc_list))

    result = HollowsHunterResult(
        total_scanned    = total_sc,
        suspicious_count = susp_cnt,
        dump_dir         = dump_dir,
    )

    for proc in proc_list:
        if not isinstance(proc, dict):
            continue
        proc_raw = dict(proc)
        proc_raw["dump_dir"] = dump_dir
        result.process_results.append(parse_pesieve(proc_raw, dump_dir))

    return result


# ---------------------------------------------------------------------------
# Dump file classification
# ---------------------------------------------------------------------------

_PE_MAGIC = b"MZ"


def classify_dump_files(dump_paths: list[Path]) -> dict[str, list[Path]]:
    """Classify dumped files as PE executables or raw shellcode blobs.

    Returns
    -------
    dict with keys:
        "pe"        - files starting with MZ (PE executables / DLLs)
        "shellcode" - non-PE executable blobs
        "other"     - unrecognised
    """
    pe_files:  list[Path] = []
    shc_files: list[Path] = []
    other:     list[Path] = []

    for path in dump_paths:
        try:
            header = path.read_bytes()[:2]
        except Exception:
            other.append(path)
            continue

        if header == _PE_MAGIC:
            pe_files.append(path)
        elif path.suffix.lower() in (".shc", ".bin", ".raw"):
            shc_files.append(path)
        else:
            other.append(path)

    return {"pe": pe_files, "shellcode": shc_files, "other": other}
