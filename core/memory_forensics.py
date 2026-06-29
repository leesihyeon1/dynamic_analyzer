"""
memory_forensics.py — 물리 메모리 덤프 + Volatility3 포렌식 연동

워크플로우:
  1. winpmem / DumpIt 으로 물리 메모리 이미지 획득
  2. Volatility3 핵심 플러그인 실행 (병렬)
     - windows.malfind   : 주입 셸코드·PE 탐지
     - windows.pstree    : 숨겨진 프로세스 포함 트리
     - windows.netscan   : 종료된 연결 포함 네트워크 아티팩트
     - windows.cmdline   : 각 프로세스 커맨드라인 (홀로잉 탐지)
     - windows.handles   : 뮤텍스 이름 → 악성코드 패밀리 식별
     - windows.dlllist   : 의심 PID 별 로드 DLL 목록
  3. 결과 구조화 → MemForensicsResult 반환

한계:
  - 메모리 덤프 시간: RAM 크기에 비례 (4 GB ≈ 1~2분)
  - 덤프 파일 크기: RAM 크기와 동일 (디스크 공간 필요)
  - 관리자 권한 필수 (winpmem 드라이버 로드)
"""
from __future__ import annotations

import collections
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── 도구 탐색 경로 ────────────────────────────────────────────────────────

_WINPMEM_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\winpmem\winpmem_mini_x64_rc2.exe"),
    Path(r"C:\Tools\winpmem\winpmem_mini_x64.exe"),
    Path(r"C:\Tools\winpmem_mini_x64_rc2.exe"),
    Path(r"C:\Tools\winpmem_mini_x64.exe"),
    Path(r"C:\Tools\winpmem.exe"),
    Path(r"C:\Tools\Comae-Toolkit\winpmem.exe"),
]

_DUMPIT_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\DumpIt.exe"),
    Path(r"C:\Tools\Comae\DumpIt.exe"),
    Path(r"C:\Tools\Comae-Toolkit\DumpIt.exe"),
    Path(r"C:\Program Files\Comae Technologies\DumpIt.exe"),
]

_VOL3_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\volatility3\vol.py"),
    Path(r"C:\Tools\volatility3\volatility3\__main__.py"),
    Path(r"C:\volatility3\vol.py"),
]

_VOL3_SCRIPT_NAMES = ("vol", "vol.exe", "vol3", "vol3.exe", "vol.py")

# Volatility3 심볼 디렉터리 고정 후보 경로 (windows/ 하위 폴더가 존재해야 함)
_SYMBOLS_DIR_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\volatility3\volatility3\symbols"),
    Path(r"C:\Tools\volatility3\symbols"),
    Path(r"C:\volatility3\volatility3\symbols"),
    Path(r"C:\volatility3\symbols"),
]


# ── 도구 탐색 ─────────────────────────────────────────────────────────────

def find_winpmem() -> Optional[Path]:
    """winpmem 또는 DumpIt 실행파일 경로 반환."""
    for c in _WINPMEM_CANDIDATES:
        if c.is_file():
            return c
    for name in ("winpmem_mini_x64_rc2.exe", "winpmem_mini_x64.exe", "winpmem.exe"):
        found = shutil.which(name)
        if found:
            return Path(found)
    # DumpIt fallback
    for c in _DUMPIT_CANDIDATES:
        if c.is_file():
            return c
    found = shutil.which("DumpIt.exe") or shutil.which("DumpIt")
    return Path(found) if found else None


def find_local_symbols(vol_cmd: list[str]) -> Optional[Path]:
    """
    Volatility3 심볼 디렉터리 자동 탐색.

    반환값: ``windows/`` 하위 폴더에 ``*.json.xz`` 또는 ``*.json`` 파일이
    있는 심볼 루트 디렉터리(``windows/``의 부모).  없으면 None.

    탐색 순서:
      1. VOLATILITY_SYMBOLS 환경변수
      2. vol.py 위치 기반 (volatility3/symbols 또는 symbols)
      3. 알려진 고정 경로
      4. pip 설치 패키지 내 symbols
    """
    candidates: list[Path] = []

    # 1. 환경변수
    env_sym = os.environ.get("VOLATILITY_SYMBOLS")
    if env_sym:
        candidates.append(Path(env_sym))

    # 2. vol.py / vol.exe 경로 기반
    for c in vol_cmd:
        p = Path(c)
        if p.suffix in (".py",) or p.stem in ("vol", "vol3"):
            candidates.append(p.parent / "volatility3" / "symbols")
            candidates.append(p.parent / "symbols")

    # 3. 고정 경로
    candidates.extend(_SYMBOLS_DIR_CANDIDATES)

    # 4. pip 설치 패키지
    try:
        import volatility3 as _v3
        candidates.append(Path(_v3.__file__).parent / "symbols")
    except Exception:
        pass

    for sym_dir in candidates:
        win_dir = sym_dir / "windows"
        if win_dir.is_dir() and (
            any(win_dir.glob("*.json.xz")) or any(win_dir.glob("*.json"))
        ):
            return sym_dir

    return None


def find_volatility3() -> Optional[tuple[list[str], str]]:
    """
    Volatility3 실행 커맨드 반환.
    Returns (cmd_prefix, kind) where kind is 'script' or 'module'.
    """
    # 1. PATH 에서 vol3 / vol3.exe
    for name in _VOL3_SCRIPT_NAMES:
        found = shutil.which(name)
        if found:
            return ([found], "binary")

    # 2. 알려진 경로의 vol.py
    for c in _VOL3_CANDIDATES:
        if c.is_file():
            return ([sys.executable, str(c)], "script")

    # 3. Python 모듈로 설치된 경우 (pip install volatility3)
    for mod in ("volatility3.cli", "volatility3"):
        try:
            r = subprocess.run(
                [sys.executable, "-m", mod, "--version"],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0:
                return ([sys.executable, "-m", mod], "module")
        except Exception:
            pass

    return None


# ── 결과 데이터클래스 ─────────────────────────────────────────────────────

@dataclass
class MalfindEntry:
    pid:            int
    process:        str
    start_vpn:      str        # 0x... 형식
    end_vpn:        str
    protection:     str        # e.g. PAGE_EXECUTE_READ_WRITE
    private_memory: bool
    hexdump:        str        # 앞 32 바이트 hex
    disasm:         str        # 앞 몇 개 인스트럭션
    shellcode_type: str        = ""  # 쉘코드 유형 자동 분류


@dataclass
class PsTreeEntry:
    pid:        int
    ppid:       int
    name:       str
    offset:     str
    threads:    int
    create_time: str
    cmd:        str
    path:       str


@dataclass
class NetScanEntry:
    proto:        str
    local_addr:   str
    local_port:   int
    foreign_addr: str
    foreign_port: int
    state:        str
    pid:          int
    owner:        str
    created:      str
    suspicious:   bool         = False
    susp_reason:  str          = ""


@dataclass
class CmdlineEntry:
    pid:  int
    name: str
    args: str


@dataclass
class HandleEntry:
    pid:      int
    name:     str
    htype:    str    # Mutant, File, Key 등
    hname:    str    # 핸들 이름
    entropy:  float  = 0.0   # Shannon 엔트로피 (랜덤 문자열 탐지)
    family:   str    = ""    # 알려진 악성코드 패밀리명
    suspicious: bool = False  # 엔트로피 기반 랜덤 문자열 or 패밀리 매칭


@dataclass
class DllEntry:
    pid:  int
    name: str
    base: str
    dll_name: str
    path: str


@dataclass
class PsxviewEntry:
    pid:     int
    name:    str
    offset:  str
    pslist:  bool    # PsActiveProcessLinks 목록에 있음
    psscan:  bool    # pool-tag 스캔에서 발견
    csrss:   bool    # CSRSS 핸들 테이블에 있음
    peb:     bool    # PEB 존재
    hidden:  bool    # psscan에서 발견됐지만 pslist에 없음 = 은닉 의심


@dataclass
class ConnscanEntry:
    proto:        str
    local_addr:   str
    local_port:   int
    foreign_addr: str
    foreign_port: int
    state:        str
    pid:          int
    owner:        str
    created:      str


@dataclass
class ProcDumpEntry:
    pid:       int
    name:      str
    dump_path: str    # 추출된 PE 파일 경로
    size:      int    # 바이트
    reason:    str    # "malfind:PAGE_EXECUTE_READWRITE" 등


@dataclass
class MemForensicsResult:
    dump_path:    Optional[Path]        = None
    dump_size_gb: float                 = 0.0
    dump_elapsed: float                 = 0.0
    vol_elapsed:  float                 = 0.0
    malfind:      list[MalfindEntry]   = field(default_factory=list)
    pstree:       list[PsTreeEntry]    = field(default_factory=list)
    netscan:      list[NetScanEntry]   = field(default_factory=list)
    connscan:     list[ConnscanEntry]  = field(default_factory=list)
    psxview:      list[PsxviewEntry]   = field(default_factory=list)
    cmdline:      list[CmdlineEntry]   = field(default_factory=list)
    handles:      list[HandleEntry]    = field(default_factory=list)
    dlllist:      list[DllEntry]       = field(default_factory=list)
    procdumps:    list[ProcDumpEntry]  = field(default_factory=list)
    plugin_errors: dict[str, str]      = field(default_factory=dict)
    error:        str                  = ""


# ── 분석 헬퍼 상수 ───────────────────────────────────────────────────────

_KNOWN_MUTEX_FAMILIES: list[tuple[str, str]] = [
    ("global\\msse",                 "Cobalt Strike"),
    ("global\\{",                    "Cobalt Strike (Beacon)"),
    ("global\\fsf",                  "Emotet"),
    ("global\\gojoma",               "Emotet"),
    ("global\\wncry@2ol7",           "WannaCry"),
    ("mswingzonescachecountermutex", "WannaCry"),
    ("global\\x2hkk",               "TrickBot"),
    ("qbot",                         "Qakbot"),
    ("qakbot",                       "Qakbot"),
    ("njq8",                         "njRAT"),
    ("remcos",                       "Remcos RAT"),
    ("asyncmutex",                   "AsyncRAT"),
    ("global\\frst",                 "Ursnif/Gozi"),
    ("dridex",                       "Dridex"),
    ("lokibot",                      "LokiBot"),
    ("formbook",                     "FormBook"),
]

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

_C2_PORTS = frozenset({
    4444, 4445, 4446, 4447, 4448, 4449, 4450,
    5555, 6666, 7777, 8888, 9999,
    31337, 31338, 31339,
    1337, 13337,
    9001, 9030, 9050, 9051,
    2222, 3333, 6000,
    1234, 12345,
})

_NORMAL_REMOTE_PORTS = frozenset({
    80, 443, 8080, 8443, 53, 21, 22, 25, 587,
    993, 994, 995, 110, 143, 465, 636, 5985, 5986,
})


# ── 분석 헬퍼 함수 ────────────────────────────────────────────────────────

def _classify_shellcode(hexdump: str, disasm: str) -> str:
    """malfind 결과에서 쉘코드 유형 자동 분류."""
    h = hexdump.replace(" ", "").replace("\n", "").lower()
    d = disasm.lower()

    # PEB 워크 시그니처 — 위치독립 쉘코드 전형 시작 (x86/x64)
    if "648b5230" in h or "648b4130" in h or "65488b52" in h:
        return "PEB워크 쉘코드 (로더/인젝터)"

    # Metasploit stager: FC E8 XX 00 00 00
    if h.startswith("fce8") or "fce882000000" in h or "fce889000000" in h:
        return "Metasploit 스테이저"

    # NOP 슬레드: 0x90 반복
    if len(h) >= 32 and h.count("90") >= 16:
        return "NOP 슬레드 + 쉘코드"

    # test + adc/add — 롤링 XOR 디코더 (0xAA XOR 키 패턴 포함)
    if "test" in d and ("adc" in d or "add" in d):
        return "롤링 XOR 디코더 스텁"

    # xor + loop — 표준 XOR 디코더
    if "xor" in d and "loop" in d:
        return "XOR 디코더 스텁"

    # call + pop — 위치독립 쉘코드 프롤로그
    if "call" in d and "pop" in d:
        return "위치독립 쉘코드 (call/pop 프롤로그)"

    # 디스어셈 없음 = 아직 복호화되지 않은 버퍼
    if not disasm.strip():
        return "암호화 페이로드 버퍼 (미복호화)"

    return "RWX 쉘코드 버퍼"


def _shannon_entropy(s: str) -> float:
    """Shannon 엔트로피 (bits per character)."""
    if len(s) < 2:
        return 0.0
    cnt = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in cnt.values())


def _analyze_mutant(hname: str) -> tuple[float, str, bool]:
    """
    뮤텍스 이름 분석 → (entropy, family, is_suspicious).
    family = 알려진 악성코드 패밀리명, "" = 미매칭.
    is_suspicious = 패밀리 매칭 or 고엔트로피 랜덤 문자열.
    """
    if not hname or hname in ("-", "N/A", ""):
        return 0.0, "", False

    lower = hname.lower()
    for pattern, family in _KNOWN_MUTEX_FAMILIES:
        if pattern in lower:
            return _shannon_entropy(hname), family, True

    name_part = re.sub(r'^(global|local)\\', '', hname, flags=re.IGNORECASE)
    entropy = _shannon_entropy(name_part)

    is_random = (
        entropy >= 3.5
        and 6 <= len(name_part) <= 48
        and bool(re.search(r'[a-zA-Z0-9]', name_part))
        and not re.search(r'[가-힣\s]', name_part)
        and not re.search(r'\.(exe|dll|sys|dat|tmp)$', name_part, re.IGNORECASE)
    )
    return entropy, "", is_random


def _is_external_ip(addr: str) -> bool:
    if not addr or addr in ("0.0.0.0", "::", "*", "-", ""):
        return False
    try:
        ip = ipaddress.ip_address(addr)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
            return False
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _flag_suspicious_netscan(
    foreign_addr: str, foreign_port: int, state: str,
) -> tuple[bool, str]:
    """netscan 항목 의심 여부 판정 → (suspicious, reason)."""
    state_up = (state or "").upper()
    if state_up in ("LISTEN", "CLOSED", "TIME_WAIT", "CLOSE_WAIT"):
        return False, ""

    if not _is_external_ip(foreign_addr):
        return False, ""

    reasons = []
    if foreign_port in _C2_PORTS:
        reasons.append(f"C2 포트 {foreign_port}")

    if foreign_port not in _NORMAL_REMOTE_PORTS and 1024 <= foreign_port <= 49151:
        reasons.append(f"비표준 포트 {foreign_port}")

    if foreign_port > 49151:
        reasons.append(f"고포트 {foreign_port}")

    if reasons:
        return True, " | ".join(reasons)

    if state_up == "ESTABLISHED":
        return True, f"외부 ESTABLISHED (:{foreign_port})"

    return False, ""


# ── 메모리 획득 헬퍼 ─────────────────────────────────────────────────────

def _get_ram_bytes() -> int:
    """물리 RAM 크기 (바이트). 실패 시 0."""
    try:
        import ctypes
        class _MEMSTATEX(ctypes.Structure):
            _fields_ = [
                ("dwLength",                ctypes.c_ulong),
                ("dwMemoryLoad",            ctypes.c_ulong),
                ("ullTotalPhys",            ctypes.c_ulonglong),
                ("ullAvailPhys",            ctypes.c_ulonglong),
                ("ullTotalPageFile",        ctypes.c_ulonglong),
                ("ullAvailPageFile",        ctypes.c_ulonglong),
                ("ullTotalVirtual",         ctypes.c_ulonglong),
                ("ullAvailVirtual",         ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        ms = _MEMSTATEX()
        ms.dwLength = ctypes.sizeof(ms)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
        return ms.ullTotalPhys
    except Exception:
        return 0


def _decode_proc_output(b: bytes) -> str:
    """subprocess 바이트 출력을 UTF-8 → CP949 → latin-1 순서로 디코딩."""
    if not b:
        return ""
    for enc in ("utf-8", "cp949", "latin-1"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("latin-1", errors="replace")


def _prepare_dump_path(
    output_path: Path,
    ram_bytes: int,
    on_status,
) -> tuple[Optional[Path], str]:
    """
    덤프 파일 경로 사전 준비.
    - 기존 덤프 삭제
    - 디스크 여유 공간 확인 (RAM × 1.05 필요)
    - 쓰기 권한 테스트
    - 실패 시 C:\\mem_dump.raw 경로로 폴백

    Returns: (usable_path, warn_msg)  — usable_path=None 이면 모두 실패
    """
    def _try(path: Path) -> tuple[bool, str]:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return False, f"디렉터리 생성 실패: {e}"

        # 기존 파일 삭제 (이전 덤프가 디스크를 점유하는 경우)
        if path.exists():
            try:
                path.unlink()
                if on_status:
                    on_status(f"      [정리] 기존 덤프 삭제: {path.name}")
            except OSError as e:
                return False, f"기존 덤프 삭제 실패 ({path}): {e}"

        # 디스크 여유 공간 확인
        if ram_bytes:
            needed = int(ram_bytes * 1.05)
            try:
                free = shutil.disk_usage(path.parent).free
            except OSError:
                free = 0
            if free and free < needed:
                return False, (
                    f"디스크 공간 부족 — 필요 {needed/1e9:.1f}GB, "
                    f"여유 {free/1e9:.1f}GB ({path.parent})\n"
                    f"  기존 덤프 파일을 삭제하거나 공간이 충분한 드라이브를 사용하세요."
                )

        # 쓰기 권한 테스트
        test = path.parent / ".wmtest"
        try:
            test.write_bytes(b"\x00")
            test.unlink()
            return True, ""
        except OSError as e:
            return False, f"쓰기 권한 없음 ({path.parent}): {e}"

    ok, msg = _try(output_path)
    if ok:
        return output_path, ""

    # 폴백: C:\mem_dump.raw (ASCII 단순 경로)
    alt = Path(r"C:\mem_dump.raw")
    if on_status:
        on_status(f"      [경고] 원래 경로 실패({msg}), 대체 경로 시도: {alt}")
    ok2, msg2 = _try(alt)
    if ok2:
        return alt, f"대체 경로 사용: {alt}"
    return None, f"덤프 경로 준비 실패\n  원래: {msg}\n  대체: {msg2}"


# ── 메모리 획득 ───────────────────────────────────────────────────────────

def acquire_memory(
    output_path: Path,
    tool_path: Optional[Path] = None,
    timeout: int = 600,
    on_status: Optional[object] = None,
) -> tuple[bool, float, str, Path]:
    """
    물리 메모리 덤프 획득.

    Returns: (success, elapsed_sec, error_msg, actual_dump_path)
    actual_dump_path 는 성공 시 실제 파일 위치 (폴백 사용 시 output_path 와 다를 수 있음).
    실패 시 output_path 를 그대로 반환.
    """
    tool = tool_path or find_winpmem()
    if not tool:
        return False, 0.0, "winpmem / DumpIt 미설치", output_path

    # 사전 준비: 경로 점검 / 기존 덤프 정리 / 디스크 공간 확인
    ram_bytes = _get_ram_bytes()
    usable_path, warn = _prepare_dump_path(output_path, ram_bytes, on_status)
    if usable_path is None:
        return False, 0.0, warn, output_path
    if warn and on_status:
        on_status(f"      [정보] {warn}")

    tool_name = tool.name.lower()
    t0 = time.monotonic()

    if "dumpit" in tool_name:
        cmd = [str(tool), "/output", str(usable_path), "/q", "/y"]
    else:
        cmd = [str(tool), str(usable_path)]

    try:
        if on_status:
            on_status(f"      메모리 덤프 시작 ({tool.name}) → {usable_path}")
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        elapsed = round(time.monotonic() - t0, 1)
        stdout = _decode_proc_output(proc.stdout)
        stderr = _decode_proc_output(proc.stderr)
        if not usable_path.exists() or usable_path.stat().st_size < 1_000_000:
            err = (stderr or stdout or "출력 파일 없음")[-600:]
            return False, elapsed, f"덤프 실패 (exit={proc.returncode}): {err}", output_path
        # 폴백 경로를 사용한 경우 원래 위치로 이동 시도
        if usable_path != output_path:
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(usable_path), str(output_path))
                usable_path = output_path
            except Exception:
                pass  # 이동 실패 시 usable_path(폴백 경로) 그대로 사용
        return True, elapsed, "", usable_path
    except subprocess.TimeoutExpired:
        return False, round(time.monotonic() - t0, 1), f"덤프 시간 초과 ({timeout}s)", output_path
    except Exception as e:
        return False, round(time.monotonic() - t0, 1), str(e), output_path


# ── Volatility3 플러그인 실행 ─────────────────────────────────────────────

class VolatilityRunner:
    def __init__(
        self,
        dump_path: Path,
        vol_cmd: list[str],
        timeout_per_plugin: int = 300,
        symbols_path: Optional[Path] = None,
    ) -> None:
        self.dump_path    = dump_path
        self.vol_cmd      = vol_cmd
        self.timeout      = timeout_per_plugin
        self.symbols_path = symbols_path   # None → Volatility3 기본 탐색 경로 사용

    @staticmethod
    def _normalize(parsed) -> dict:
        """
        Volatility3 JSON 출력 → {"columns": [...], "rows": [...]} 정규화.

        Volatility3 버전에 따라 출력 형식이 다름:
          - dict {"columns":…,"rows":…}   → 그대로
          - [{"columns":…,"rows":…}]      → 첫 원소 unwrap
          - [{"col1":v1,"col2":v2},…]     → list-of-dicts → 키를 컬럼으로
          - [["col1","col2"],[v1,v2],…]   → 첫 행이 헤더
        """
        if isinstance(parsed, dict):
            return parsed
        if not isinstance(parsed, list) or not parsed:
            return {"columns": [], "rows": []}
        first = parsed[0]
        # [{"columns":…,"rows":…}] — dict 하나를 배열로 감싼 경우
        if isinstance(first, dict) and "columns" in first and "rows" in first:
            return first
        # list-of-dicts: [{"Variable":"Kernel Base","Value":"0x…"},…]
        if isinstance(first, dict):
            cols = list(first.keys())
            rows = [
                [str(row.get(c, "")) for c in cols]
                for row in parsed if isinstance(row, dict)
            ]
            return {"columns": cols, "rows": rows}
        # list-of-lists: 첫 행이 컬럼 헤더
        if isinstance(first, list):
            return {"columns": [str(c) for c in first], "rows": parsed[1:]}
        return {"columns": [], "rows": parsed}

    def _run(self, plugin: str, extra: list[str] | None = None) -> dict:
        """플러그인 실행 → JSON dict 반환. 실패 시 RuntimeError 발생."""
        cmd = self.vol_cmd + [
            "-f", str(self.dump_path),
            "-r", "json",   # Volatility3 렌더러 플래그 (-r / --renderer)
        ]
        if self.symbols_path:
            cmd += ["-s", str(self.symbols_path)]
        cmd.append(plugin)
        if extra:
            cmd.extend(extra)
        try:
            r = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout,
                text=True, errors="replace",
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{plugin}: 타임아웃 ({self.timeout}s 초과)")

        # Volatility3는 0(성공), 1(경고 포함 성공), 2(심볼 경고) 를 반환할 수 있음
        if r.returncode not in (0, 1, 2):
            stderr_tail = (r.stderr or r.stdout or "")[-400:].strip()
            raise RuntimeError(
                f"{plugin}: exit={r.returncode}"
                + (f"\n{stderr_tail}" if stderr_tail else "")
            )

        # JSON은 stdout에 있고 진행/오류 로그는 stderr에 출력됨
        out = r.stdout.strip()
        if not out:
            stderr_tail = (r.stderr or "")[-800:].strip()
            # Volatility3가 "다운로드 실패"로 확정되는 패턴만 감지
            # "automagic" 등 정상 로그 키워드는 포함하지 않음
            _hard_fail_kws = (
                "unsatisfied requirement",
                "requirements are not satisfied",
                "could not find a pdb",
                "no suitable address space mapping",
                "failed to download",
            )
            if stderr_tail and any(k in stderr_tail.lower() for k in _hard_fail_kws):
                raise RuntimeError(
                    f"{plugin}: 심볼 파일 없음 — "
                    "`vol -f <dump> windows.info` 실행 시 자동 다운로드\n"
                    + stderr_tail[-400:]
                )
            raise RuntimeError(
                f"{plugin}: 출력 없음"
                + (f"\n[stderr] {stderr_tail[-400:]}" if stderr_tail else "")
            )

        # stdout에서 첫 번째 유효한 JSON 위치 탐색
        # (앞에 로그/배너 라인이 섞일 수 있음 → 파싱 실패 시 continue로 다음 위치 시도)
        for i, ch in enumerate(out):
            if ch not in ('{', '['):
                continue
            try:
                parsed = json.loads(out[i:])
            except json.JSONDecodeError:
                continue   # 이 위치는 JSON 아님 → 다음 위치 계속 탐색
            return self._normalize(parsed)

        # 어떤 위치에서도 유효한 JSON 없음 → stderr 에서 원인 추출
        stderr_tail = (r.stderr or "")[-800:].strip()
        _hard_fail_kws = (
            "unsatisfied requirement",
            "requirements are not satisfied",
            "could not find a pdb",
            "no suitable address space mapping",
            "failed to download",
        )
        if stderr_tail and any(k in stderr_tail.lower() for k in _hard_fail_kws):
            raise RuntimeError(
                f"{plugin}: 심볼 파일 없음 — "
                "`vol -f <dump> windows.info` 실행 시 자동 다운로드\n"
                + stderr_tail[-400:]
            )
        raise RuntimeError(
            f"{plugin}: stdout에 JSON 없음\n"
            f"  stdout: {out[:200]}\n"
            f"  stderr: {stderr_tail[-300:]}"
        )

    def _col(self, data: dict, row: list, col_name: str, default="") -> str:
        """컬럼 이름으로 row 값 조회."""
        cols = data.get("columns", [])
        try:
            idx = cols.index(col_name)
            v = row[idx] if idx < len(row) else default
            return str(v) if v is not None else default
        except (ValueError, IndexError):
            return default

    def _col_int(self, data: dict, row: list, col_name: str, default: int = 0) -> int:
        v = self._col(data, row, col_name, str(default))
        try:
            return int(str(v).replace(",", ""))
        except Exception:
            return default

    # ── 개별 플러그인 ────────────────────────────────────────────────

    def malfind(self, pid_filter: set[int] | None = None) -> list[MalfindEntry]:
        data = self._run("windows.malfind")
        results = []
        for row in (data.get("rows") or []):
            pid = self._col_int(data, row, "PID") or self._col_int(data, row, "Pid")
            if pid_filter and pid not in pid_filter:
                continue
            hexdump = self._col(data, row, "Hexdump")[:64]
            disasm  = self._col(data, row, "Disasm")[:256]
            results.append(MalfindEntry(
                pid=pid,
                process=self._col(data, row, "Process") or self._col(data, row, "ImageFileName"),
                start_vpn=self._col(data, row, "Start VPN") or self._col(data, row, "VPN"),
                end_vpn=self._col(data, row, "End VPN"),
                protection=self._col(data, row, "Protection"),
                private_memory=str(self._col(data, row, "PrivateMemory")).lower() in ("true", "1"),
                hexdump=hexdump,
                disasm=disasm,
                shellcode_type=_classify_shellcode(hexdump, disasm),
            ))
        return results

    def pstree(self) -> list[PsTreeEntry]:
        data = self._run("windows.pstree")
        results = []
        for row in (data.get("rows") or []):
            results.append(PsTreeEntry(
                pid=self._col_int(data, row, "PID") or self._col_int(data, row, "Pid"),
                ppid=self._col_int(data, row, "PPID") or self._col_int(data, row, "PPid"),
                name=self._col(data, row, "ImageFileName") or self._col(data, row, "Name"),
                offset=self._col(data, row, "Offset(V)") or self._col(data, row, "Offset"),
                threads=self._col_int(data, row, "Threads"),
                create_time=self._col(data, row, "CreateTime"),
                cmd=self._col(data, row, "Cmd"),
                path=self._col(data, row, "Path"),
            ))
        return results

    def netscan(self) -> list[NetScanEntry]:
        data = self._run("windows.netscan")
        results = []
        for row in (data.get("rows") or []):
            lport = self._col(data, row, "LocalPort")
            fport = self._col(data, row, "ForeignPort")
            foreign_addr = self._col(data, row, "ForeignAddr")
            foreign_port = int(fport) if str(fport).isdigit() else 0
            state        = self._col(data, row, "State")
            susp, reason = _flag_suspicious_netscan(foreign_addr, foreign_port, state)
            results.append(NetScanEntry(
                proto=self._col(data, row, "Proto"),
                local_addr=self._col(data, row, "LocalAddr"),
                local_port=int(lport) if str(lport).isdigit() else 0,
                foreign_addr=foreign_addr,
                foreign_port=foreign_port,
                state=state,
                pid=self._col_int(data, row, "PID") or self._col_int(data, row, "Pid"),
                owner=self._col(data, row, "Owner"),
                created=self._col(data, row, "Created"),
                suspicious=susp,
                susp_reason=reason,
            ))
        return results

    def cmdline(self, pid_filter: set[int] | None = None) -> list[CmdlineEntry]:
        data = self._run("windows.cmdline")
        results = []
        for row in (data.get("rows") or []):
            pid = self._col_int(data, row, "PID") or self._col_int(data, row, "Pid")
            if pid_filter and pid not in pid_filter:
                continue
            results.append(CmdlineEntry(
                pid=pid,
                name=self._col(data, row, "Process") or self._col(data, row, "ImageFileName"),
                args=self._col(data, row, "Args"),
            ))
        return results

    def handles(self, pid_filter: set[int] | None = None,
                type_filter: tuple[str, ...] = ("Mutant", "File", "Key")) -> list[HandleEntry]:
        """뮤텍스(Mutant), 파일, 레지스트리 키 핸들 — 악성코드 패밀리 식별에 핵심."""
        data = self._run("windows.handles")
        results = []
        for row in (data.get("rows") or []):
            pid = self._col_int(data, row, "PID") or self._col_int(data, row, "Pid")
            if pid_filter and pid not in pid_filter:
                continue
            htype = self._col(data, row, "Type")
            if type_filter and htype not in type_filter:
                continue
            hname = self._col(data, row, "Name")
            if not hname or hname in ("-", "N/A", ""):
                continue
            entropy, family, suspicious = _analyze_mutant(hname) if htype == "Mutant" else (0.0, "", False)
            results.append(HandleEntry(
                pid=pid,
                name=self._col(data, row, "Process") or self._col(data, row, "ImageFileName"),
                htype=htype,
                hname=hname,
                entropy=round(entropy, 3),
                family=family,
                suspicious=suspicious,
            ))
        return results

    def psxview(self) -> list[PsxviewEntry]:
        """windows.psxview — EPROCESS 목록 교차 비교로 은닉 프로세스 탐지."""
        data = self._run("windows.psxview")
        results: list[PsxviewEntry] = []

        def _b(val: str) -> bool:
            return str(val).strip().lower() in ("true", "1", "yes")

        for row in (data.get("rows") or []):
            pid  = self._col_int(data, row, "PID") or self._col_int(data, row, "Pid")
            name = (self._col(data, row, "ImageFileName")
                    or self._col(data, row, "Name"))
            offset = (self._col(data, row, "Offset(P)")
                      or self._col(data, row, "Offset"))
            # 컬럼 이름은 버전마다 "KO Pslist" 또는 "PsActiveProcessLinks" 등 다름
            pslist = _b(self._col(data, row, "KO Pslist")
                        or self._col(data, row, "PsActiveProcessLinks")
                        or self._col(data, row, "Pslist"))
            psscan = _b(self._col(data, row, "KO Psscan")
                        or self._col(data, row, "Psscan"))
            csrss  = _b(self._col(data, row, "KO Csrss")
                        or self._col(data, row, "Csrss"))
            peb    = _b(self._col(data, row, "KO Session")
                        or self._col(data, row, "Session")
                        or self._col(data, row, "PEB"))
            # psscan에서 발견됐지만 pslist에 없음 = 가장 의심스러운 루트킷 패턴
            hidden = psscan and not pslist
            results.append(PsxviewEntry(
                pid=pid, name=name, offset=offset,
                pslist=pslist, psscan=psscan, csrss=csrss, peb=peb,
                hidden=hidden,
            ))
        return results

    def connscan(self) -> list[ConnscanEntry]:
        """windows.connscan — 종료된 TCP 소켓 포함 연결 이력 스캔."""
        data = self._run("windows.connscan")
        results: list[ConnscanEntry] = []
        for row in (data.get("rows") or []):
            lport = self._col(data, row, "LocalPort")
            fport = self._col(data, row, "ForeignPort")
            results.append(ConnscanEntry(
                proto       =self._col(data, row, "Proto") or "TCP",
                local_addr  =self._col(data, row, "LocalAddr"),
                local_port  =int(lport) if str(lport).isdigit() else 0,
                foreign_addr=self._col(data, row, "ForeignAddr"),
                foreign_port=int(fport) if str(fport).isdigit() else 0,
                state       =self._col(data, row, "State"),
                pid         =self._col_int(data, row, "PID") or self._col_int(data, row, "Pid"),
                owner       =self._col(data, row, "Owner"),
                created     =self._col(data, row, "Created"),
            ))
        return results

    def procdump(
        self,
        pid_reasons: dict[int, str],
        pid_name_map: dict[int, str],
        output_dir: Path,
    ) -> list[ProcDumpEntry]:
        """의심 PID의 PE를 메모리에서 추출 (windows.procdump)."""
        results: list[ProcDumpEntry] = []
        if not pid_reasons:
            return results
        output_dir.mkdir(parents=True, exist_ok=True)
        for pid, reason in pid_reasons.items():
            before = {p.name for p in output_dir.glob("*.dmp")}
            cmd = self.vol_cmd + [
                "-f", str(self.dump_path),
                "-r", "json",
                "-o", str(output_dir),
            ]
            if self.symbols_path:
                cmd += ["-s", str(self.symbols_path)]
            cmd += ["windows.procdump", "--pid", str(pid)]
            try:
                subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            except Exception:
                continue
            for dp in sorted(output_dir.glob("*.dmp")):
                if dp.name not in before:
                    results.append(ProcDumpEntry(
                        pid=pid,
                        name=pid_name_map.get(pid, f"pid_{pid}"),
                        dump_path=str(dp),
                        size=dp.stat().st_size,
                        reason=reason,
                    ))
        return results

    def warmup(self) -> tuple[bool, str]:
        """
        windows.info 실행으로 심볼 자동 다운로드 트리거 및 OS 정보 추출.

        Volatility3는 첫 실행 시 메모리 덤프에 맞는 kernel PDB 심볼을
        인터넷에서 자동 다운로드한다. 이 메서드를 병렬 플러그인 실행 전에
        먼저 호출해 심볼을 캐시에 확보한다.

        Returns: (success, os_info_or_error_str)
        """
        try:
            data = self._run("windows.info")
            cols = data.get("columns", [])
            rows = data.get("rows") or []
            key_i = val_i = -1
            for i, c in enumerate(cols):
                cl = c.lower()
                if cl in ("key", "variable"):
                    key_i = i
                elif cl == "value":
                    val_i = i
            kv: dict[str, str] = {}
            if key_i >= 0 and val_i >= 0:
                for r in rows:
                    if len(r) > max(key_i, val_i):
                        kv[str(r[key_i])] = str(r[val_i])
            major   = kv.get("NtMajorVersion", "")
            minor   = kv.get("NtMinorVersion", "")
            build   = kv.get("NtBuildLab", kv.get("NtBuildLabEx", ""))
            product = kv.get("NtProductType", "")
            os_str  = (
                f"Windows {major}.{minor} build {build} ({product})"
                if major else "(버전 미확인)"
            )
            return True, os_str
        except RuntimeError as e:
            return False, str(e)

    def dlllist(self, pid_filter: set[int] | None = None) -> list[DllEntry]:
        data = self._run("windows.dlllist")
        results = []
        seen: set[tuple] = set()
        for row in (data.get("rows") or []):
            pid = self._col_int(data, row, "PID") or self._col_int(data, row, "Pid")
            if pid_filter and pid not in pid_filter:
                continue
            dll_name = self._col(data, row, "Name")
            key = (pid, dll_name)
            if key in seen:
                continue
            seen.add(key)
            results.append(DllEntry(
                pid=pid,
                name=self._col(data, row, "Process"),
                base=self._col(data, row, "Base"),
                dll_name=dll_name,
                path=self._col(data, row, "Path"),
            ))
        return results


# ── 통합 실행 함수 ────────────────────────────────────────────────────────

_SUSPICIOUS_PROTECTIONS = frozenset({
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_READ_WRITE",
    "PAGE_EXECUTE_WRITECOPY",
})


def run_memory_forensics(
    output_dir: Path,
    sample_pids: set[int] | None = None,
    winpmem_path: Optional[Path] = None,
    vol_path: Optional[Path] = None,
    dump_timeout: int = 600,
    plugin_timeout: int = 300,
    on_status: Optional[object] = None,
    skip_dump: bool = False,
    existing_dump: Optional[Path] = None,
    symbols_path: Optional[str] = None,
) -> MemForensicsResult:
    """
    메모리 덤프 획득 + Volatility3 분석 통합 실행.

    Parameters
    ----------
    sample_pids:    분석 대상 PID 집합 (None이면 전체 결과 반환)
    skip_dump:      True면 덤프 없이 existing_dump 사용
    existing_dump:  이미 있는 덤프 파일 경로
    symbols_path:   Volatility3 심볼 디렉터리 (None이면 자동 탐색)
    """
    def _st(msg: str) -> None:
        if on_status:
            on_status(msg)

    result = MemForensicsResult()

    # ── Volatility3 탐색 ─────────────────────────────────────────────
    vol_cmd_info = None
    if vol_path and Path(vol_path).is_file():
        vol_cmd_info = ([sys.executable, str(vol_path)], "script")
    else:
        vol_cmd_info = find_volatility3()

    if not vol_cmd_info:
        result.error = "Volatility3 미설치 (vol3, vol.py 를 찾을 수 없음)"
        return result

    vol_cmd, vol_kind = vol_cmd_info
    _st(f"      Volatility3 발견: {' '.join(vol_cmd[:2])} ({vol_kind})")

    # ── 메모리 덤프 ──────────────────────────────────────────────────
    if skip_dump and existing_dump and Path(existing_dump).exists():
        dump_path = Path(existing_dump)
        _st(f"      기존 덤프 사용: {dump_path.name} "
            f"({dump_path.stat().st_size / 1e9:.1f} GB)")
    else:
        dump_path = output_dir / "memory.raw"
        _st("[메모리] 물리 메모리 덤프 획득 중 (수분 소요)...")
        ok, elapsed, err, dump_path = acquire_memory(
            dump_path,
            tool_path=winpmem_path or find_winpmem(),
            timeout=dump_timeout,
            on_status=on_status,
        )
        result.dump_elapsed = elapsed
        if not ok:
            result.error = err
            return result
        _st(f"      덤프 완료: {elapsed}s  "
            f"({dump_path.stat().st_size / 1e9:.1f} GB)")

    result.dump_path = dump_path
    try:
        result.dump_size_gb = round(dump_path.stat().st_size / 1e9, 2)
    except Exception:
        pass

    # ── 심볼 경로 결정 ────────────────────────────────────────────────
    # 명시적 지정 > 로컬 자동 탐색 > None (Volatility3 기본값 / 인터넷 다운로드)
    _sym_path: Optional[Path] = None
    if symbols_path:
        _sym_path = Path(symbols_path)
        _st(f"      심볼 경로 (지정): {_sym_path}")
    else:
        _sym_path = find_local_symbols(vol_cmd)
        if _sym_path:
            _st(f"      심볼 경로 (자동): {_sym_path}")

    # ── Volatility3 플러그인 병렬 실행 ───────────────────────────────
    runner = VolatilityRunner(
        dump_path, vol_cmd,
        timeout_per_plugin=plugin_timeout,
        symbols_path=_sym_path,
    )

    # 심볼 사전 확인 — 첫 실행 시 kernel PDB를 자동 다운로드.
    # 다운로드 시간을 고려해 plugin_timeout보다 긴 타임아웃 사용.
    # 병렬 플러그인 실행 전에 완료해야 심볼 다운로드 경합이 없다.
    _warmup_timeout = max(plugin_timeout, dump_timeout, 600)
    runner.timeout = _warmup_timeout
    _st(f"[메모리] 심볼 파일 확인 중 (자동 다운로드 포함, 최대 {_warmup_timeout}s)...")
    _sym_ok, _sym_info = runner.warmup()
    runner.timeout = plugin_timeout   # 이후 플러그인은 원래 타임아웃 복원

    if _sym_ok:
        _st(f"      OS: {_sym_info}")
    else:
        # 실제 원인을 보여줘서 진단 가능하게 함
        _st(f"      [경고] windows.info 실패: {_sym_info[:300]}")
        result.plugin_errors["windows.info"] = _sym_info

        # 심볼 파일 완전 부재가 확실한 경우만 조기 종료
        # ("automagic" 등 정상 로그 키워드로 오탐하지 않음)
        _hard_fail = (
            "unsatisfied requirement" in _sym_info.lower()
            or "requirements are not satisfied" in _sym_info.lower()
            or "could not find a pdb" in _sym_info.lower()
            or "no suitable address space mapping" in _sym_info.lower()
        )
        if _hard_fail and not _sym_path:
            _install_hint = str(
                Path(vol_cmd[-1]).parent / "volatility3" / "symbols"
                if vol_cmd and Path(vol_cmd[-1]).suffix == ".py"
                else Path(r"C:\Tools\volatility3\volatility3\symbols")
            )
            result.error = (
                "Volatility3 심볼 파일 없음\n"
                "해결 방법:\n"
                "  [온라인] 인터넷이 되는 환경에서 한 번 실행하면 자동 다운로드\n"
                "  [오프라인] Volatility Foundation 사이트에서 windows.zip 다운로드 후\n"
                f"  → 압축 해제한 windows/ 폴더를 {_install_hint}\\windows\\ 에 복사\n"
                "  또는: python analyzer.py ... --vol-symbols <압축해제경로>"
            )
            _st(f"      [오류] 심볼 파일 없음 (확정) — 플러그인 실행 건너뜀")
            return result
        # 불확실한 오류(타임아웃, 기타) → 플러그인 계속 시도
        _st("      플러그인 실행을 계속 시도합니다...")

    _st("[메모리] Volatility3 플러그인 실행 중 (병렬)...")
    t_vol = time.monotonic()

    plugins = {
        "malfind":  lambda: runner.malfind(pid_filter=sample_pids),
        "pstree":   lambda: runner.pstree(),
        "netscan":  lambda: runner.netscan(),
        "connscan": lambda: runner.connscan(),
        "psxview":  lambda: runner.psxview(),
        "cmdline":  lambda: runner.cmdline(pid_filter=sample_pids),
        "handles":  lambda: runner.handles(pid_filter=sample_pids),
        "dlllist":  lambda: runner.dlllist(pid_filter=sample_pids),
    }

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in plugins.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                data = fut.result()
                setattr(result, name, data)
                _st(f"      {name}: {len(data)}건")
            except Exception as e:
                result.plugin_errors[name] = str(e)
                _st(f"      {name}: 오류 — {e}")

    result.vol_elapsed = round(time.monotonic() - t_vol, 1)
    _st(f"      Volatility3 완료: {result.vol_elapsed}s")

    # ── 의심 프로세스 PE 추출 ─────────────────────────────────────────
    # malfind RWX 영역 + psxview 은닉 프로세스를 대상으로 windows.procdump 실행
    pid_reasons: dict[int, str] = {}
    for e in result.malfind:
        if e.protection in _SUSPICIOUS_PROTECTIONS and e.pid:
            pid_reasons.setdefault(e.pid, f"malfind:{e.protection}")
    for e in result.psxview:
        if e.hidden and e.pid and e.pid not in pid_reasons:
            pid_reasons[e.pid] = "psxview:hidden"

    if pid_reasons:
        pid_name_map = {e.pid: e.name for e in result.pstree}
        dumps_dir = output_dir / "procdumps"
        _st(f"[메모리] 의심 프로세스 PE 추출 중 ({len(pid_reasons)}개 PID)...")
        result.procdumps = runner.procdump(pid_reasons, pid_name_map, dumps_dir)
        _st(f"      추출 완료: {len(result.procdumps)}개 파일")

    return result


# ── 직렬화 헬퍼 ──────────────────────────────────────────────────────────

def memforensics_to_dict(r: MemForensicsResult) -> dict:
    """JSON 직렬화 가능한 dict 변환."""
    return {
        "dump_path":    str(r.dump_path) if r.dump_path else "",
        "dump_size_gb": r.dump_size_gb,
        "dump_elapsed": r.dump_elapsed,
        "vol_elapsed":  r.vol_elapsed,
        "error":        r.error,
        "plugin_errors": r.plugin_errors,
        "malfind": [
            {"pid": e.pid, "process": e.process, "start_vpn": e.start_vpn,
             "end_vpn": e.end_vpn, "protection": e.protection,
             "private_memory": e.private_memory,
             "hexdump": e.hexdump, "disasm": e.disasm,
             "shellcode_type": e.shellcode_type}
            for e in r.malfind
        ],
        "pstree": [
            {"pid": e.pid, "ppid": e.ppid, "name": e.name,
             "offset": e.offset, "threads": e.threads,
             "create_time": e.create_time, "cmd": e.cmd, "path": e.path}
            for e in r.pstree
        ],
        "netscan": [
            {"proto": e.proto, "local": f"{e.local_addr}:{e.local_port}",
             "foreign": f"{e.foreign_addr}:{e.foreign_port}",
             "state": e.state, "pid": e.pid, "owner": e.owner,
             "created": e.created,
             "suspicious": e.suspicious, "susp_reason": e.susp_reason}
            for e in r.netscan
        ],
        "cmdline": [
            {"pid": e.pid, "name": e.name, "args": e.args}
            for e in r.cmdline
        ],
        "handles": [
            {"pid": e.pid, "name": e.name, "type": e.htype, "handle_name": e.hname,
             "entropy": e.entropy, "family": e.family, "suspicious": e.suspicious}
            for e in r.handles
        ],
        "dlllist": [
            {"pid": e.pid, "name": e.name, "base": e.base,
             "dll": e.dll_name, "path": e.path}
            for e in r.dlllist
        ],
        "psxview": [
            {"pid": e.pid, "name": e.name, "offset": e.offset,
             "pslist": e.pslist, "psscan": e.psscan, "csrss": e.csrss,
             "peb": e.peb, "hidden": e.hidden}
            for e in r.psxview
        ],
        "connscan": [
            {"proto": e.proto, "local": f"{e.local_addr}:{e.local_port}",
             "foreign": f"{e.foreign_addr}:{e.foreign_port}",
             "state": e.state, "pid": e.pid, "owner": e.owner,
             "created": e.created}
            for e in r.connscan
        ],
        "procdumps": [
            {"pid": e.pid, "name": e.name, "dump_path": e.dump_path,
             "size": e.size, "reason": e.reason}
            for e in r.procdumps
        ],
    }
