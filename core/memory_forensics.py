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

import json
import os
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

_VOL3_SCRIPT_NAMES = ("vol3", "vol3.exe", "vol.py")


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

    # 3. Python 모듈로 설치된 경우
    try:
        r = subprocess.run(
            [sys.executable, "-m", "volatility3", "--version"],
            capture_output=True, timeout=10,
        )
        if r.returncode == 0:
            return ([sys.executable, "-m", "volatility3"], "module")
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


@dataclass
class CmdlineEntry:
    pid:  int
    name: str
    args: str


@dataclass
class HandleEntry:
    pid:    int
    name:   str
    htype:  str    # Mutant, File, Key 등
    hname:  str    # 핸들 이름


@dataclass
class DllEntry:
    pid:  int
    name: str
    base: str
    dll_name: str
    path: str


@dataclass
class MemForensicsResult:
    dump_path:   Optional[Path]       = None
    dump_size_gb: float               = 0.0
    dump_elapsed: float               = 0.0
    vol_elapsed:  float               = 0.0
    malfind:     list[MalfindEntry]  = field(default_factory=list)
    pstree:      list[PsTreeEntry]   = field(default_factory=list)
    netscan:     list[NetScanEntry]  = field(default_factory=list)
    cmdline:     list[CmdlineEntry]  = field(default_factory=list)
    handles:     list[HandleEntry]   = field(default_factory=list)
    dlllist:     list[DllEntry]      = field(default_factory=list)
    plugin_errors: dict[str, str]    = field(default_factory=dict)
    error:       str                 = ""


# ── 메모리 획득 ───────────────────────────────────────────────────────────

def acquire_memory(
    output_path: Path,
    tool_path: Optional[Path] = None,
    timeout: int = 600,
    on_status: Optional[object] = None,
) -> tuple[bool, float, str]:
    """
    물리 메모리 덤프 획득.

    Returns: (success, elapsed_sec, error_msg)
    """
    tool = tool_path or find_winpmem()
    if not tool:
        return False, 0.0, "winpmem / DumpIt 미설치"

    tool_name = tool.name.lower()
    t0 = time.monotonic()

    if "dumpit" in tool_name:
        cmd = [str(tool), f"/output", str(output_path), "/q", "/y"]
    else:
        # winpmem
        cmd = [str(tool), str(output_path)]

    try:
        if on_status:
            on_status(f"      메모리 덤프 시작 ({tool.name}) → {output_path.name}")
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            text=True, errors="replace",
        )
        elapsed = round(time.monotonic() - t0, 1)
        if not output_path.exists() or output_path.stat().st_size < 1_000_000:
            err = (proc.stderr or proc.stdout or "출력 파일 없음")[-500:]
            return False, elapsed, f"덤프 실패 (exit={proc.returncode}): {err}"
        return True, elapsed, ""
    except subprocess.TimeoutExpired:
        return False, round(time.monotonic() - t0, 1), f"덤프 시간 초과 ({timeout}s)"
    except Exception as e:
        return False, round(time.monotonic() - t0, 1), str(e)


# ── Volatility3 플러그인 실행 ─────────────────────────────────────────────

class VolatilityRunner:
    def __init__(
        self,
        dump_path: Path,
        vol_cmd: list[str],
        timeout_per_plugin: int = 300,
    ) -> None:
        self.dump_path = dump_path
        self.vol_cmd   = vol_cmd
        self.timeout   = timeout_per_plugin

    def _run(self, plugin: str, extra: list[str] | None = None) -> dict:
        """플러그인 실행 → JSON dict 반환. 실패 시 RuntimeError 발생."""
        cmd = self.vol_cmd + [
            "-f", str(self.dump_path),
            "-r", "json",   # Volatility3 렌더러 플래그 (--output은 출력 파일 경로로 해석됨)
            plugin,
        ]
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
            stderr_tail = (r.stderr or "")[-600:].strip()
            _sym_kws = ("symbol", "could not find", "isf", "unsatisfied", "automagic", "no module")
            if stderr_tail and any(k in stderr_tail.lower() for k in _sym_kws):
                raise RuntimeError(
                    f"{plugin}: 심볼 파일 없음 — "
                    "`vol -f memory.raw windows.info` 로 심볼 자동 다운로드\n"
                    + stderr_tail[-300:]
                )
            raise RuntimeError(
                f"{plugin}: 출력 없음"
                + (f"\n[stderr] {stderr_tail}" if stderr_tail else "")
            )

        # 첫 번째 '{' 또는 '[' 위치 찾기 (앞에 로그 라인이 섞일 수 있음)
        for i, ch in enumerate(out):
            if ch in ('{', '['):
                try:
                    return json.loads(out[i:])
                except json.JSONDecodeError as e:
                    raise RuntimeError(f"{plugin}: JSON 파싱 오류 — {e}")

        # JSON 없음 — stderr에서 실제 원인 추출
        stderr_tail = (r.stderr or "")[-600:].strip()
        _sym_kws = ("symbol", "could not find", "isf", "unsatisfied", "automagic", "no module")
        if stderr_tail and any(k in stderr_tail.lower() for k in _sym_kws):
            raise RuntimeError(
                f"{plugin}: 심볼 파일 없음 — "
                "`vol -f memory.raw windows.info` 로 심볼 자동 다운로드\n"
                + stderr_tail[-300:]
            )
        raise RuntimeError(
            f"{plugin}: stdout에 JSON 없음 ({out[:120]})"
            + (f"\n[stderr] {stderr_tail[:300]}" if stderr_tail else "")
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
            results.append(MalfindEntry(
                pid=pid,
                process=self._col(data, row, "Process") or self._col(data, row, "ImageFileName"),
                start_vpn=self._col(data, row, "Start VPN") or self._col(data, row, "VPN"),
                end_vpn=self._col(data, row, "End VPN"),
                protection=self._col(data, row, "Protection"),
                private_memory=str(self._col(data, row, "PrivateMemory")).lower() in ("true", "1"),
                hexdump=self._col(data, row, "Hexdump")[:64],
                disasm=self._col(data, row, "Disasm")[:256],
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
            results.append(NetScanEntry(
                proto=self._col(data, row, "Proto"),
                local_addr=self._col(data, row, "LocalAddr"),
                local_port=int(lport) if str(lport).isdigit() else 0,
                foreign_addr=self._col(data, row, "ForeignAddr"),
                foreign_port=int(fport) if str(fport).isdigit() else 0,
                state=self._col(data, row, "State"),
                pid=self._col_int(data, row, "PID") or self._col_int(data, row, "Pid"),
                owner=self._col(data, row, "Owner"),
                created=self._col(data, row, "Created"),
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
            results.append(HandleEntry(
                pid=pid,
                name=self._col(data, row, "Process") or self._col(data, row, "ImageFileName"),
                htype=htype,
                hname=hname,
            ))
        return results

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
) -> MemForensicsResult:
    """
    메모리 덤프 획득 + Volatility3 분석 통합 실행.

    Parameters
    ----------
    sample_pids:    분석 대상 PID 집합 (None이면 전체 결과 반환)
    skip_dump:      True면 덤프 없이 existing_dump 사용
    existing_dump:  이미 있는 덤프 파일 경로
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
        ok, elapsed, err = acquire_memory(
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

    # ── Volatility3 플러그인 병렬 실행 ───────────────────────────────
    runner = VolatilityRunner(dump_path, vol_cmd, timeout_per_plugin=plugin_timeout)

    _st("[메모리] Volatility3 플러그인 실행 중 (병렬)...")
    t_vol = time.monotonic()

    plugins = {
        "malfind":  lambda: runner.malfind(pid_filter=sample_pids),
        "pstree":   lambda: runner.pstree(),
        "netscan":  lambda: runner.netscan(),
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
             "hexdump": e.hexdump, "disasm": e.disasm}
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
             "created": e.created}
            for e in r.netscan
        ],
        "cmdline": [
            {"pid": e.pid, "name": e.name, "args": e.args}
            for e in r.cmdline
        ],
        "handles": [
            {"pid": e.pid, "name": e.name, "type": e.htype, "handle_name": e.hname}
            for e in r.handles
        ],
        "dlllist": [
            {"pid": e.pid, "name": e.name, "base": e.base,
             "dll": e.dll_name, "path": e.path}
            for e in r.dlllist
        ],
    }
