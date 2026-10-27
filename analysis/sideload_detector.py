"""
sideload_detector.py — DLL 사이드로딩 / 검색 순서 하이재킹 탐지

전형적인 사이드로딩 체인:

    1. 드로퍼가 비표준 디렉터리(예: C:\\ProgramData\\PushNotifyBroker\\)에
       실행 파일 + DLL + 페이로드 파일을 함께 떨군다.
    2. 그 디렉터리의 실행 파일이 실행된다 (정상 서명 바이너리인 경우가 많음).
    3. 실행 파일이 **같은 디렉터리의 DLL** 을 로드한다.
       Windows 의 DLL 검색 순서상 실행 파일 디렉터리가 System32 보다 먼저다.
    4. 로드된 DLL 이 옆에 있는 데이터 파일(.pmt/.dat/.bin 등)을 읽어
       실제 페이로드를 복호화하고 C2 통신을 수행한다.

ProcMon 의 ``Load Image`` 이벤트에 이 관계가 전부 남는다. 판정 근거는
"프로세스가 자기 실행 경로와 같은 비시스템 디렉터리에서 DLL 을 로드했고,
그 DLL 이 이번 분석 중에 생성되었다" 이다.

EXE 가 정상 서명 바이너리라 개별 탐지를 피해도, **드롭 → 동일 디렉터리
로드** 라는 관계 자체는 숨길 수 없다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from parsers.procmon_csv import ProcMonEvent, EventCategory


# 정상 DLL 로드가 일어나는 시스템 경로 — 사이드로딩 후보에서 제외
_SYSTEM_DIRS: tuple[str, ...] = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\sysnative",
    r"c:\windows\winsxs",
    r"c:\windows\assembly",
    r"c:\windows\microsoft.net",
    r"c:\windows\servicing",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)

# 분석 도구 자신의 DLL 로드는 무시
_TOOL_FRAGMENTS: tuple[str, ...] = (
    "procmon", "pe-sieve", "pe_sieve", "hollows_hunter", "hollows-hunter",
    "systeminformer", "processhacker", "tshark", "dumpcap", "wireshark",
    "winpmem", "volatility", "python",
)

# 페이로드/설정으로 자주 쓰이는 비실행 확장자
_PAYLOAD_EXTS: frozenset[str] = frozenset({
    ".pmt", ".dat", ".bin", ".tmp", ".log", ".cfg", ".ini", ".db",
    ".cache", ".enc", ".pak", ".res", ".blob",
})

_CREATE_OPS: frozenset[str] = frozenset({"WriteFile", "CreateFile"})


@dataclass
class SideloadFinding:
    """사이드로딩 의심 한 건."""

    loader_name:  str = ""          # 로더 프로세스명
    loader_pid:   int = 0
    loader_exe:   str = ""          # 로더 실행 파일 전체 경로
    dll_path:     str = ""          # 사이드로드된 DLL
    directory:    str = ""          # 공통 디렉터리
    dll_dropped:  bool = False      # DLL 이 이번 분석 중 생성됨
    exe_dropped:  bool = False      # EXE 가 이번 분석 중 생성됨
    same_dir:     bool = False      # EXE 와 DLL 이 같은 디렉터리
    in_lineage:   bool = False      # 로더가 샘플 계보
    companions:   list = field(default_factory=list)  # 같은 디렉터리의 다른 드롭 파일
    confidence:   str = "MEDIUM"    # HIGH / MEDIUM

    def summary(self) -> str:
        comp = f", 동반 파일 {len(self.companions)}개" if self.companions else ""
        return (
            f"{self.loader_name}(PID {self.loader_pid})가 "
            f"{self.dll_path} 로드{comp}"
        )


def _norm(path: str) -> str:
    return (path or "").strip().lower().replace("/", "\\")


def _is_system_dir(path_lower: str) -> bool:
    return any(path_lower.startswith(d) for d in _SYSTEM_DIRS)


def _is_tool(text: str) -> bool:
    t = _norm(text)
    return any(f in t for f in _TOOL_FRAGMENTS)


def detect_sideloading(
    events: list,
    lineage_pids: set | None = None,
    new_processes: list | None = None,
) -> list:
    """ProcMon 이벤트에서 DLL 사이드로딩 의심 체인을 찾는다.

    Parameters
    ----------
    events:
        ProcMon 이벤트 목록. ``Load Image`` 가 포함되어야 하므로
        filter_events() 이전/이후 모두 가능하나, 계보 필터가 걸린
        filtered_events 를 넣으면 노이즈가 적다.
    lineage_pids:
        샘플 계보 PID 집합. 계보 여부를 표시하는 데만 쓰며, 계보 밖
        로더도 버리지 않는다(주입/스케줄 실행으로 계보가 끊길 수 있음).
    new_processes:
        ProcessSnapshot 목록 — PID → 실행 파일 경로 역색인용.

    Returns
    -------
    list[SideloadFinding]
        신뢰도 높은 순으로 정렬된 탐지 결과.
    """
    lineage_pids = set(lineage_pids or ())
    events = events or []

    # ── 1. 이번 분석 중 생성된 파일 수집 ─────────────────────────────
    created: dict = {}          # 정규화 경로 → 생성 PID
    for ev in events:
        try:
            if ev.category != EventCategory.FILE:
                continue
            if ev.operation not in _CREATE_OPS:
                continue
            if getattr(ev, "result", "") != "SUCCESS":
                continue
            p = _norm(ev.path)
            if p and p not in created:
                created[p] = getattr(ev, "pid", 0)
        except Exception:
            continue

    # ── 2. PID → 실행 파일 경로 ──────────────────────────────────────
    pid_exe: dict = {}
    for p in (new_processes or []):
        try:
            pid_exe[getattr(p, "pid", 0)] = getattr(p, "exe", "") or ""
        except Exception:
            continue

    # ── 3. 디렉터리별 생성 파일 색인 (동반 파일 찾기용) ──────────────
    dir_files: dict = {}
    for path in created:
        d = os.path.dirname(path)
        dir_files.setdefault(d, []).append(path)

    # ── 4. Load Image 이벤트 검사 ────────────────────────────────────
    findings: list = []
    seen: set = set()

    for ev in events:
        try:
            if getattr(ev, "operation", "") != "Load Image":
                continue
            dll = _norm(ev.path)
            if not dll.endswith(".dll"):
                continue
            if _is_system_dir(dll) or _is_tool(dll) or _is_tool(getattr(ev, "process", "")):
                continue

            pid       = getattr(ev, "pid", 0)
            loader_ex = _norm(pid_exe.get(pid, ""))
            dll_dir   = os.path.dirname(dll)
            exe_dir   = os.path.dirname(loader_ex) if loader_ex else ""

            dll_dropped = dll in created
            exe_dropped = bool(loader_ex) and loader_ex in created
            same_dir    = bool(exe_dir) and exe_dir == dll_dir

            # 판정: 비시스템 경로에서 DLL 을 로드했고,
            #       그 DLL 이 이번 분석 중 생성됐거나 EXE 와 같은 디렉터리
            if not (dll_dropped or same_dir):
                continue

            key = (pid, dll)
            if key in seen:
                continue
            seen.add(key)

            companions = [
                f for f in dir_files.get(dll_dir, [])
                if f != dll and f != loader_ex
            ]
            # 페이로드로 보이는 비실행 파일을 앞으로
            companions.sort(
                key=lambda f: (0 if os.path.splitext(f)[1] in _PAYLOAD_EXTS else 1, f)
            )

            # 신뢰도: 드롭된 DLL 을 같은 디렉터리에서 로드 = HIGH
            conf = "HIGH" if (dll_dropped and same_dir) else "MEDIUM"

            findings.append(SideloadFinding(
                loader_name = getattr(ev, "process", "") or "?",
                loader_pid  = pid,
                loader_exe  = pid_exe.get(pid, "") or "",
                dll_path    = ev.path,
                directory   = dll_dir,
                dll_dropped = dll_dropped,
                exe_dropped = exe_dropped,
                same_dir    = same_dir,
                in_lineage  = pid in lineage_pids,
                companions  = companions[:8],
                confidence  = conf,
            ))
        except Exception:
            continue

    findings.sort(key=lambda f: (
        0 if f.confidence == "HIGH" else 1,
        0 if f.in_lineage else 1,
        f.loader_name.lower(),
    ))
    return findings


def sideload_to_dict(f: SideloadFinding) -> dict:
    return {
        "loader_name": f.loader_name,
        "loader_pid":  f.loader_pid,
        "loader_exe":  f.loader_exe,
        "dll_path":    f.dll_path,
        "directory":   f.directory,
        "dll_dropped": f.dll_dropped,
        "exe_dropped": f.exe_dropped,
        "same_dir":    f.same_dir,
        "in_lineage":  f.in_lineage,
        "companions":  f.companions,
        "confidence":  f.confidence,
    }


def add_sideload_techniques(behavior_report, findings: list) -> int:
    """탐지 결과를 MITRE T1574.002 로 behavior_report 에 병합한다.

    Returns 추가/보강된 근거 수.
    """
    if not behavior_report or not findings:
        return 0
    from analysis.behavior_classifier import MitreTechnique

    techs = getattr(behavior_report, "techniques", None)
    if techs is None:
        return 0

    existing = {getattr(t, "technique_id", ""): t for t in techs}
    added = 0
    for f in findings:
        ev = (
            f"[{f.loader_name}] {f.dll_path} 사이드로드 "
            f"(로더 {f.loader_exe or '경로불명'}"
            + (", DLL 분석 중 드롭됨" if f.dll_dropped else "")
            + (f", 동반 파일: {', '.join(os.path.basename(c) for c in f.companions[:3])}"
               if f.companions else "")
            + f", 신뢰도 {f.confidence})"
        )
        t = existing.get("T1574.002")
        if t is None:
            t = MitreTechnique(
                technique_id   = "T1574.002",
                technique_name = "DLL Side-Loading",
                tactic         = "Defense Evasion",
                evidence       = [],
                reference      = "https://attack.mitre.org/techniques/T1574/002/",
                sources        = ["사이드로딩탐지"],
            )
            techs.append(t)
            existing["T1574.002"] = t
        if ev not in t.evidence:
            t.evidence.append(ev)
            added += 1
        if "사이드로딩탐지" not in (t.sources or []):
            t.sources.append("사이드로딩탐지")
    return added
