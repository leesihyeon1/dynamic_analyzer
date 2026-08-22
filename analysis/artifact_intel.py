"""
artifact_intel.py — 드롭 아티팩트에서 파생 사실 도출

AI 는 원시 파일 목록을 봐도 "이건 NSIS 인스톨러다" 를 알아채지 못한다.
알아채라고 요구할 일도 아니다 — 결정론적으로 판정 가능한 사실은 코드가
만들어서 확정 근거로 넘겨주는 편이 정확하고 재현 가능하다.

두 가지를 도출한다.

1. **패커 / 인스톨러 식별** (:func:`detect_packers`)
   드롭 파일 이름 패턴으로 NSIS·Inno Setup·AutoIt·PyInstaller 등을 식별한다.
   예: ``ns*.tmp\\nsDialogs.dll`` + ``System.dll`` → NSIS 확정.
   "추정 악성코드 패밀리" 대신 "NSIS 로 패킹된 드로퍼" 라고 쓸 수 있게 된다.

2. **정상 구성요소 사칭 탐지** (:func:`detect_masquerading`)
   두 갈래로 나눈다.
   - 실제 Windows 시스템 바이너리 이름을 비표준 경로에서 사용 → T1036.005
   - 실존하지 않지만 그럴듯한 MS 풍 이름 (TelemetryDispatcher, PushNotifyBroker)
     → T1036. 후자는 휴리스틱이므로 신뢰도를 낮게 잡는다.
"""
from __future__ import annotations

import os
import re


# ── 1. 패커 / 인스톨러 지문 ──────────────────────────────────────────────────
# (표시명, 필수 패턴 리스트, 보조 패턴 리스트, 설명)
# 필수 패턴이 모두 맞으면 HIGH, 일부만 맞고 보조가 있으면 MEDIUM.

_PACKER_SIGNATURES: tuple = (
    (
        "NSIS (Nullsoft Scriptable Install System)",
        [r"\\ns[a-z]?[0-9a-f]{3,}\.tmp\\"],
        [r"nsdialogs\.dll$", r"\\system\.dll$", r"nsexec\.dll$",
         r"installoptions\.dll$", r"\\banner\.dll$", r"\\inetc\.dll$"],
        "임시 디렉터리에 플러그인 DLL 을 풀고 실행하는 구조. 드로퍼로 흔히 쓰임.",
    ),
    (
        "Inno Setup",
        [r"\\is-[0-9a-z]{8}\.tmp\\"],
        [r"_isetup\\", r"unins\d*\.(exe|dat)$", r"_iu[0-9a-z]+\.tmp$"],
        "Delphi 기반 인스톨러. 언인스톨러 아티팩트를 남김.",
    ),
    (
        "AutoIt",
        [r"\\aut[0-9a-f]{3,}\.tmp"],
        [r"autoit3\.exe$", r"\.au3$"],
        "스크립트 컴파일 실행 파일. 스크립트 malware 에서 자주 사용.",
    ),
    (
        "PyInstaller",
        [r"\\_mei\d+\\"],
        [r"python\d*\.dll$", r"base_library\.zip$", r"\\vcruntime\d+\.dll$"],
        "Python 스크립트를 단일 EXE 로 묶은 형태. 임시 디렉터리에 런타임을 전개.",
    ),
    (
        "7-Zip SFX",
        [r"\\7zs[0-9a-f]+\.tmp"],
        [r"\\7z[a-z]?\.(dll|sfx)$"],
        "7-Zip 자동 압축 해제 실행 파일.",
    ),
    (
        "WinRAR SFX",
        [r"\\rarsfx\d+\\"],
        [r"\\__tmp_rar_sfx_access_check_\d+"],
        "WinRAR 자동 압축 해제 실행 파일.",
    ),
    (
        "InstallShield",
        [r"\\\{[0-9a-f-]{36}\}\\setup\.inx"],
        [r"_isres[_0-9]*\.dll$", r"\\isbew64\.exe$"],
        "상용 인스톨러.",
    ),
    (
        "Windows Installer (MSI)",
        [r"\\msi[0-9a-f]{4,}\.tmp"],
        [r"\.msi$"],
        "MSI 패키지 실행. 정상 소프트웨어에서도 흔하므로 단독으로는 약한 신호.",
    ),
    (
        "Electron / NW.js",
        [r"\\resources\\app\.asar$"],
        [r"\\ffmpeg\.dll$", r"\\libegl\.dll$"],
        "Node 기반 데스크톱 앱 번들.",
    ),
)


def detect_packers(ioc, new_processes: list | None = None) -> list:
    """드롭 파일 패턴으로 패커/인스톨러를 식별한다.

    Returns
    -------
    list[dict]
        {name, confidence, description, evidence:list[str]}
    """
    files = [f.lower().replace("/", "\\") for f in (getattr(ioc, "dropped_files", []) or [])]
    for p in (new_processes or []):
        exe = (getattr(p, "exe", "") or "").lower().replace("/", "\\")
        if exe:
            files.append(exe)
    if not files:
        return []

    out: list = []
    for name, required, optional, desc in _PACKER_SIGNATURES:
        req_hits: list[str] = []
        for pat in required:
            rx = re.compile(pat, re.IGNORECASE)
            hit = next((f for f in files if rx.search(f)), None)
            if hit:
                req_hits.append(hit)

        opt_hits: list[str] = []
        for pat in optional:
            rx = re.compile(pat, re.IGNORECASE)
            hit = next((f for f in files if rx.search(f)), None)
            if hit and hit not in opt_hits:
                opt_hits.append(hit)

        if not req_hits and not opt_hits:
            continue
        # 필수 패턴 전부 + 보조 1개 이상 → HIGH
        if len(req_hits) >= len(required) and opt_hits:
            conf = "HIGH"
        elif req_hits and opt_hits:
            conf = "HIGH"
        elif req_hits or len(opt_hits) >= 2:
            conf = "MEDIUM"
        else:
            continue

        out.append({
            "name":        name,
            "confidence":  conf,
            "description": desc,
            "evidence":    (req_hits + opt_hits)[:5],
        })

    _order = {"HIGH": 0, "MEDIUM": 1}
    out.sort(key=lambda d: _order.get(d["confidence"], 2))
    return out


# ── 2. 정상 구성요소 사칭 탐지 ───────────────────────────────────────────────

# 실제 Windows 시스템 바이너리 — System32 밖에서 나타나면 강한 신호
_REAL_SYSTEM_BINARIES: frozenset[str] = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "taskhostw.exe", "dwm.exe",
    "runtimebroker.exe", "searchindexer.exe", "spoolsv.exe", "conhost.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "dllhost.exe",
    "wuauclt.exe", "ctfmon.exe", "sihost.exe", "audiodg.exe", "fontdrvhost.exe",
    "lsm.exe", "userinit.exe", "taskmgr.exe", "wmiprvse.exe", "msmpeng.exe",
    "securityhealthservice.exe", "trustedinstaller.exe", "tiworker.exe",
})

# 정상 시스템 바이너리가 존재하는 경로
_LEGIT_SYSTEM_DIRS: tuple[str, ...] = (
    r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\winsxs",
    r"c:\windows\servicing", r"c:\windows\explorer.exe",
    "c:\\program files\\", "c:\\program files (x86)\\",
)

# 드롭 위치로 흔히 쓰이는 사용자 쓰기 가능 경로
_DROP_DIRS: tuple[str, ...] = (
    r"c:\programdata\\", r"\appdata\local\\", r"\appdata\roaming\\",
    r"c:\users\public\\", r"c:\windows\temp\\", r"\temp\\",
)

# MS 제품군에서 흔한 어휘 — 조합하면 그럴듯한 이름이 된다
_MS_STYLE_TOKENS: tuple[str, ...] = (
    "telemetry", "notify", "notification", "broker", "dispatcher", "service",
    "host", "helper", "agent", "update", "updater", "sync", "manager",
    "monitor", "runtime", "platform", "provider", "handler", "worker",
    "security", "defender", "windows", "microsoft", "office", "edge",
    "store", "search", "index", "shell", "system", "network", "device",
)

_CAMEL_RE = re.compile(r"^(?:[A-Z][a-z0-9]+){2,}$")


def _in_drop_dir(path_lower: str) -> bool:
    return any(d in path_lower for d in _DROP_DIRS)


def _in_legit_dir(path_lower: str) -> bool:
    return any(path_lower.startswith(d) for d in _LEGIT_SYSTEM_DIRS)


def detect_masquerading(
    ioc,
    new_processes: list | None = None,
    lineage_pids: set | None = None,
) -> list:
    """정상 구성요소를 사칭한 드롭 파일을 찾는다.

    Returns
    -------
    list[dict]
        {path, filename, kind, confidence, reason, technique, in_lineage}
    """
    lineage_pids = set(lineage_pids or ())
    candidates: list[tuple] = []          # (path, pid|None)

    for f in (getattr(ioc, "dropped_files", []) or []):
        candidates.append((f, None))
    for p in (new_processes or []):
        exe = getattr(p, "exe", "") or ""
        if exe:
            candidates.append((exe, getattr(p, "pid", None)))

    seen: set = set()
    out: list = []

    for path, pid in candidates:
        low = path.lower().replace("/", "\\")
        if low in seen:
            continue
        ext = os.path.splitext(low)[1]
        if ext not in (".exe", ".dll", ".scr", ".sys"):
            continue
        if _in_legit_dir(low):
            continue                       # 정상 위치의 정상 파일
        seen.add(low)

        fname   = os.path.basename(low)
        stem    = os.path.splitext(os.path.basename(path))[0]
        parent  = os.path.basename(os.path.dirname(low))
        in_lin  = pid in lineage_pids if pid is not None else False

        # (a) 실제 시스템 바이너리 이름을 비표준 경로에서 사용 — 강한 신호
        if fname in _REAL_SYSTEM_BINARIES:
            out.append({
                "path": path, "filename": fname, "kind": "system-binary-name",
                "confidence": "HIGH",
                "reason": (
                    f"실제 Windows 시스템 바이너리 이름({fname})을 "
                    f"System32 가 아닌 경로에서 사용"
                ),
                "technique": "T1036.005",
                "in_lineage": in_lin,
            })
            continue

        # (b) 실존하지 않지만 MS 풍으로 조합된 이름 — 휴리스틱
        if not _in_drop_dir(low):
            continue
        low_stem = stem.lower()
        token_hits = [t for t in _MS_STYLE_TOKENS if t in low_stem]
        if len(token_hits) < 2:
            continue

        reasons = [
            f"MS 제품군 어휘 조합({', '.join(token_hits[:3])})",
        ]
        conf = "MEDIUM"
        if _CAMEL_RE.match(stem):
            reasons.append("CamelCase 표기")
        # ProgramData\<이름>\<이름>.exe — 자기 이름 디렉터리를 만든 경우
        if parent and parent == low_stem:
            reasons.append("실행 파일과 동일한 이름의 전용 디렉터리 생성")
            conf = "HIGH"

        out.append({
            "path": path, "filename": os.path.basename(path),
            "kind": "plausible-ms-name",
            "confidence": conf,
            "reason": (
                "실존하지 않는 이름이나 정상 Windows 구성요소처럼 보이도록 "
                "구성됨 — " + ", ".join(reasons)
            ),
            "technique": "T1036",
            "in_lineage": in_lin,
        })

    _order = {"HIGH": 0, "MEDIUM": 1}
    out.sort(key=lambda d: (_order.get(d["confidence"], 2), not d["in_lineage"]))
    return out


def artifact_intel_to_dict(packers: list, masq: list) -> dict:
    return {"packers": packers, "masquerading": masq}


def add_masquerade_techniques(behavior_report, findings: list) -> int:
    """사칭 탐지를 T1036 / T1036.005 로 병합한다."""
    if not behavior_report or not findings:
        return 0
    from analysis.behavior_classifier import MitreTechnique

    techs = getattr(behavior_report, "techniques", None)
    if techs is None:
        return 0
    existing = {getattr(t, "technique_id", ""): t for t in techs}

    _META = {
        "T1036":     ("Masquerading", "https://attack.mitre.org/techniques/T1036/"),
        "T1036.005": ("Match Legitimate Name or Location",
                      "https://attack.mitre.org/techniques/T1036/005/"),
    }
    added = 0
    for f in findings:
        tid = f.get("technique", "T1036")
        name, ref = _META.get(tid, _META["T1036"])
        t = existing.get(tid)
        if t is None:
            t = MitreTechnique(
                technique_id=tid, technique_name=name,
                tactic="Defense Evasion", evidence=[],
                reference=ref, sources=["사칭탐지"],
            )
            techs.append(t)
            existing[tid] = t
        ev = f"{f.get('path','')} — {f.get('reason','')} (신뢰도 {f.get('confidence','')})"
        if ev not in t.evidence:
            t.evidence.append(ev)
            added += 1
        if "사칭탐지" not in (t.sources or []):
            t.sources.append("사칭탐지")
    return added
