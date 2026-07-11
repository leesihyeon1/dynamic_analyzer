"""
injection_paths.py — 의심 모듈(DLL) 로드 경로 판정 (공유 단일 소스).

실시간 감시(core/process_watcher.py)와 사후 ProcMon 분석(core/orchestrator.py)이
동일한 injection 신호 기준을 쓰도록 경로 상수와 판정 함수를 한 곳에 둔다.

injection 신호란: 악성코드가 기존/신규 프로세스에 코드를 주입할 때 흔히
Temp·Public 등 비정상 경로의 DLL을 로드하는 패턴. 시스템 정상 경로(System32 등)
에서의 로드는 무시한다.
"""

from __future__ import annotations

# 거의 항상 악성: Temp 계열 디렉터리에서 로드되는 모듈
# 주의: 백슬래시를 이중 이스케이프(\\)로 표기해야 path.lower() in 비교가 정확히 동작함
SUSPICIOUS_DIRS: tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\recycle",              # 휴지통 경유 은닉
)

# 시스템 정상 경로 — 여기서 로드되면 무시
SAFE_DIRS: tuple[str, ...] = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\",
    "\\windows\\fonts\\",
)


def is_suspicious_module_path(path: str) -> bool:
    """모듈 로드 경로가 injection 의심 경로인지 판정한다.

    안전 경로(System32 등)에 해당하면 우선 False,
    그렇지 않고 의심 경로(Temp 등)에 해당하면 True.
    """
    if not path:
        return False
    pl = path.lower()
    if any(safe in pl for safe in SAFE_DIRS):
        return False
    return any(susp in pl for susp in SUSPICIOUS_DIRS)
