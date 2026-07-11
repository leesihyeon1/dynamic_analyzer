"""
sensitive_paths.py — 자격증명 저장소 / anti-VM 아티팩트 파일 경로 (공유 단일 소스).

행위 분류기(behavior_classifier)와 노이즈 필터(noise_filter)가 동일한 기준을
쓰도록 경로 조각과 판정 함수를 한 곳에 둔다.

배경: ReadFile 은 노이즈로 간주돼 필터에서 제거되지만, "자격증명 파일 읽기"
(T1555.003)나 "anti-VM 아티팩트 점검"(T1497.001)은 ReadFile 형태로 나타나는
악성 행위다. 필터가 이 경로의 ReadFile 만 예외적으로 보존하도록
is_sensitive_read_path() 를 carve-out 에 사용한다.
"""

from __future__ import annotations

# 브라우저 자격증명/쿠키 저장소 경로 조각 — T1555.003 (소문자)
BROWSER_CRED_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\google\\chrome\\user data\\default\\login data",
    "\\google\\chrome\\user data\\default\\cookies",
    "\\google\\chrome\\user data\\default\\web data",
    "\\microsoft\\edge\\user data\\default\\login data",
    "\\microsoft\\edge\\user data\\default\\cookies",
    "\\microsoft\\credentials\\",
    "\\microsoft\\protect\\",
)

# Firefox 계열 자격증명 파일명 (경로 조각으로 못 잡는 파일 단위 매칭)
BROWSER_CRED_FILENAMES: frozenset[str] = frozenset(
    {"logins.json", "key4.db", "key3.db", "signons.sqlite"}
)

# anti-VM/Sandbox 탐지에 쓰이는 VM 도구 파일 조각 — T1497.001 (소문자)
ANTI_VM_FILE_FRAGMENTS: tuple[str, ...] = (
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "vmacthlp.exe", "vmnat.exe", "vmnetdhcp.exe",
    "vboxservice.exe", "vboxtray.exe", "vboxcontrol.exe",
    "\\vmware\\", "\\oracle\\virtualbox",
    "prl_tools.exe", "prl_cc.exe", "vmsrvc.exe", "vmusrvc.exe",
)


def _basename_lower(lower_path: str) -> str:
    """소문자 경로에서 파일명 컴포넌트 추출."""
    sep = max(lower_path.rfind("\\"), lower_path.rfind("/"))
    return lower_path[sep + 1:] if sep >= 0 else lower_path


def is_sensitive_read_path(path: str) -> bool:
    """경로가 자격증명 저장소 또는 anti-VM 아티팩트에 해당하는지 판정.

    ReadFile carve-out 용 — True 면 노이즈 필터가 해당 ReadFile 을 보존해야 한다.
    """
    if not path:
        return False
    lower = path.lower()
    if any(frag in lower for frag in BROWSER_CRED_PATH_FRAGMENTS):
        return True
    if "\\mozilla\\firefox\\" in lower and _basename_lower(lower) in BROWSER_CRED_FILENAMES:
        return True
    if any(frag in lower for frag in ANTI_VM_FILE_FRAGMENTS):
        return True
    return False
