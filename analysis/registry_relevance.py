"""
registry_relevance.py — 레지스트리 키의 지속성/보안 관심도 판정 (공유 단일 소스).

레지스트리 이벤트는 정상 활동만으로도 대량 발생하므로, 리포트 표시 시
"악성이 흔히 건드리는 키"(지속성·실행 하이재킹·보안 무력화)를 고관심으로
분리하는 데 사용한다. behavior_classifier 의 ATT&CK 매핑과 목적이 겹치지만,
여기서는 표시 계층화를 위한 "키 경로만으로의" 가벼운 판정을 제공한다.
"""

from __future__ import annotations

# (경로 조각(소문자), 관심 사유 라벨) — 더 구체적인 조각을 앞에 두어 우선 매칭.
_INTEREST_RULES: tuple[tuple[str, str], ...] = (
    ("\\session manager\\bootexecute", "BootExecute 자동실행"),
    # ── 자동 실행 / 지속성 ────────────────────────────────────────────
    ("\\currentversion\\runonce",      "RunOnce 자동실행"),
    ("\\currentversion\\runservices",  "RunServices 자동실행"),
    ("\\currentversion\\run",          "Run 자동실행"),
    ("\\explorer\\run",                "Explorer Run"),
    ("\\services\\",                   "서비스 생성/변경"),
    ("image file execution options",  "IFEO 디버거 인젝션"),
    ("appinit_dlls",                   "AppInit DLL 인젝션"),
    ("\\winlogon\\",                   "Winlogon 헬퍼"),
    ("\\environment\\",                "로그온 스크립트/환경변수"),
    ("\\currentversion\\policies\\explorer", "Explorer 정책"),
    ("startupapproved",                "시작 프로그램 승인"),
    # ── 보안 무력화 ───────────────────────────────────────────────────
    ("disableantispyware",             "Defender 무력화"),
    ("disablerealtimemonitoring",      "Defender 실시간보호 해제"),
    ("disablebehaviormonitoring",      "Defender 행위감시 해제"),
    ("disableioavprotection",          "Defender 다운로드검사 해제"),
    ("disableonaccessprotection",      "Defender 실시간검사 해제"),
    ("\\policies\\system",             "시스템 정책 변경(UAC 등)"),
    ("enablelua",                      "UAC 설정 변경"),
    # ── 실행 하이재킹 ─────────────────────────────────────────────────
    ("\\classes\\clsid",               "COM 하이재킹 가능"),
    ("\\shell\\open\\command",         "파일 연결 하이재킹"),
)


def registry_key_interest(path: str) -> str:
    """레지스트리 키 경로의 관심 사유 라벨을 반환. 해당 없으면 빈 문자열."""
    if not path:
        return ""
    lower = path.lower()
    for frag, label in _INTEREST_RULES:
        if frag in lower:
            return label
    return ""


def is_persistence_key(path: str) -> bool:
    """키가 지속성/보안/하이재킹 관련(고관심)인지 여부."""
    return bool(registry_key_interest(path))
