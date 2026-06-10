"""
vm_setup.py — 패킷 캡처 품질 향상을 위한 VM 자동 세팅

스냅샷 복원 후 매번 실행될 때마다 자동 적용됩니다.
관리자 권한이 있으면 레지스트리에 정책을 써서 캡처를 방해하는 브라우저/시스템
동작을 억제합니다. 이미 적용된 경우 추가 비용 없이 덮어씁니다(멱등).

적용 내용
---------
- Chrome DoH/QUIC 비활성화  → A 쿼리가 평문 UDP 53으로 노출
- Edge   DoH/QUIC 비활성화  → 동일
- Firefox DoH 비활성화       → 동일
- LLMNR 비활성화             → .in-addr.arpa PTR 노이즈 제거
- NetBIOS-NS 비활성화        → UDP 137 브로드캐스트 노이즈 제거
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

# Windows 전용 — 비-Windows 환경에서는 전체 모듈을 스킵
try:
    import winreg as _reg
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


@dataclass
class _Policy:
    hive: int
    path: str
    name: str
    kind: int   # winreg.REG_SZ | REG_DWORD
    value: object
    label: str  # 콘솔 표시용


def _policies() -> List[_Policy]:
    if not _AVAILABLE:
        return []
    REG_SZ    = _reg.REG_SZ
    REG_DWORD = _reg.REG_DWORD
    HKLM      = _reg.HKEY_LOCAL_MACHINE
    return [
        # ── Chrome ────────────────────────────────────────────────
        _Policy(HKLM, r"SOFTWARE\Policies\Google\Chrome",
                "DnsOverHttpsMode", REG_SZ, "off",      "Chrome DoH"),
        _Policy(HKLM, r"SOFTWARE\Policies\Google\Chrome",
                "QuicAllowed",      REG_DWORD, 0,        "Chrome QUIC"),
        # ── Edge ──────────────────────────────────────────────────
        _Policy(HKLM, r"SOFTWARE\Policies\Microsoft\Edge",
                "DnsOverHttpsMode", REG_SZ, "off",       "Edge DoH"),
        _Policy(HKLM, r"SOFTWARE\Policies\Microsoft\Edge",
                "QuicAllowed",      REG_DWORD, 0,         "Edge QUIC"),
        # ── Firefox ───────────────────────────────────────────────
        _Policy(HKLM, r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
                "Enabled",          REG_DWORD, 0,         "Firefox DoH"),
        # ── Windows 네트워크 노이즈 ───────────────────────────────
        _Policy(HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast",  REG_DWORD, 0,         "LLMNR"),
        _Policy(HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
                "NodeType",         REG_DWORD, 2,         "NetBIOS-NS"),
    ]


def apply_capture_policies() -> tuple[list[str], list[str]]:
    """
    레지스트리 정책을 적용하고 (성공 레이블 목록, 실패 레이블 목록)을 반환합니다.
    권한 부족·비-Windows 환경에서는 조용히 빈 리스트를 반환합니다.
    """
    if not _AVAILABLE:
        return [], []

    ok: list[str]   = []
    fail: list[str] = []

    for p in _policies():
        try:
            key = _reg.CreateKeyEx(
                p.hive, p.path, 0,
                _reg.KEY_SET_VALUE | _reg.KEY_CREATE_SUB_KEY
            )
            _reg.SetValueEx(key, p.name, 0, p.kind, p.value)
            _reg.CloseKey(key)
            ok.append(p.label)
        except OSError:
            fail.append(p.label)

    return ok, fail
