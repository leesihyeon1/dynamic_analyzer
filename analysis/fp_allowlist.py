"""
fp_allowlist.py — hollows-hunter / pe-sieve 오탐(FP) 화이트리스트 단일 정의.

behavior_classifier · ai_analyzer · html_report 에 흩어져 있던 동일 목록을
한 곳으로 통합한다. 목록 변경 시 이 파일만 수정하면 된다.

주의: 이 목록은 "무조건 제외"가 아니라, 각 호출부에서
      replaced == 0 AND implanted_pe == 0 (쉘코드·훅만 탐지) 조건과
      함께 사용해야 한다 — 화이트리스트 프로세스에 진짜 PE 인젝션이
      들어간 경우는 계속 탐지되어야 하기 때문.
"""

from __future__ import annotations

# Windows 10/11에서 hollows-hunter가 UWP / .NET JIT 스텁 때문에
# 쉘코드로 오탐하는 시스템 프로세스 (소문자).
HH_SYSTEM_FP_NAMES: frozenset[str] = frozenset({
    "dwm.exe",                      # Desktop Window Manager (UWP/DWM shellcode stubs)
    "explorer.exe",                 # Windows Explorer (.NET JIT trampolines)
    "searchapp.exe",                # Windows Search (UWP)
    "searchui.exe",                 # Windows Search (older builds)
    "lockapp.exe",                  # Lock Screen (UWP)
    "shellexperiencehost.exe",      # Start Menu shell (UWP)
    "startmenuexperiencehost.exe",  # Start Menu (Windows 11)
    "runtimebroker.exe",            # UWP broker
    "applicationframehost.exe",     # UWP app frame
    "textinputhost.exe",            # Touch keyboard
    "systemsettings.exe",           # Settings app (UWP)
    "smartscreen.exe",              # SmartScreen filter
    "wuauclt.exe",                  # Windows Update client
    "sihost.exe",                   # Shell Infrastructure Host
    "taskhostw.exe",                # Task Host Window
    "ctfmon.exe",                   # CTF monitor (IME)
    # 분석 도구 — FP가 아니라 원래부터 의심 대상이 아님
    # (실제 실행 파일명은 하이픈 표기 — 언더스코어 표기는 과거 호환용)
    "picpick.exe",
    "processhacker.exe",
    "systeminformer.exe",
    "procmon.exe",
    "procmon64.exe",
    "hollows_hunter.exe",
    "hollows_hunter64.exe",
    "hollows-hunter.exe",
    "hollows-hunter64.exe",
    "pe-sieve.exe",
    "pe-sieve64.exe",
    "pe_sieve.exe",
    "pe_sieve64.exe",
})
