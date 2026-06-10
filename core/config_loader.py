"""
config_loader.py — config.json 로드 및 기본값 병합

사용법:
    from core.config_loader import load_config, get_hunt_cfg

    cfg      = load_config()               # 전체 설정 dict
    hunt_cfg = get_hunt_cfg()              # hunt 섹션만
"""
from __future__ import annotations

import json
from pathlib import Path

# ── 기본값 ──────────────────────────────────────────────────────────
_DEFAULTS: dict = {
    "capa": {
        "enabled": True,
        "path":    "capa.exe",
        "timeout": 120,
    },
    "virustotal": {
        "enabled": False,
        "api_key": "",
        "timeout": 20,
    },
    "hunt": {
        "serve_port": 18080,
        "services": {
            "mb": {
                "enabled": True,
                "label":   "MalwareBazaar",
                "url":     "https://mb-api.abuse.ch/api/v1/",
            },
            "tf": {
                "enabled": True,
                "label":   "ThreatFox",
                "url":     "https://threatfox-api.abuse.ch/api/v1/",
            },
            "uh_url": {
                "enabled": True,
                "label":   "URLhaus (URL)",
                "url":     "https://urlhaus-api.abuse.ch/v1/url/",
            },
            "uh_host": {
                "enabled": True,
                "label":   "URLhaus (Host)",
                "url":     "https://urlhaus-api.abuse.ch/v1/host/",
            },
            "feodo": {
                "enabled": True,
                "label":   "Feodo Tracker",
                "url":     "https://feodotracker.abuse.ch/api/v1/host_info/",
            },
        },
    }
}


def _deep_merge(base: dict, override: dict) -> dict:
    """override 로 base 를 재귀 병합합니다 (dict 값은 중첩 병합)."""
    result = base.copy()
    for k, v in override.items():
        if k.startswith("_"):          # _comment 같은 메타 키 무시
            continue
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(path: str | Path | None = None) -> dict:
    """
    config.json 을 로드하고 기본값과 병합해 반환합니다.

    path 미지정 시 프로젝트 루트(이 파일 기준 상위 두 단계)의
    config.json 을 탐색합니다.  파일이 없거나 파싱 실패 시 기본값만 반환합니다.
    """
    if path is None:
        path = Path(__file__).parent.parent / "config.json"
    else:
        path = Path(path)

    cfg = _deep_merge({}, _DEFAULTS)   # 기본값 복사
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
            cfg = _deep_merge(cfg, user)
        except Exception:
            pass  # 파싱 실패 → 기본값 사용
    return cfg


def get_hunt_cfg(path: str | Path | None = None) -> dict:
    """Hunt 탭 설정(hunt 섹션)만 반환합니다."""
    return load_config(path)["hunt"]
