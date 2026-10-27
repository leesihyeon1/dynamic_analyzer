"""
config_loader.py — config.json 로드 및 기본값 병합

사용법:
    from core.config_loader import load_config, get_hunt_cfg

    cfg      = load_config()               # 전체 설정 dict
    hunt_cfg = get_hunt_cfg()              # hunt 섹션만
"""
from __future__ import annotations

import json
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

# ── 기본값 ──────────────────────────────────────────────────────────
_DEFAULTS: dict = {
    "tools": {
        "pe_sieve":       "",   # 비워두면 PATH + 알려진 디렉터리 자동 탐색
        "hollows_hunter": "",
    },
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
    "ai": {
        # provider: auto(NVIDIA 우선 → Ollama 폴백) | nvidia | ollama
        "enabled":  True,
        "provider": "nvidia",
        "model": "mistralai/mistral-large-2-instruct",
        "api_key": "",
        "timeout":  600,
        "nvidia": {
            "base_url":         "https://integrate.api.nvidia.com/v1",
            "model":            "qwen/qwen2.5-72b-instruct",
            # 권장: 환경변수 NVIDIA_API_KEY 사용 (여기 평문 저장 금지)
            "api_key":          "",
            "max_prompt_chars": 40000,
            # 0 = 모델 종류에 따라 자동 (일반 4096 / reasoning 16384)
            "max_tokens":       0,
        },
        "ollama": {
            "base_url":         "http://localhost:11434",
            "model":            "auto",   # auto: 실행 중인 모델 자동 감지
            "max_prompt_chars": 10000,
        },
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
        path = CONFIG_PATH
    else:
        path = Path(path)

    cfg = _deep_merge({}, _DEFAULTS)   # 기본값 복사
    if path.exists():
        try:
            with open(path, encoding="utf-8-sig") as f:
                user = json.load(f)
            cfg = _deep_merge(cfg, user)
        except Exception:
            pass  # 파싱 실패 → 기본값 사용
    return cfg


def get_hunt_cfg(path: str | Path | None = None) -> dict:
    """Hunt 탭 설정(hunt 섹션)만 반환합니다."""
    return load_config(path)["hunt"]


def get_ai_cfg() -> dict:
    """config.json의 AI 설정을 우선 사용하고 빈 값만 환경변수로 보완한다."""
    cfg = dict(load_config()["ai"])
    # 원격 버전의 중첩 ai.nvidia 설정도 읽되, 기존 ai.api_key/model을 우선한다.
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")) if CONFIG_PATH.exists() else {}
        raw_ai = raw.get("ai", {}) if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        raw_ai = {}
    if not isinstance(raw_ai, dict):
        raw_ai = {}
    nested = raw_ai.get("nvidia", {})
    if not isinstance(nested, dict):
        nested = {}
    for key in ("api_key", "model"):
        if key not in raw_ai and nested.get(key):
            cfg[key] = nested[key]
    for key, variable in (("api_key", "NVIDIA_API_KEY"), ("model", "NVIDIA_MODEL")):
        if not str(cfg.get(key, "")).strip() and os.environ.get(variable, "").strip():
            cfg[key] = os.environ[variable].strip()
    if not cfg.get("model"):
        cfg["model"] = _DEFAULTS["ai"]["model"]
    return cfg


def save_ai_settings(model: str, api_key: str | None = None) -> None:
    """기존 설정 섹션을 보존하면서 config.json의 ai 항목만 갱신한다."""
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")) if CONFIG_PATH.exists() else {}
    if not isinstance(data, dict) or not isinstance(data.get("ai", {}), dict):
        raise ValueError("config.json 형식이 올바르지 않습니다.")
    cfg = data.setdefault("ai", {})
    cfg["model"] = model.strip()
    if api_key is not None:
        cfg["api_key"] = api_key.strip()
    CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
