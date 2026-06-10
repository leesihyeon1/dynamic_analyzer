"""
capa_analyzer.py — CAPA 정적 분석 연동

Mandiant CAPA (https://github.com/mandiant/capa) 를 subprocess 로 실행하고
ATT&CK 기법 목록을 추출합니다.

FLARE VM에 capa.exe 가 기본 포함되어 있으므로 PATH에서 자동 검색됩니다.
config.json > capa.path 에서 경로를 재정의할 수 있습니다.

지원 CAPA 버전: v5 이상 (JSON 출력 형식 기준)
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from analysis.behavior_classifier import MitreTechnique


# ── CAPA 실행 파일 후보 ────────────────────────────────────────────────
_CAPA_CANDIDATES: list[str] = [
    "capa.exe",
    "capa",
    r"C:\Tools\capa\capa.exe",
    r"C:\FLARE\Tools\capa\capa.exe",
]


def find_capa() -> str | None:
    """PATH 및 알려진 경로에서 capa 실행 파일을 찾아 반환합니다."""
    import shutil
    for candidate in _CAPA_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return found
        p = Path(candidate)
        if p.exists():
            return str(p)
    return None


def run_capa(
    sample_path: Path | str,
    capa_path:   str | None = None,
    timeout:     int = 120,
) -> list[MitreTechnique]:
    """
    CAPA를 실행하고 ATT&CK 기법 목록을 반환합니다.

    Parameters
    ----------
    sample_path:
        분석 대상 PE 파일 경로.
    capa_path:
        capa 실행 파일 경로. None 이면 자동 탐색.
    timeout:
        최대 실행 시간(초). 기본 120초.

    Returns
    -------
    list[MitreTechnique]
        각 기법의 sources = ["CAPA"]. 실패 시 빈 리스트.
    """
    exe = capa_path or find_capa()
    if not exe:
        return []

    sample_path = Path(sample_path)
    if not sample_path.exists():
        return []

    try:
        result = subprocess.run(
            [exe, str(sample_path), "-j"],
            capture_output=True,
            timeout=timeout,
        )
        # returncode: 0 = 탐지 없음, 1 = 탐지 있음, 기타 = 오류
        if result.returncode not in (0, 1):
            return []

        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return []

        data = json.loads(stdout)
        return _parse_capa_json(data)

    except FileNotFoundError:
        return []   # capa.exe 없음
    except subprocess.TimeoutExpired:
        return []   # 시간 초과
    except (json.JSONDecodeError, Exception):
        return []


def _parse_capa_json(data: dict) -> list[MitreTechnique]:
    """
    CAPA JSON 출력에서 ATT&CK 기법을 추출합니다.

    v5~v8 JSON 형식 지원 (meta.attack[].id / tactic / technique / subtechnique).
    """
    technique_map: dict[str, MitreTechnique] = {}

    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        return []

    for rule_name, rule_data in rules.items():
        if not isinstance(rule_data, dict):
            continue
        meta = rule_data.get("meta", {}) if isinstance(rule_data.get("meta"), dict) else {}
        attacks = meta.get("attack", [])
        if not isinstance(attacks, list):
            continue

        for atk in attacks:
            if not isinstance(atk, dict):
                continue

            tid = atk.get("id", "").strip()
            if not tid or not tid.startswith("T"):
                continue

            tactic      = atk.get("tactic", "")
            technique   = atk.get("technique", "")
            subtechnique = atk.get("subtechnique", "")

            # technique_name 조합
            if subtechnique:
                tname = f"{technique}: {subtechnique}"
            elif technique:
                tname = technique
            else:
                tname = tid

            ref = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"

            # 이미 등록된 기법이면 rule_name 을 evidence 에 추가
            if tid in technique_map:
                t = technique_map[tid]
                if rule_name and rule_name not in t.evidence:
                    t.evidence.append(rule_name)
            else:
                technique_map[tid] = MitreTechnique(
                    technique_id   = tid,
                    technique_name = tname,
                    tactic         = tactic,
                    evidence       = [rule_name] if rule_name else [],
                    reference      = ref,
                    sources        = ["CAPA"],
                )

    return list(technique_map.values())
