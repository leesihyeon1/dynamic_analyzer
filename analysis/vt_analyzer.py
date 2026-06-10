"""
vt_analyzer.py — VirusTotal API 동적 분석 연동

샘플 SHA256 해시로 VT v3 API를 쿼리하고 ATT&CK 기법을 추출합니다.

엔드포인트:
  GET /files/{sha256}/behaviours        — 샌드박스별 ATT&CK T-ID 직접 반환 (권장)
  GET /files/{sha256}/behaviour_summary — 집계 요약 (보완)

무료 API 키: 4 req/분, 500 req/일
config.json > virustotal.api_key 에 설정합니다.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from analysis.behavior_classifier import MitreTechnique
from analysis.attack_lookup import lookup_technique

_VT_API_BASE = "https://www.virustotal.com/api/v3"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def query_vt(
    sha256:  str,
    api_key: str,
    timeout: int = 20,
) -> list[MitreTechnique]:
    """
    VT API에서 샘플의 ATT&CK 기법을 조회합니다.

    Parameters
    ----------
    sha256:   샘플 SHA256 해시 (소문자 64자).
    api_key:  VirusTotal API 키.
    timeout:  HTTP 요청 타임아웃(초).

    Returns
    -------
    list[MitreTechnique]
        각 기법의 sources = ["VirusTotal"]. 실패·미등록 시 빈 리스트.
    """
    if not sha256 or not api_key or len(sha256) != 64:
        return []

    technique_map: dict[str, MitreTechnique] = {}

    # ── 1차: behaviours (샌드박스별 T-ID 딕셔너리) ──────────────────────
    _fetch_behaviours(sha256, api_key, timeout, technique_map)

    # ── 2차: behaviour_summary (보완 — 첫 번째 결과 없을 때만) ─────────
    if not technique_map:
        _fetch_summary(sha256, api_key, timeout, technique_map)

    return list(technique_map.values())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _vt_get(url: str, api_key: str, timeout: int) -> dict | None:
    """VT API GET 요청. 실패 시 None 반환."""
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept":   "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None   # 미등록 샘플 — 정상
        return None
    except Exception:
        return None


def _add_tech(
    technique_map: dict[str, MitreTechnique],
    tid:       str,
    info:      Any,
    evidence:  str,
) -> None:
    """기법을 technique_map 에 추가 또는 evidence 병합."""
    tid = tid.strip()
    if not tid or not tid.startswith("T"):
        return

    if tid in technique_map:
        t = technique_map[tid]
        if evidence and evidence not in t.evidence:
            t.evidence.append(evidence)
        return

    # 이름·전술 결정: info dict 우선, 없으면 lookup 테이블
    name, tactic = lookup_technique(tid)

    if isinstance(info, dict):
        desc = info.get("description") or info.get("name") or ""
        if desc and not name:
            name = desc
        if isinstance(info.get("tags"), list):
            tag_tactic = _tags_to_tactic(info["tags"])
            if tag_tactic and not tactic:
                tactic = tag_tactic

    ref = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
    technique_map[tid] = MitreTechnique(
        technique_id   = tid,
        technique_name = name or tid,
        tactic         = tactic or "Unknown",
        evidence       = [evidence] if evidence else [],
        reference      = ref,
        sources        = ["VirusTotal"],
    )


def _tags_to_tactic(tags: list) -> str:
    """VT severity tags (예: ["EXECUTION"]) → tactic 문자열."""
    mapping = {
        "EXECUTION":           "Execution",
        "PERSISTENCE":         "Persistence",
        "PRIVILEGE_ESCALATION":"Privilege Escalation",
        "DEFENSE_EVASION":     "Defense Evasion",
        "CREDENTIAL_ACCESS":   "Credential Access",
        "DISCOVERY":           "Discovery",
        "LATERAL_MOVEMENT":    "Lateral Movement",
        "COLLECTION":          "Collection",
        "COMMAND_AND_CONTROL": "Command and Control",
        "EXFILTRATION":        "Exfiltration",
        "IMPACT":              "Impact",
    }
    for tag in tags:
        t = mapping.get(str(tag).upper().replace(" ", "_"), "")
        if t:
            return t
    return ""


def _fetch_behaviours(
    sha256:        str,
    api_key:       str,
    timeout:       int,
    technique_map: dict[str, MitreTechnique],
) -> None:
    """
    GET /files/{sha256}/behaviours — 샌드박스 보고서별 파싱.

    각 sandbox 보고서의 attributes.mitre_attack_techniques 가
    - dict: {"T1059.001": {"description": "...", "link": "..."}, ...}
    - list: [{"id": "T1059.001", "description": "...", ...}, ...] 또는 ["T1059.001", ...]
    두 형식을 모두 처리합니다.
    """
    url  = f"{_VT_API_BASE}/files/{sha256}/behaviours"
    data = _vt_get(url, api_key, timeout)
    if not data:
        return

    items = data.get("data", [])
    if isinstance(items, dict):
        items = [items]

    for sandbox in items:
        if not isinstance(sandbox, dict):
            continue
        attrs = sandbox.get("attributes", {})
        if not isinstance(attrs, dict):
            continue

        sandbox_name = attrs.get("sandbox_name", "VT Sandbox")
        mitre = attrs.get("mitre_attack_techniques")
        if not mitre:
            continue

        if isinstance(mitre, dict):
            # {"T1059.001": {"description": "...", "link": "..."}, ...}
            for tid, info in mitre.items():
                _add_tech(technique_map, tid, info, sandbox_name)

        elif isinstance(mitre, list):
            for item in mitre:
                if isinstance(item, str):
                    _add_tech(technique_map, item, {}, sandbox_name)
                elif isinstance(item, dict):
                    tid = item.get("id", "") or item.get("technique_id", "")
                    _add_tech(technique_map, tid, item, sandbox_name)


def _fetch_summary(
    sha256:        str,
    api_key:       str,
    timeout:       int,
    technique_map: dict[str, MitreTechnique],
) -> None:
    """
    GET /files/{sha256}/behaviour_summary — 집계 요약 보완.

    mitre_attack_techniques 가 T-ID 리스트 형식인 경우에만 유효합니다.
    STIX UUID 형식이면 무시합니다.
    """
    url  = f"{_VT_API_BASE}/files/{sha256}/behaviour_summary"
    data = _vt_get(url, api_key, timeout)
    if not data:
        return

    payload = data.get("data", {})
    if isinstance(payload, dict):
        mitre = payload.get("mitre_attack_techniques", [])
    else:
        return

    if isinstance(mitre, list):
        for item in mitre:
            if isinstance(item, str) and item.startswith("T"):
                _add_tech(technique_map, item, {}, "VT Summary")
            elif isinstance(item, dict):
                tid = item.get("id", "")
                if tid.startswith("T"):
                    _add_tech(technique_map, tid, item, "VT Summary")
    elif isinstance(mitre, dict):
        for tid, info in mitre.items():
            _add_tech(technique_map, tid, info, "VT Summary")
