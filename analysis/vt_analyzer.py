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

def query_vt_file_info(
    sha256:  str,
    api_key: str,
    timeout: int = 20,
) -> dict:
    """파일 해시로 VT 탐지 통계를 조회합니다.

    GET /files/{sha256} 를 한 번만 호출합니다 (요청 1건).

    Returns
    -------
    dict:
        detections  — 악성 탐지 엔진 수. -1 이면 미등록 또는 조회 실패.
        total       — 전체 스캔 엔진 수.
        label       — 위협 레이블 (예: "trojan.agent/injector").
    """
    empty: dict = {"detections": -1, "total": 0, "label": ""}
    if not sha256 or not api_key or len(sha256) != 64:
        return empty

    data = _vt_get(f"{_VT_API_BASE}/files/{sha256}", api_key, timeout)
    if not data or not isinstance(data.get("data"), dict):
        return empty

    attrs  = data["data"].get("attributes") or {}
    stats  = attrs.get("last_analysis_stats") or {}

    malicious  = int(stats.get("malicious",  0))
    total      = (malicious
                  + int(stats.get("suspicious", 0))
                  + int(stats.get("undetected", 0))
                  + int(stats.get("harmless",   0))
                  + int(stats.get("failure",    0)))

    label = ""
    ptc = attrs.get("popular_threat_classification") or {}
    label = ptc.get("suggested_threat_label", "") or ""
    if not label:
        names = attrs.get("popular_threat_names") or []
        if names and isinstance(names, list):
            first = names[0]
            label = first.get("value", "") if isinstance(first, dict) else str(first)

    return {"detections": malicious, "total": total, "label": label}


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


def _item_to_str(item: Any) -> str:
    """VT 행위 아이템 → 간결한 문자열 변환."""
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return ""
    # 네트워크: destination_ip:port
    if "destination_ip" in item:
        ip   = item.get("destination_ip", "")
        port = item.get("destination_port", "")
        return f"{ip}:{port}" if port else str(ip)
    # HTTP
    if "url" in item:
        return str(item["url"])
    # 레지스트리: key\value
    if "key" in item:
        val = item.get("value", "")
        return f"{item['key']}\\{val}" if val else str(item["key"])
    # 파일
    if "path" in item:
        return str(item["path"])
    # 프로세스
    if "process_name" in item:
        cmd = item.get("command_line", "")
        name = str(item["process_name"])
        return f"{name}: {cmd}" if cmd else name
    if "name" in item:
        return str(item["name"])
    return ""


def _build_evidence(sandbox_name: str, info: Any) -> str:
    """샌드박스 이름 + 기법 description(있을 경우)으로 1차 근거 문자열 생성.

    VT가 반환하는 일반적인 MITRE 설명 텍스트("Adversaries may ...")는
    특정 행위 근거가 아니므로 제외하고 sandbox_name만 사용합니다.
    """
    desc = ""
    if isinstance(info, dict):
        desc = (info.get("description") or info.get("name") or "").strip()
        # MITRE 표준 설명 텍스트는 근거로 부적합 → 제외
        _low = desc.lower()
        if _low.startswith("adversaries may") or _low.startswith("adversaries might"):
            desc = ""
    if desc:
        return f"[{sandbox_name}] {desc}"
    return sandbox_name


def _extract_behav_evidence(attrs: dict, tid: str) -> list[str]:
    """샌드박스 attrs에서 해당 기법과 관련된 행위 아티팩트를 최대 3건 추출."""
    tid_base = tid.split(".")[0]

    # 기법 계열 → 관련 샌드박스 속성 필드 (순서가 우선순위)
    _FIELD_MAP: dict[str, list[str]] = {
        "T1059": ["command_executions", "processes_created"],
        "T1106": ["processes_created"],
        "T1047": ["command_executions"],
        "T1112": ["registry_keys_set"],
        "T1547": ["registry_keys_set"],
        "T1055": ["processes_injected", "processes_created"],
        "T1036": ["processes_created"],
        "T1082": ["command_executions"],
        "T1083": ["files_opened"],
        "T1012": ["registry_keys_opened"],
        "T1057": ["processes_created"],
        "T1071": ["http_conversations", "network_communications"],
        "T1095": ["network_communications", "ip_traffic"],
        "T1573": ["network_communications"],
        "T1105": ["files_written", "http_conversations"],
        "T1041": ["network_communications", "ip_traffic"],
        "T1027": ["files_written"],
        "T1140": ["files_written", "command_executions"],
        "T1221": ["http_conversations"],
        "T1518": ["processes_created"],
        "T1018": ["network_communications"],
        "T1010": [],
    }

    # 서브기법(T1059.001)과 기본기법(T1059) 필드를 합쳐 중복 제거
    seen_fields: list[str] = []
    for f in (_FIELD_MAP.get(tid, []) + _FIELD_MAP.get(tid_base, [])):
        if f not in seen_fields:
            seen_fields.append(f)

    results: list[str] = []
    seen_vals: set[str] = set()

    for field in seen_fields:
        raw_items = attrs.get(field, [])
        if not isinstance(raw_items, list):
            continue
        for raw in raw_items:
            val = _item_to_str(raw)
            if val and val not in seen_vals:
                seen_vals.add(val)
                results.append(val[:100])
                if len(results) >= 3:
                    return results

    return results


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
                evidence = _build_evidence(sandbox_name, info)
                _add_tech(technique_map, tid, info, evidence)
                for artifact in _extract_behav_evidence(attrs, tid)[:2]:
                    _add_tech(technique_map, tid, {}, f"[{sandbox_name}] {artifact}")

        elif isinstance(mitre, list):
            for item in mitre:
                if isinstance(item, str):
                    _add_tech(technique_map, item, {}, sandbox_name)
                    for artifact in _extract_behav_evidence(attrs, item)[:2]:
                        _add_tech(technique_map, item, {}, f"[{sandbox_name}] {artifact}")
                elif isinstance(item, dict):
                    tid = item.get("id", "") or item.get("technique_id", "")
                    evidence = _build_evidence(sandbox_name, item)
                    _add_tech(technique_map, tid, item, evidence)
                    for artifact in _extract_behav_evidence(attrs, tid)[:2]:
                        _add_tech(technique_map, tid, {}, f"[{sandbox_name}] {artifact}")


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
