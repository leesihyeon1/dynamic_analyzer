"""JSON 보고서 저장"""
from __future__ import annotations

import json
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path
from typing import Any


def _to_serializable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        out = {f.name: _to_serializable(getattr(obj, f.name)) for f in fields(obj)}
        # relevance.annotate() 가 setattr 로 붙인 등급은 dataclass 필드가
        # 아니어서 fields() 에 잡히지 않는다. 있으면 함께 내보낸다.
        if "relevance_tier" not in out and hasattr(obj, "relevance_tier"):
            out["relevance_tier"] = getattr(obj, "relevance_tier")
        return out
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(i) for i in obj]
    if isinstance(obj, set):
        return sorted(_to_serializable(i) for i in obj)
    if isinstance(obj, dict):
        return {str(k): _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, 'value'):   # Enum
        return obj.value
    return obj


def _iocs_json(ioc) -> dict:
    """IOCReport → dict. relevance.annotate() 가 붙인 경로별 등급도 함께 내보낸다.

    dropped_file_tiers 는 dataclass 필드가 아니라 setattr 로 붙기 때문에
    _to_serializable 의 fields() 순회에서 빠진다.
    """
    if not ioc:
        return {}
    out = _to_serializable(ioc)
    tiers = getattr(ioc, "dropped_file_tiers", None)
    if tiers:
        out["dropped_file_tiers"] = {str(k): v for k, v in tiers.items()}
    return out


def _build_yara_json(yr) -> dict:
    """YaraScanResult → JSON-serialisable dict."""
    if yr is None:
        return {"available": False, "error": "실행되지 않음"}
    base = {
        "available":     yr.available,
        "rules_loaded":  yr.rules_loaded,
        "rules_failed":  yr.rules_failed,
        "files_scanned": yr.files_scanned,
        "match_count":   len(yr.matches),
        "error":         yr.error,
    }
    base["matches"] = [
        {
            "rule":            m.rule_name,
            "file":            m.file_scanned,
            "description":     m.meta.get("description", m.meta.get("desc", "")),
            "author":          m.meta.get("author", ""),
            "tags":            m.tags,
            "matched_strings": m.matched_strings,
            "meta":            m.meta,
        }
        for m in yr.matches
    ]
    return base


def save_json_report(result, output_path: str) -> None:
    """AnalysisResult → JSON 파일 저장"""
    from core.orchestrator import AnalysisResult

    data = {
        "sample":    str(result.config.sample_path),
        "timeout":   result.config.timeout,
        "duration":  round(result.end_time - result.start_time, 1),
        "tools_used": result.tools_used,
        "errors":    result.errors,
        "sample_pid": result.sample_pid,
        "all_pids":  sorted(result.all_pids),

        # 관련도 등급 — 1=샘플 계보 2=상관 의심 3=환경 배경 (0=미판정)
        "relevance": {
            "counts":   getattr(result, "relevance_counts", {}) or {},
            "baseline": getattr(result, "baseline_info", {}) or {},
            "tiers": {
                "1": "샘플 계보", "2": "상관 의심", "3": "환경 배경",
            },
        },
        "lineage_pids":  sorted(getattr(result, "lineage_pids", None) or []),
        "injected_pids": sorted(getattr(result, "injected_pids", None) or []),
        "sideload_findings":  getattr(result, "sideload_findings", None) or [],
        "injection_findings": getattr(result, "injection_findings", None) or [],
        "packer_findings":    getattr(result, "packer_findings", None) or [],
        "masquerade_findings": getattr(result, "masquerade_findings", None) or [],

        "mitre_techniques": [
            {
                "id":        t.technique_id,
                "name":      t.technique_name,
                "tactic":    t.tactic,
                "reference": t.reference,
                "evidence":  t.evidence[:10],
                # sources 가 없으면 CAPA(정적)·VirusTotal(타 샌드박스)·로컬룰을
                # JSON 만 보고 구분할 수 없다.
                "sources":   list(getattr(t, "sources", None) or []),
                "relevance_tier": getattr(t, "relevance_tier", 0),
            }
            for t in (result.behavior_report.techniques if result.behavior_report else [])
        ],

        "iocs": _iocs_json(result.ioc_report),

        "registry_diff": {
            "added":    [[k, n, str(v)] for k, n, v in result.registry_diff.get("added",    [])],
            "modified": [[k, n, str(o), str(nw)] for k, n, o, nw in result.registry_diff.get("modified", [])],
            "deleted":  [[k, n, str(v)] for k, n, v in result.registry_diff.get("deleted",  [])],
        },

        "process_diff": {
            "new_processes": [
                {"pid": p.pid, "ppid": getattr(p, "ppid", 0),
                 "name": p.name, "exe": p.exe, "cmdline": p.cmdline,
                 "relevance_tier": getattr(p, "relevance_tier", 0)}
                for p in result.process_diff.get("new_processes", [])
            ],
            "terminated_processes": [
                {"pid": p.pid, "name": p.name}
                for p in result.process_diff.get("terminated_processes", [])
            ],
        },

        "network": _to_serializable(result.pcap_result) if result.pcap_result else {},

        "process_network_map": [
            {
                "pid":         c.pid,
                "process":     c.process,
                "proto":       c.proto,
                "remote_ip":   c.remote_ip,
                "remote_port": c.remote_port,
                "direction":   c.direction,
                "event_count": c.event_count,
            }
            for c in getattr(result, "process_network_map", [])
        ],

        "events_summary": {
            "total":    len(result.procmon_events),
            "filtered": len(result.filtered_events),
        },

        "yara_scan": _build_yara_json(getattr(result, "yara_result", None)),
    }

    Path(output_path).write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
