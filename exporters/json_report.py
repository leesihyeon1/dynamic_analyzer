"""JSON 보고서 저장"""
from __future__ import annotations

import json
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path
from typing import Any


def _to_serializable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_serializable(getattr(obj, f.name)) for f in fields(obj)}
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

        "mitre_techniques": [
            {
                "id":        t.technique_id,
                "name":      t.technique_name,
                "tactic":    t.tactic,
                "reference": t.reference,
                "evidence":  t.evidence[:10],
            }
            for t in (result.behavior_report.techniques if result.behavior_report else [])
        ],

        "iocs": _to_serializable(result.ioc_report) if result.ioc_report else {},

        "registry_diff": {
            "added":    [[k, n, str(v)] for k, n, v in result.registry_diff.get("added",    [])],
            "modified": [[k, n, str(o), str(nw)] for k, n, o, nw in result.registry_diff.get("modified", [])],
            "deleted":  [[k, n, str(v)] for k, n, v in result.registry_diff.get("deleted",  [])],
        },

        "process_diff": {
            "new_processes": [
                {"pid": p.pid, "name": p.name, "exe": p.exe, "cmdline": p.cmdline}
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
