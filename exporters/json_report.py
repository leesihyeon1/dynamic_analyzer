"""JSON 보고서 저장

보고서는 분석 중(1차, AI 진행 중)과 끝난 뒤(최종) 두 번 같은 파일로 쓰일 수 있다.
GUI·브라우저가 읽는 도중에 반쯤 쓰인 파일을 보지 않도록 같은 폴더의 임시 파일에
쓴 뒤 os.replace 로 바꿔 끼운다 (atomic_write_text).
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path
from typing import Any

_LIST_CAP = 200     # process_behaviors 항목별 목록 상한


def atomic_write_text(path, text: str, encoding: str = "utf-8", retries: int = 6, delay: float = 0.25) -> None:
    """같은 폴더의 임시 파일에 쓴 뒤 os.replace 로 교체한다.

    Windows 에서는 GUI·브라우저가 파일을 읽는 순간 교체가 PermissionError 로 실패할 수
    있어 잠깐씩 기다리며 몇 번 다시 시도한다. 끝내 실패하면 직접 덮어쓰기로 물러선다.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
        last_exc = None
        for attempt in range(max(1, retries)):
            try:
                os.replace(tmp, path)
                return
            except PermissionError as exc:
                last_exc = exc
                time.sleep(delay * (attempt + 1))
        try:
            path.write_text(text, encoding=encoding)
        except OSError:
            raise last_exc
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


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
    tiers = getattr(ioc, "dropped_file_tiers", None) or {}
    if tiers:
        out["dropped_file_tiers"] = {str(k): v for k, v in tiers.items()}
    # 차단 목록에는 샘플 계보·상관 의심(tier ≤2)만, 환경 배경(tier 3)은 참고용으로 분리
    drops = [str(f) for f in (getattr(ioc, "dropped_files", None) or [])]
    out["dropped_files_sample"] = [f for f in drops if (tiers.get(f, 2) or 2) <= 2]
    out["dropped_files_background"] = [f for f in drops if (tiers.get(f, 2) or 2) >= 3]
    return out


def _cap(items) -> list:
    return [str(i) for i in list(items or [])[:_LIST_CAP]]


def _process_behaviors_json(behaviors) -> dict:
    """{pid: ProcessBehavior} → {"<pid>": {name, files_written, …, <key>_count}}."""
    out: dict = {}
    if not isinstance(behaviors, dict):
        return out
    for pid, b in behaviors.items():
        if b is None:
            continue
        try:
            row: dict = {"name": str(getattr(b, "name", "") or "")}
            lists = {
                "files_written": list(getattr(b, "files_written", None) or []),
                "files_deleted": list(getattr(b, "files_deleted", None) or []),
                "reg_written":   list(getattr(b, "reg_written", None) or []),
                "reg_deleted":   list(getattr(b, "reg_deleted", None) or []),
                "children":      [f"{c[1]} ({c[0]})" if isinstance(c, (list, tuple)) and len(c) >= 2 else str(c)
                                  for c in (getattr(b, "children", None) or [])],
                "tcp_conns":     [f"{c[0]}:{c[1]}" if isinstance(c, (list, tuple)) and len(c) >= 2 else str(c)
                                  for c in (getattr(b, "tcp_conns", None) or [])],
                "dns_queries":   list(getattr(b, "dns_queries", None) or []),
            }
            for key, items in lists.items():
                row[key] = _cap(items)
                row[f"{key}_count"] = len(items)
            out[str(pid)] = row
        except Exception:
            continue
    return out


def _verdict_json(result) -> dict:
    """판정 요약과 같은 규칙 기반 지표·점수 (exporters.report_visuals)."""
    try:
        from exporters.report_visuals import build_indicators, score_indicators
        inds = build_indicators(result)
        score, level, label, _color = score_indicators(inds)
    except Exception as exc:
        return {"level": "", "label": "", "score": None, "indicators": [],
                "error": f"{type(exc).__name__}: {exc}"}
    return {
        "level": level, "label": label, "score": score,
        "indicators": [{k: i.get(k, "") for k in ("level", "cat", "title", "ev", "tid")} for i in inds],
    }


def _collection_status_json(result) -> list:
    try:
        from core.collection_health import collection_status
        return collection_status(result) or []
    except Exception:
        return []


def _sample_display_name(result) -> str:
    sp = getattr(getattr(result, "config", None), "sample_path", None)
    if not sp:
        return "전체 시스템 모니터링"
    try:
        return Path(sp).name or str(sp)
    except TypeError:
        return str(sp)


def write_index_json(result, output_dir, verdict: dict | None = None) -> None:
    """<output_dir>/index.json — GUI 최근 결과 목록용 요약."""
    v = verdict or _verdict_json(result)
    data = {
        "sample":       _sample_display_name(result),
        "level":        v.get("level", ""),
        "score":        v.get("score"),
        "label":        v.get("label", ""),
        "report_stage": str(getattr(result, "report_stage", "final") or "final"),
    }
    atomic_write_text(Path(output_dir) / "index.json", json.dumps(data, ensure_ascii=False, indent=2))


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
    """AnalysisResult → JSON 파일 저장 (원자적 교체) + 같은 폴더에 index.json"""
    verdict = _verdict_json(result)
    data = {
        "sample":    str(result.config.sample_path),
        "sample_sha256": str(getattr(result, "sample_sha256", "") or ""),
        "report_stage":  str(getattr(result, "report_stage", "final") or "final"),
        "verdict":       verdict,
        "sample_active": bool(getattr(result, "sample_active", True)),
        "inactivity_signals": [str(x) for x in (getattr(result, "inactivity_signals", None) or [])],
        "collection_status":  _collection_status_json(result),
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
        "evidence":           getattr(result, "evidence", None) or {},
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
                "evidence":  t.evidence,
                "sources":   t.sources,
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

        "network_scope": "전체 관찰 기록 — 샘플 귀속과 별개",
        "dns_attributed": _to_serializable(getattr(result, "dns_attributed", [])),
        "analysis_network": _to_serializable(getattr(result, "analysis_pcap", None)),
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

        "process_behaviors": _process_behaviors_json(getattr(result, "process_behaviors", None)),

        "events_summary": {
            "total":    len(result.procmon_events),
            "filtered": len(result.filtered_events),
        },

        "yara_scan": _build_yara_json(getattr(result, "yara_result", None)),
        "ai_analysis": _to_serializable(getattr(result, "ai_analysis", None)),
    }

    atomic_write_text(output_path, json.dumps(data, ensure_ascii=False, indent=2, default=str))
    try:
        write_index_json(result, Path(output_path).parent, verdict)
    except Exception:
        pass    # 목록용 요약 실패는 보고서 저장을 막지 않는다
