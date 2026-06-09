"""
injection_classifier.py - 프로세스 인젝션 / 쉘코드 분류 및 MITRE ATT&CK 매핑.

pe-sieve / hollows-hunter 결과를 받아 탐지된 인젝션 기법을 분류하고
BehaviorReport 구조에 통합한다.

MITRE ATT&CK 매핑
-----------------
  T1055       Process Injection (parent)
  T1055.001   Dynamic-link Library Injection
  T1055.002   Portable Executable Injection
  T1055.004   Asynchronous Procedure Call
  T1055.012   Process Hollowing
  T1620       Reflective Code Loading
  T1027.007   Dynamic API Resolution  (shellcode 전형 패턴)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from parsers.pesieve_result import (
    PeSieveResult,
    HollowsHunterResult,
    InjectedModule,
    classify_dump_files,
)
from analysis.behavior_classifier import (
    BehaviorReport,
    MitreTechnique,
    _add_evidence,   # 내부 헬퍼 재사용
)


# ---------------------------------------------------------------------------
# 인젝션 유형 결정 로직
# ---------------------------------------------------------------------------

def _classify_module(mod: InjectedModule) -> tuple[str, str, str, str]:
    """
    단일 InjectedModule에서 MITRE 기법 추론.

    Returns (technique_id, technique_name, tactic, reference)
    """
    if mod.is_shellcode or mod.implanted_count > 0 and not mod.dump_file.lower().endswith(".exe"):
        # 비-PE RX 메모리 → 쉘코드 인젝션
        return (
            "T1055",
            "Process Injection (Shellcode)",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1055/",
        )

    if mod.replaced > 0 if hasattr(mod, "replaced") else False:
        # 모듈 교체 → Process Hollowing 가능성
        return (
            "T1055.012",
            "Process Hollowing",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1055/012/",
        )

    if mod.patches_count > 0:
        # IAT / inline hook
        return (
            "T1055",
            "Process Injection (Hook / Patch)",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1055/",
        )

    if mod.implanted_pe > 0 if hasattr(mod, "implanted_pe") else mod.implanted_count > 0:
        # PE 삽입
        return (
            "T1055.002",
            "Portable Executable Injection",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1055/002/",
        )

    # 기본
    return (
        "T1055",
        "Process Injection",
        "Defense Evasion",
        "https://attack.mitre.org/techniques/T1055/",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_injections(
    pe_result: PeSieveResult | None = None,
    hh_result: HollowsHunterResult | None = None,
    report: BehaviorReport | None = None,
) -> BehaviorReport:
    """
    pe-sieve / hollows-hunter 결과를 BehaviorReport에 병합.

    Parameters
    ----------
    pe_result:
        단일 PID 스캔 결과 (PeSieveScanner.scan_pid() 반환값 파싱 결과).
    hh_result:
        전체 시스템 스캔 결과 (HollowsHunter.scan_all() 반환값 파싱 결과).
    report:
        기존 BehaviorReport. None이면 새로 생성.

    Returns
    -------
    BehaviorReport
        인젝션 기법이 추가된 보고서.
    """
    if report is None:
        report = BehaviorReport()

    technique_map: dict[str, MitreTechnique] = {
        t.technique_id: t for t in report.techniques
    }

    # ── 단일 PID 결과 처리 ──────────────────────────────────────
    results_to_process: list[PeSieveResult] = []
    if pe_result and not pe_result.error:
        results_to_process.append(pe_result)

    # ── hollows-hunter 전체 결과 처리 ───────────────────────────
    if hh_result and not hh_result.error:
        results_to_process.extend(hh_result.suspicious_processes)

    for res in results_to_process:
        if not res.modules:
            continue

        for mod in res.modules:
            tid, tname, tactic, ref = _classify_module(mod)
            evidence = (
                f"PID {res.pid} | "
                f"{Path(mod.module_path).name} | "
                + (f"덤프: {Path(mod.dump_file).name}" if mod.dump_file else "덤프 없음")
            )
            _add_evidence(technique_map, tid, tname, tactic,
                          evidence=evidence, reference=ref)

            if mod.dump_file:
                report.suspicious_files.append(mod.dump_file)

        # 쉘코드 카운트가 있으면 Reflective Code Loading도 추가
        if res.implanted_shc > 0:
            _add_evidence(
                technique_map,
                "T1620",
                "Reflective Code Loading",
                "Defense Evasion",
                evidence=f"PID {res.pid}: shellcode region {res.implanted_shc}개",
                reference="https://attack.mitre.org/techniques/T1620/",
            )

    # technique_map을 report에 반영
    existing_ids = {t.technique_id for t in report.techniques}
    for tid, tech in technique_map.items():
        if tid not in existing_ids:
            report.techniques.append(tech)
        else:
            # 기존 항목 증거 업데이트
            for t in report.techniques:
                if t.technique_id == tid:
                    for ev in tech.evidence:
                        if ev not in t.evidence:
                            t.evidence.append(ev)
                    break

    return report


@dataclass
class ShellcodeInfo:
    """덤프된 쉘코드 파일 정보."""
    path:     Path
    size:     int
    pid:      int
    sha256:   str = ""
    is_pe:    bool = False


def summarise_dumps(
    pe_result: PeSieveResult | None = None,
    hh_result: HollowsHunterResult | None = None,
) -> list[ShellcodeInfo]:
    """
    스캔 결과에서 덤프된 파일 목록을 ShellcodeInfo 리스트로 반환.
    PE / 쉘코드 구분 포함.
    """
    import hashlib

    infos: list[ShellcodeInfo] = []
    results: list[PeSieveResult] = []

    if pe_result and not pe_result.error:
        results.append(pe_result)
    if hh_result and not hh_result.error:
        results.extend(hh_result.suspicious_processes)

    for res in results:
        for mod in res.modules:
            if not mod.dump_file:
                continue
            p = Path(mod.dump_file)
            if not p.exists():
                continue
            try:
                data   = p.read_bytes()
                sha256 = hashlib.sha256(data).hexdigest()
                is_pe  = data[:2] == b"MZ"
            except Exception:
                sha256 = ""
                is_pe  = False
            infos.append(ShellcodeInfo(
                path   = p,
                size   = p.stat().st_size,
                pid    = res.pid,
                sha256 = sha256,
                is_pe  = is_pe,
            ))

    return infos
