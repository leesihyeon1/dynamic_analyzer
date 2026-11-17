"""
evidence_collector.py — 악성 행위를 뒷받침하는 증적(Evidence) 수집·보존

동적 분석은 "무엇이 관찰됐는가"만큼 "그 근거 파일이 어디 있는가"가 중요하다.
이 모듈은 분석 종료 시점에

  1. 샘플 계보가 드롭한 파일을 결과 폴더(evidence/dropped/)로 복사해 보존하고
     (악성코드가 스스로 지우거나 VM 스냅샷 복원으로 사라지기 전에)
  2. 각 파일의 존재 여부·크기·SHA-256·기록한 프로세스를 정리한다.

리포트의 "증거" 탭(exporters/evidence_tab.py)이 이 결과와 결과 폴더의
원본 수집물(ProcMon CSV/PML, PCAP, 메모리 덤프 등)을 한곳에 묶어 보여준다.

외부 도구가 필요 없고, 실패해도 분석 전체를 중단시키지 않는다.
보존 사본에는 실수로 실행하지 않도록 ``.evd`` 확장자를 덧붙인다.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

# 한 번의 분석에서 보존할 파일 수·크기 상한 (결과 폴더가 비대해지는 것 방지)
MAX_FILES      = 60
MAX_FILE_BYTES = 64 * 1024 * 1024

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _writers_by_path(events, wanted: set) -> dict:
    """경로(소문자) → 그 파일을 쓴 "프로세스 (PID)" 목록."""
    out: dict = {}
    for ev in events or []:
        if getattr(ev, "operation", "") not in ("WriteFile", "CreateFile", "SetRenameInformationFile"):
            continue
        p = (getattr(ev, "path", "") or "").lower()
        if p not in wanted:
            continue
        label = f"{getattr(ev, 'process', '?')} ({getattr(ev, 'pid', '?')})"
        lst = out.setdefault(p, [])
        if label not in lst:
            lst.append(label)
    return out


def collect_evidence(result, output_dir: Path, status=None) -> dict:
    """드롭 파일을 보존하고 증적 메타데이터를 돌려준다.

    Returns
    -------
    dict
        {"dropped": [ {path, tier, exists, size, sha256, saved_as, writers, note}, ... ],
         "sample":  {path, sha256, size} | {},
         "dir":     "evidence"}
    """
    say = status or (lambda _m: None)
    output_dir = Path(output_dir)
    ev_dir = output_dir / "evidence" / "dropped"
    info: dict = {"dropped": [], "sample": {}, "dir": "evidence"}

    # 샘플 자체
    try:
        sp = getattr(getattr(result, "config", None), "sample_path", None)
        if sp and Path(sp).is_file():
            info["sample"] = {
                "path": str(sp), "size": Path(sp).stat().st_size, "sha256": _sha256(Path(sp)),
            }
    except Exception:
        pass

    ioc = getattr(result, "ioc_report", None)
    files = list(getattr(ioc, "dropped_files", None) or []) if ioc is not None else []
    tiers = getattr(ioc, "dropped_file_tiers", {}) or {}
    has_lineage = bool(getattr(result, "lineage_pids", None))

    # 계보(1)는 항상, 상관 의심(2)은 계보를 특정하지 못했을 때만 보존한다.
    # 계보가 있는데 Tier 2 까지 복사하면 브라우저 캐시 따위가 증거 폴더를 채운다.
    max_tier = 1 if has_lineage and any(t == 1 for t in tiers.values()) else 2
    picked = [f for f in files if tiers.get(str(f), 2) <= max_tier]
    picked.sort(key=lambda f: tiers.get(str(f), 2))
    sample_l = str(info["sample"].get("path", "")).lower()
    picked = [f for f in picked if str(f).lower() != sample_l][:MAX_FILES]

    writers = _writers_by_path(
        getattr(result, "filtered_events", None) or getattr(result, "procmon_events", None),
        {str(f).lower() for f in picked},
    )

    saved = 0
    for idx, f in enumerate(picked, 1):
        path = str(f)
        rec = {
            "path": path, "tier": tiers.get(path, 0), "exists": False, "size": 0,
            "sha256": "", "saved_as": "", "writers": writers.get(path.lower(), []), "note": "",
        }
        try:
            # NTFS ADS(파일:스트림) 는 복사 대상이 아니다 — 경로만 기록
            if ":" in path[2:]:
                rec["note"] = "대체 데이터 스트림(ADS) — 경로만 기록"
                info["dropped"].append(rec)
                continue
            src = Path(path)
            if not src.is_file():
                rec["note"] = "분석 종료 시점에 없음 (삭제·이동됨)"
                info["dropped"].append(rec)
                continue
            rec["exists"] = True
            rec["size"] = src.stat().st_size
            if rec["size"] > MAX_FILE_BYTES:
                rec["note"] = f"크기 상한({MAX_FILE_BYTES // (1024 * 1024)}MB) 초과 — 복사 생략"
                info["dropped"].append(rec)
                continue
            rec["sha256"] = _sha256(src)
            ev_dir.mkdir(parents=True, exist_ok=True)
            safe = _SAFE_NAME_RE.sub("_", src.name)[:80] or "file"
            dst = ev_dir / f"{idx:02d}_{rec['sha256'][:8]}_{safe}.evd"
            shutil.copyfile(src, dst)
            rec["saved_as"] = dst.relative_to(output_dir).as_posix()
            saved += 1
        except Exception as exc:  # 잠긴 파일·권한 문제 등 — 기록만 남기고 계속
            rec["note"] = f"보존 실패: {type(exc).__name__}"
        info["dropped"].append(rec)

    if info["dropped"]:
        say(f"[증거] 드롭 파일 {len(info['dropped'])}건 정리, {saved}건 보존 "
            f"→ {ev_dir}")
    return info
