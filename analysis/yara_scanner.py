"""YARA rule scanning for malware samples.

Loads all .yar / .yara files from ``rules/yaraify/`` (539 community rules
from YARAify / YARAhub) and scans the sample + any dropped files.

Falls back gracefully when yara-python is not installed::

    pip install yara-python

Exported names
--------------
YaraMatch       – single rule hit against one file
YaraScanResult  – aggregated scan results
run_yara_scan   – public entry point
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default rules directory: <project_root>/rules/yaraify/
_RULES_DIR: Path = Path(__file__).parent.parent / "rules" / "yaraify"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """A single YARA rule hit against one file."""
    rule_name:       str
    file_scanned:    str                           # absolute path scanned
    meta:            dict  = field(default_factory=dict)   # rule meta (description, author…)
    tags:            list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)  # identifiers, e.g. ["$s1"]


@dataclass
class YaraScanResult:
    """Aggregated results for one analysis run."""
    matches:       list[YaraMatch] = field(default_factory=list)
    files_scanned: list[str]       = field(default_factory=list)
    rules_loaded:  int  = 0
    rules_failed:  int  = 0
    available:     bool = False       # False → yara-python not installed
    error:         Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_filepath_dict(rules_dir: Path) -> dict[str, str]:
    """Return {unique_namespace: filepath_str} for every rule file."""
    rule_files = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
    filepath_dict: dict[str, str] = {}
    seen: set[str] = set()
    for rf in rule_files:
        ns = rf.stem.replace("-", "_").replace(" ", "_").replace(".", "_")
        base, n = ns, 1
        while ns in seen:
            ns = f"{base}_{n}"
            n += 1
        seen.add(ns)
        filepath_dict[ns] = str(rf)
    return filepath_dict


def _load_compiled_rules(rules_dir: Path):
    """Compile rules; return (compiled | None, loaded_count, failed_count)."""
    try:
        import yara
    except ImportError:
        return None, 0, 0

    if not rules_dir.exists():
        return None, 0, 0

    filepath_dict = _build_filepath_dict(rules_dir)
    if not filepath_dict:
        return None, 0, 0

    # ── Fast path: batch compile all at once ────────────────────
    try:
        compiled = yara.compile(filepaths=filepath_dict)
        return compiled, len(filepath_dict), 0
    except Exception:
        pass

    # ── Fallback: compile individually, drop broken rules ───────
    good: dict[str, str] = {}
    failed = 0
    for ns, fp in filepath_dict.items():
        try:
            yara.compile(filepath=fp)
            good[ns] = fp
        except Exception as exc:
            logger.debug("YARA: skipping %s — %s", Path(fp).name, exc)
            failed += 1

    if not good:
        return None, 0, failed

    try:
        compiled = yara.compile(filepaths=good)
        return compiled, len(good), failed
    except Exception as exc:
        logger.error("YARA: batch compile of good rules failed — %s", exc)
        return None, 0, len(filepath_dict)


def _scan_single(compiled, path: Path, timeout: int = 60) -> list[YaraMatch]:
    """Scan *path* with pre-compiled rules; return matches."""
    try:
        import yara
    except ImportError:
        return []

    if not path.exists() or not path.is_file():
        return []

    try:
        raw = compiled.match(str(path), timeout=timeout)
    except Exception as exc:
        logger.warning("YARA: scan error on %s — %s", path.name, exc)
        return []

    results: list[YaraMatch] = []
    for m in raw:
        # Extract matched string identifiers — compatible with yara-python 3.x & 4.x
        identifiers: list[str] = []
        try:
            for s in m.strings:
                if hasattr(s, "identifier"):          # 4.x StringMatch object
                    identifiers.append(s.identifier)
                elif isinstance(s, tuple) and len(s) >= 2:  # 3.x tuple
                    identifiers.append(str(s[1]))
        except Exception:
            pass

        results.append(YaraMatch(
            rule_name=m.rule,
            file_scanned=str(path),
            meta=dict(m.meta) if hasattr(m, "meta") else {},
            tags=list(m.tags) if hasattr(m, "tags") else [],
            matched_strings=list(dict.fromkeys(identifiers)),  # deduplicate, keep order
        ))
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_yara_scan(
    sample_path: Optional[Path],
    dropped_files: list[str],
    rules_dir: Optional[Path] = None,
) -> YaraScanResult:
    """Scan *sample_path* and *dropped_files* with all YARAify community rules.

    Parameters
    ----------
    sample_path:
        Primary analysis target; ``None`` in system-monitoring mode.
    dropped_files:
        File paths from :attr:`IOCReport.dropped_files`.
    rules_dir:
        Custom rules directory.  Defaults to ``<project>/rules/yaraify/``.

    Returns
    -------
    YaraScanResult
        If yara-python is not installed, ``available=False`` and ``error``
        explains how to install it.
    """
    result = YaraScanResult()

    # ── Availability check ──────────────────────────────────────
    try:
        import yara as _  # noqa: F401
        result.available = True
    except ImportError:
        result.error = "yara-python 미설치 → pip install yara-python"
        return result

    _dir = rules_dir or _RULES_DIR
    if not _dir.exists():
        result.error = f"YARA 룰 디렉터리 없음: {_dir}"
        return result

    # ── Compile ─────────────────────────────────────────────────
    compiled, loaded, failed = _load_compiled_rules(_dir)
    result.rules_loaded = loaded
    result.rules_failed = failed

    if compiled is None:
        result.error = f"컴파일 성공 룰 없음 (실패 {failed}개)"
        return result

    # ── Scan targets ────────────────────────────────────────────
    targets: list[Path] = []
    if sample_path and sample_path.exists():
        targets.append(sample_path.resolve())
    for fp in dropped_files:
        p = Path(fp).resolve()
        if p.exists() and p not in targets:
            targets.append(p)

    for target in targets:
        result.files_scanned.append(str(target))
        hits = _scan_single(compiled, target)
        result.matches.extend(hits)

    return result
