"""
baseline.py — 환경 노이즈 베이스라인 수집 · 저장 · 차감

동적 분석 VM 은 샘플과 무관하게 끊임없이 배경 활동을 만든다.
Windows Update, Defender 서명 갱신, 텔레메트리, Conhost/wevtutil 스폰 등은
분석 세션마다 수백 개의 프로세스·파일·도메인을 리포트에 밀어 넣는다.

이 모듈은 "샘플 없이 한 번 공회전한 결과"를 베이스라인으로 저장해 두고,
이후 분석에서 같은 항목을 배경(Tier 3)으로 강등하는 데 쓴다.

수집:
    python analyzer.py --baseline-capture --timeout 600

사용 (자동):
    baseline/<hostname>.json 이 있으면 다음 분석부터 자동 적용

핵심은 경로 정규화다. Defender 임시 디렉터리
``C:\\Windows\\TEMP\\4C974312-7F7F-45BC-9CD3-7E72989C97BD\\`` 처럼 실행마다
GUID 가 바뀌는 경로는 원문 그대로 비교하면 절대 일치하지 않는다.
:func:`normalize_path` 로 변동 요소를 와일드카드로 치환한 뒤 비교한다.
"""
from __future__ import annotations

import json
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


BASELINE_VERSION = 1

# 베이스라인 신선도 — Defender 서명 버전·업데이트 대상이 계속 바뀌므로
# 오래된 베이스라인은 차감 효과가 떨어진다. 경고만 하고 사용은 허용.
DEFAULT_MAX_AGE_DAYS = 14


# ── 경로 정규화 ──────────────────────────────────────────────────────────────

_GUID_RE      = re.compile(
    r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?",
    re.IGNORECASE,
)
_USERDIR_RE   = re.compile(r"(?i)^([a-z]:\\users\\)[^\\]+", re.IGNORECASE)
_APPXTMP_RE   = re.compile(r"(?i)appx\.[0-9a-z_]{8,}\.tmp")
_TMPFILE_RE   = re.compile(r"(?i)\btmp[0-9a-f]{3,}\.tmp\b")
_LONGHEX_RE   = re.compile(r"(?i)\b[0-9a-f]{16,}\b")
_VERSION_RE   = re.compile(r"\b\d+\.\d+\.\d+[\.\d]*\b")
_DIGITRUN_RE  = re.compile(r"\b\d{5,}\b")


def _as_text(value) -> str:
    """문자열이 아닌 값(list/None 등)이 들어와도 안전하게 문자열로 만든다.

    pcap 파서의 ip_to_domain 처럼 IP 하나에 도메인 리스트가 매달린 필드가
    있어, 호출부에서 타입을 잘못 넘겨도 정규화 함수가 죽지 않도록 방어한다.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        for v in value:                      # 첫 번째 유효 항목만 사용
            s = _as_text(v)
            if s:
                return s
        return ""
    return str(value)


def normalize_path(path: str) -> str:
    """실행마다 달라지는 요소를 와일드카드로 치환한 비교용 경로를 만든다.

    치환 대상:
      * 사용자 디렉터리명      ``c:\\users\\user\\``  → ``c:\\users\\*\\``
      * GUID                   ``{4C97...}``          → ``*``
      * AppX 임시 파일         ``appx.xk3f9.tmp``     → ``appx.*.tmp``
      * 임시 파일              ``tmp2eb0.tmp``        → ``tmp*.tmp``
      * 긴 16진 문자열(해시)   ``fd97eadc6059...``    → ``*``
      * 버전 번호              ``4.18.26070.9``       → ``*``
      * 5자리 이상 숫자        ``45861975``           → ``*``
    """
    path = _as_text(path)
    if not path:
        return ""
    p = path.strip().lower().replace("/", "\\")
    p = _USERDIR_RE.sub(r"\1*", p)
    p = _GUID_RE.sub("*", p)
    p = _APPXTMP_RE.sub("appx.*.tmp", p)
    p = _TMPFILE_RE.sub("tmp*.tmp", p)
    p = _LONGHEX_RE.sub("*", p)
    p = _VERSION_RE.sub("*", p)
    p = _DIGITRUN_RE.sub("*", p)
    return p


def normalize_domain(domain: str) -> str:
    return _as_text(domain).strip().lower().rstrip(".")


# ── 데이터 모델 ──────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    """샘플 없이 관측된 환경 배경 활동 프로파일."""

    version:       int   = BASELINE_VERSION
    captured_at:   float = 0.0            # unix timestamp
    host:          str   = ""
    duration_sec:  float = 0.0
    sample_note:   str   = ""             # 수집 조건 메모

    process_names: set   = field(default_factory=set)   # "conhost.exe"
    exe_paths:     set   = field(default_factory=set)   # normalize_path 적용
    file_paths:    set   = field(default_factory=set)   # normalize_path 적용
    domains:       set   = field(default_factory=set)
    dst_ips:       set   = field(default_factory=set)
    endpoints:     set   = field(default_factory=set)   # "1.2.3.4:443"
    registry_keys: set   = field(default_factory=set)
    # 샘플 없이도 hollows-hunter / pe-sieve 가 주입으로 탐지한 프로세스.
    # dwm.exe·explorer.exe·SearchApp.exe 처럼 .NET JIT·ASLR 재배치 영역을
    # 상시 오탐당하는 프로세스가 여기 쌓인다. 이후 분석에서 차감한다.
    injection_procs: set = field(default_factory=set)

    # ── 조회 ────────────────────────────────────────────────────────
    def has_process(self, name: str) -> bool:
        return (name or "").lower() in self.process_names

    def has_exe(self, exe: str) -> bool:
        return normalize_path(exe) in self.exe_paths if exe else False

    def has_file(self, path: str) -> bool:
        return normalize_path(path) in self.file_paths if path else False

    def has_domain(self, domain: str) -> bool:
        return normalize_domain(domain) in self.domains if domain else False

    def has_endpoint(self, ip: str, port: int = 0) -> bool:
        if not ip:
            return False
        if port and f"{ip}:{port}" in self.endpoints:
            return True
        return ip in self.dst_ips

    def has_registry(self, key: str) -> bool:
        return (key or "").lower() in self.registry_keys

    def has_injection_fp(self, proc_name: str) -> bool:
        """샘플 없이도 주입으로 탐지되던 프로세스면 True (환경 상시 오탐)."""
        return (proc_name or "").lower() in self.injection_procs

    @property
    def age_days(self) -> float:
        if not self.captured_at:
            return 0.0
        return (time.time() - self.captured_at) / 86400.0

    def is_stale(self, max_age_days: float = DEFAULT_MAX_AGE_DAYS) -> bool:
        return self.age_days > max_age_days

    def item_count(self) -> int:
        return (
            len(self.process_names) + len(self.exe_paths) + len(self.file_paths)
            + len(self.domains) + len(self.dst_ips) + len(self.endpoints)
            + len(self.registry_keys) + len(self.injection_procs)
        )

    def summary(self) -> str:
        return (
            f"프로세스 {len(self.process_names)} · 실행경로 {len(self.exe_paths)} · "
            f"파일 {len(self.file_paths)} · 도메인 {len(self.domains)} · "
            f"IP {len(self.dst_ips)} · 레지스트리 {len(self.registry_keys)} · "
            f"주입오탐 {len(self.injection_procs)}"
        )


# ── 수집 ─────────────────────────────────────────────────────────────────────

def capture_baseline(result, note: str = "") -> Baseline:
    """AnalysisResult(샘플 없이 실행한 결과) → Baseline.

    샘플을 지정하고 실행한 결과를 넘겨도 동작하지만, 그 경우 악성 활동까지
    베이스라인에 섞이므로 ``--baseline-capture`` 로 수집한 결과만 쓸 것.
    """
    bl = Baseline(
        captured_at  = time.time(),
        host         = socket.gethostname(),
        duration_sec = float(getattr(result, "duration", 0.0) or 0.0),
        sample_note  = note,
    )

    # 프로세스
    for p in (getattr(result, "process_diff", {}) or {}).get("new_processes", []):
        name = (getattr(p, "name", "") or "").lower()
        if name:
            bl.process_names.add(name)
        exe = getattr(p, "exe", "") or ""
        if exe:
            bl.exe_paths.add(normalize_path(exe))

    # 드롭 파일 / IOC
    iocs = getattr(result, "ioc_report", None)
    if iocs is not None:
        for f in (getattr(iocs, "dropped_files", []) or []):
            path = f if isinstance(f, str) else getattr(f, "path", "")
            if path:
                bl.file_paths.add(normalize_path(path))
        for d in (getattr(iocs, "domains", []) or []):
            bl.domains.add(normalize_domain(d))
        for ip in (getattr(iocs, "ip_addresses", []) or []):
            if ip:
                bl.dst_ips.add(ip)

    # 네트워크
    pcap = getattr(result, "pcap_result", None)
    if pcap is not None:
        for c in (getattr(pcap, "connections", []) or []):
            ip   = getattr(c, "dst_ip", "")
            port = getattr(c, "dst_port", 0)
            if ip:
                bl.dst_ips.add(ip)
                if port:
                    bl.endpoints.add(f"{ip}:{port}")
        for q in (getattr(pcap, "dns_queries", []) or []):
            name = normalize_domain(getattr(q, "name", ""))
            if name:
                bl.domains.add(name)
        for h in (getattr(pcap, "http_requests", []) or []):
            host = normalize_domain(getattr(h, "host", ""))
            if host:
                bl.domains.add(host)
        for t in (getattr(pcap, "tls_info", []) or []):
            sni = normalize_domain(getattr(t, "sni", ""))
            if sni:
                bl.domains.add(sni)

    # 주입 스캐너 상시 오탐 프로세스
    _hh = getattr(result, "hh_result", None)
    if _hh is not None and not getattr(_hh, "error", ""):
        for r in (getattr(_hh, "process_results", []) or []):
            if getattr(r, "suspicious", 0) > 0:
                nm = (getattr(r, "name", "") or "").lower()
                if nm:
                    bl.injection_procs.add(nm)
    for r in (getattr(result, "pe_sieve_results", []) or []):
        if not getattr(r, "error", "") and getattr(r, "suspicious", 0) > 0:
            nm = (getattr(r, "name", "") or "").lower()
            if nm:
                bl.injection_procs.add(nm)

    # 레지스트리
    reg = getattr(result, "registry_diff", {}) or {}
    for bucket in ("added", "modified", "deleted"):
        for entry in (reg.get(bucket) or []):
            key = entry if isinstance(entry, str) else getattr(entry, "key", "")
            if key:
                bl.registry_keys.add(key.lower())

    return bl


# ── 직렬화 ───────────────────────────────────────────────────────────────────

_SET_FIELDS = (
    "process_names", "exe_paths", "file_paths",
    "domains", "dst_ips", "endpoints", "registry_keys",
    "injection_procs",
)


def baseline_to_dict(bl: Baseline) -> dict:
    d = {
        "version":      bl.version,
        "captured_at":  bl.captured_at,
        "host":         bl.host,
        "duration_sec": bl.duration_sec,
        "sample_note":  bl.sample_note,
    }
    for f in _SET_FIELDS:
        d[f] = sorted(getattr(bl, f))
    return d


def baseline_from_dict(d: dict) -> Baseline:
    bl = Baseline(
        version      = int(d.get("version", 0) or 0),
        captured_at  = float(d.get("captured_at", 0.0) or 0.0),
        host         = d.get("host", "") or "",
        duration_sec = float(d.get("duration_sec", 0.0) or 0.0),
        sample_note  = d.get("sample_note", "") or "",
    )
    for f in _SET_FIELDS:
        setattr(bl, f, set(d.get(f) or []))
    return bl


def default_baseline_dir() -> Path:
    """프로젝트 루트의 baseline/ 디렉터리."""
    return Path(__file__).parent.parent / "baseline"


def default_baseline_path(host: str = "") -> Path:
    """호스트별 기본 베이스라인 경로 (VM 마다 배경 활동이 다르므로 분리)."""
    h = (host or socket.gethostname() or "default").lower()
    h = re.sub(r"[^a-z0-9_.-]", "_", h)
    return default_baseline_dir() / f"{h}.json"


def save_baseline(bl: Baseline, path: Optional[str | Path] = None) -> Path:
    p = Path(path) if path else default_baseline_path(bl.host)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(baseline_to_dict(bl), f, ensure_ascii=False, indent=2)
    return p


def load_baseline(path: Optional[str | Path] = None) -> Optional[Baseline]:
    """베이스라인을 로드한다. 없거나 파싱 실패 시 None."""
    p = Path(path) if path else default_baseline_path()
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if int(data.get("version", 0) or 0) != BASELINE_VERSION:
        return None
    return baseline_from_dict(data)
