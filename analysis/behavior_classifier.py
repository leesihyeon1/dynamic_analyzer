"""Classify malware behaviors and map them to MITRE ATT&CK techniques.

Given filtered ProcMon events, a PcapResult, a registry diff, and a process
diff, this module produces a :class:`BehaviorReport` containing identified
MITRE ATT&CK techniques sorted by tactic priority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from parsers.procmon_csv import ProcMonEvent, EventCategory
from parsers.pcap_parser import PcapResult


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    """A MITRE ATT&CK technique identified during analysis."""

    technique_id:   str                # e.g. "T1547.001"
    technique_name: str                # e.g. "Registry Run Keys / Startup Folder"
    tactic:         str                # e.g. "Persistence"
    evidence:       list[str] = field(default_factory=list)   # supporting paths/details
    reference:      str = ""           # https://attack.mitre.org/techniques/…
    sources:        list[str] = field(default_factory=list)   # e.g. ["로컬룰", "CAPA", "VirusTotal"]


@dataclass
class BehaviorReport:
    """Aggregated classification results for a malware sample."""

    techniques:          list[MitreTechnique] = field(default_factory=list)
    suspicious_files:    list[str]            = field(default_factory=list)
    suspicious_registry: list[str]            = field(default_factory=list)
    suspicious_network:  list[str]            = field(default_factory=list)
    suspicious_processes:list[str]            = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tactic ordering
# ---------------------------------------------------------------------------

_TACTIC_ORDER: dict[str, int] = {
    "Execution":         0,
    "Persistence":       1,
    "Defense Evasion":   2,
    "Command and Control": 3,
    "Exfiltration":      4,
    "Impact":            5,
}


def _tactic_key(technique: MitreTechnique) -> int:
    return _TACTIC_ORDER.get(technique.tactic, 99)


# ---------------------------------------------------------------------------
# Pattern matchers – file events
# ---------------------------------------------------------------------------

# Paths that suggest startup / run-key persistence via the filesystem
_STARTUP_PATH_FRAGMENTS: tuple[str, ...] = (
    r"\currentversion\run",
    r"\startup",
    r"\start menu\programs\startup",
    r"\appdata\roaming\microsoft\windows\start menu\programs\startup",
)

_TEMP_EXEC_EXTENSIONS: frozenset[str] = frozenset({".exe", ".dll", ".bat"})
_APPDATA_TEMP_FRAGMENTS: tuple[str, ...] = (r"\appdata\\", r"\temp\\")

_RANSOMWARE_EXTENSIONS: frozenset[str] = frozenset(
    {".locked", ".encrypted", ".crypt", ".enc", ".zzz", ".zepto"}
)

_WRITE_CREATE_OPS: frozenset[str] = frozenset({"WriteFile", "CreateFile"})


def _file_extension(path: str) -> str:
    """Return the lowercased file extension from *path*, including the dot."""
    dot = path.rfind(".")
    slash = max(path.rfind("\\"), path.rfind("/"))
    if dot > slash:
        return path[dot:].lower()
    return ""


def _classify_file_events(
    events: list[ProcMonEvent],
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Detect file-system-based techniques."""
    for ev in events:
        if ev.category != EventCategory.FILE:
            continue

        op    = ev.operation
        path  = ev.path
        lower = path.lower()
        ext   = _file_extension(path)

        # T1547.001 – startup/run-key file placement
        if op in _WRITE_CREATE_OPS:
            if any(frag in lower for frag in _STARTUP_PATH_FRAGMENTS):
                _add_evidence(
                    technique_map,
                    technique_id="T1547.001",
                    technique_name="Registry Run Keys / Startup Folder",
                    tactic="Persistence",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1547/001/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)

        # T1027 – executable/script dropped in AppData or Temp
        if op in _WRITE_CREATE_OPS:
            if ext in _TEMP_EXEC_EXTENSIONS and any(
                frag in lower for frag in _APPDATA_TEMP_FRAGMENTS
            ):
                _add_evidence(
                    technique_map,
                    technique_id="T1027",
                    technique_name="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1027/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)

        # T1486 – ransomware-style file extension
        if op == "WriteFile" and ext in _RANSOMWARE_EXTENSIONS:
            _add_evidence(
                technique_map,
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="Impact",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1486/",
                process=ev.process,
            )
            report.suspicious_files.append(path)

        # T1070.004 – self-deletion
        if op == "DeleteFile":
            # Heuristic: the process name appears in the deleted path
            proc_stem = ev.process.lower().replace(".exe", "")
            if proc_stem and proc_stem in lower:
                _add_evidence(
                    technique_map,
                    technique_id="T1070.004",
                    technique_name="File Deletion",
                    tactic="Defense Evasion",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1070/004/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)


# ---------------------------------------------------------------------------
# Pattern matchers – registry events
# ---------------------------------------------------------------------------

_REG_RUN_KEYS: tuple[str, ...] = (
    r"\currentversion\run",
    r"\currentversion\runonce",
)


def _classify_registry_events(
    events: list[ProcMonEvent],
    reg_diff: dict,
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Detect registry-based persistence techniques from events and reg_diff."""

    def _check_reg_path(path: str, detail: str = "", process: str = "") -> None:
        lower = path.lower()
        det   = detail.lower()

        if any(frag in lower for frag in _REG_RUN_KEYS):
            _add_evidence(
                technique_map,
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1547/001/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if r"\services\\" in lower:
            _add_evidence(
                technique_map,
                "T1543.003",
                "Windows Service",
                "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1543/003/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "winlogon" in lower and ("userinit" in det or "shell" in det):
            _add_evidence(
                technique_map,
                "T1547.004",
                "Winlogon Helper DLL",
                "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1547/004/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "appinit_dlls" in lower:
            _add_evidence(
                technique_map,
                "T1546.010",
                "AppInit DLLs",
                "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/010/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "image file execution options" in lower and "debugger" in det:
            _add_evidence(
                technique_map,
                "T1546.012",
                "Image File Execution Options Injection",
                "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/012/",
                process=process,
            )
            report.suspicious_registry.append(path)

    # Events — ev.process 를 _check_reg_path 에 전달
    for ev in events:
        if ev.category == EventCategory.REGISTRY and ev.operation == "RegSetValue":
            _check_reg_path(ev.path, ev.detail, process=ev.process)

    # reg_diff["added"] — 프로세스 정보 없음 (Regshot 스냅샷 기반)
    for entry in reg_diff.get("added", []):
        try:
            if isinstance(entry, dict):
                path   = entry.get("path", "")
                detail = entry.get("detail", "") or entry.get("name", "")
            else:
                path   = str(entry)
                detail = ""
            _check_reg_path(path, detail)
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Pattern matchers – process events
# ---------------------------------------------------------------------------

_PROC_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # (fragment, technique_id, technique_name, tactic, reference)
    (
        "cmd.exe", "T1059.003", "Windows Command Shell", "Execution",
        "https://attack.mitre.org/techniques/T1059/003/",
    ),
    (
        "powershell.exe", "T1059.001", "PowerShell", "Execution",
        "https://attack.mitre.org/techniques/T1059/001/",
    ),
    (
        "wscript.exe", "T1059.005", "Visual Basic", "Execution",
        "https://attack.mitre.org/techniques/T1059/005/",
    ),
    (
        "cscript.exe", "T1059.005", "Visual Basic", "Execution",
        "https://attack.mitre.org/techniques/T1059/005/",
    ),
    (
        "rundll32.exe", "T1218.011", "Rundll32", "Defense Evasion",
        "https://attack.mitre.org/techniques/T1218/011/",
    ),
    (
        "regsvr32.exe", "T1218.010", "Regsvr32", "Defense Evasion",
        "https://attack.mitre.org/techniques/T1218/010/",
    ),
]

_APPDATA_TEMP_PROC_FRAGS: tuple[str, ...] = (r"\appdata\\", r"\temp\\")


def _classify_process_events(
    events: list[ProcMonEvent],
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Detect process-spawning / LOLBin techniques."""
    for ev in events:
        if ev.category != EventCategory.PROCESS:
            continue
        if ev.operation != "Process Create":
            continue

        detail_lower = ev.detail.lower()
        path_lower   = ev.path.lower()

        # vssadmin delete shadows
        if "vssadmin" in detail_lower and "delete" in detail_lower:
            _add_evidence(
                technique_map,
                "T1490",
                "Inhibit System Recovery",
                "Impact",
                evidence=ev.detail,
                reference="https://attack.mitre.org/techniques/T1490/",
                process=ev.process,
            )
            report.suspicious_processes.append(ev.detail)

        # Known LOLBins / scripting interpreters
        for frag, tid, tname, tactic, ref in _PROC_PATTERNS:
            if frag in detail_lower or frag in path_lower:
                _add_evidence(
                    technique_map,
                    tid, tname, tactic,
                    evidence=ev.detail or ev.path,
                    reference=ref,
                    process=ev.process,
                )
                report.suspicious_processes.append(ev.detail or ev.path)
                break  # only match the first pattern per event

        # Process launched from AppData / Temp
        if any(frag in detail_lower for frag in _APPDATA_TEMP_PROC_FRAGS):
            _add_evidence(
                technique_map,
                "T1059",
                "Command and Scripting Interpreter",
                "Execution",
                evidence=ev.detail,
                reference="https://attack.mitre.org/techniques/T1059/",
                process=ev.process,
            )
            report.suspicious_processes.append(ev.detail)


# ---------------------------------------------------------------------------
# Pattern matchers – network (pcap)
# ---------------------------------------------------------------------------

# mDNS / LLMNR / SSDP 멀티캐스트 주소 — C2 오탐 방지
_MULTICAST_IPS: frozenset[str] = frozenset({
    "224.0.0.252",      # LLMNR (T1095 오탐 원인)
    "224.0.0.251",      # mDNS
    "239.255.255.250",  # SSDP
    "ff02::fb",         # mDNS IPv6
    "ff02::1:3",        # LLMNR IPv6
    "ff02::2",          # All-routers
    "ff02::16",         # MLDv2
})

# 분석 도구 / 위협인텔 서비스 — MITRE 귀속에서 제외
# (pcap_parser.py 의 _is_analysis_service_domain 과 동기화 유지)
_ANALYSIS_SERVICE_SUFFIXES_BC: tuple[str, ...] = (
    "abuse.ch",
    "virustotal.com",
    "alienvault.com",
    "shodan.io",
    "system-informer.com",
    "github.com",
    "githubusercontent.com",
    "phantom.app",
    "metamask.io",
    "xdefi.services",
)


def _is_analysis_domain_bc(domain: str) -> bool:
    """분석 도구·위협인텔 서비스 도메인이면 True.

    T1071.001 / T1071.004 귀속 전에 호출해 오탐을 방지합니다.
    """
    d = domain.lower().rstrip(".")
    for suffix in _ANALYSIS_SERVICE_SUFFIXES_BC:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local addresses."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 169 and b == 254:
            return True
    except (ValueError, AttributeError):
        pass
    return False


def _classify_network(
    pcap: PcapResult,
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Map network observations to MITRE C2 / exfiltration techniques."""

    # TCP/UDP 연결
    for conn in pcap.connections:
        if _is_private_ip(conn.dst_ip):
            continue
        # mDNS / LLMNR 멀티캐스트 — 정상 OS 동작, C2 아님
        if conn.dst_ip in _MULTICAST_IPS:
            continue
        # 분석 서비스 IP 체크 — DNS A 레코드 역참조로 판별
        if any(_is_analysis_domain_bc(d)
               for d in pcap.ip_to_domain.get(conn.dst_ip, [])):
            continue

        evidence = f"{conn.dst_ip}:{conn.dst_port}"

        if conn.dst_port in (80, 8080):
            _add_evidence(technique_map, "T1071.001", "Web Protocols",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
        elif conn.dst_port in (443, 8443):
            _add_evidence(technique_map, "T1071.001", "Web Protocols (HTTPS)",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
        else:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1095/")

        # 의심 포트
        if conn.suspicious_port:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol (의심 포트)",
                          "Command and Control",
                          evidence=f"{conn.dst_ip}:{conn.dst_port} [{conn.proto}]",
                          reference="https://attack.mitre.org/techniques/T1095/")

        report.suspicious_network.append(evidence)

    # TLS SNI → HTTPS C2 도메인 탐지 (분석 서비스 도메인 제외)
    seen_sni: set[str] = set()
    for tls in pcap.tls_info:
        if tls.sni and tls.sni not in seen_sni:
            if _is_analysis_domain_bc(tls.sni):
                continue  # 분석 도구 통신 — 제외
            seen_sni.add(tls.sni)
            _add_evidence(technique_map, "T1071.001",
                          "Web Protocols (TLS SNI)",
                          "Command and Control",
                          evidence=f"SNI={tls.sni} → {tls.dst_ip}:{tls.dst_port}",
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            report.suspicious_network.append(f"TLS SNI: {tls.sni}")

    # DNS 쿼리 (분석 서비스 도메인 제외 — PTR 레코드는 pcap_parser에서 이미 제거)
    for q in pcap.dns_queries:
        if _is_analysis_domain_bc(q.name):
            continue  # 분석 도구 DNS 조회 — 제외
        _add_evidence(technique_map, "T1071.004", "DNS",
                      "Command and Control", evidence=q.name,
                      reference="https://attack.mitre.org/techniques/T1071/004/")

    # DGA 의심 도메인
    if pcap.suspicious_domains:
        for domain in pcap.suspicious_domains:
            _add_evidence(technique_map, "T1568.002",
                          "Domain Generation Algorithms",
                          "Command and Control",
                          evidence=f"고엔트로피 도메인: {domain}",
                          reference="https://attack.mitre.org/techniques/T1568/002/")
            report.suspicious_network.append(f"DGA 의심: {domain}")

    # DNS 터널링 의심
    if pcap.dns_tunnel_suspects:
        for base in pcap.dns_tunnel_suspects:
            _add_evidence(technique_map, "T1071.004",
                          "DNS (터널링 의심)",
                          "Command and Control",
                          evidence=f"다수 서브도메인 쿼리: {base}",
                          reference="https://attack.mitre.org/techniques/T1071/004/")
            report.suspicious_network.append(f"DNS 터널링 의심: {base}")

    # 비콘 탐지 → C2 주기적 통신
    if pcap.beacon_candidates:
        for bc in pcap.beacon_candidates:
            _add_evidence(technique_map, "T1071.001",
                          "Web Protocols (Beaconing)",
                          "Command and Control",
                          evidence=(f"비콘 {bc.dst_ip}:{bc.dst_port} "
                                    f"— {bc.count}회, 평균 {bc.interval_avg}s, "
                                    f"지터 {bc.jitter_ratio:.1%}"),
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            report.suspicious_network.append(
                f"비콘: {bc.dst_ip}:{bc.dst_port} ({bc.count}회, ~{bc.interval_avg}s 간격)")

    # 데이터 유출 (외부 IP + 대용량 전송)
    external_ips = {c.dst_ip for c in pcap.connections if not _is_private_ip(c.dst_ip)}
    large_transfers = [c for c in pcap.connections
                       if not _is_private_ip(c.dst_ip) and c.bytes_out > 100_000]
    if external_ips:
        _add_evidence(technique_map, "T1041",
                      "Exfiltration Over C2 Channel",
                      "Exfiltration",
                      evidence=", ".join(sorted(external_ips)),
                      reference="https://attack.mitre.org/techniques/T1041/")
    for c in large_transfers:
        report.suspicious_network.append(
            f"대용량 전송: {c.dst_ip}:{c.dst_port} {c.bytes_out:,} bytes")


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _add_evidence(
    technique_map: dict[str, MitreTechnique],
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence: str,
    reference: str = "",
    source: str = "로컬룰",
    process: str = "",  # 발생 프로세스 이름 — 제공 시 "[process] evidence" 형식으로 기록
) -> None:
    """Insert or update a technique in *technique_map*, appending *evidence* and *source*."""
    # 프로세스 이름을 증거 문자열 앞에 태그로 붙여 분석가가 어느 프로세스가
    # 해당 기법을 유발했는지 바로 알 수 있도록 한다.
    if process and evidence:
        evidence = f"[{process}] {evidence}"
    if technique_id in technique_map:
        existing = technique_map[technique_id]
        if evidence and evidence not in existing.evidence:
            existing.evidence.append(evidence)
        if source and source not in existing.sources:
            existing.sources.append(source)
    else:
        technique_map[technique_id] = MitreTechnique(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            evidence=[evidence] if evidence else [],
            reference=reference,
            sources=[source] if source else [],
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_behaviors(
    events: list[ProcMonEvent],
    pcap: PcapResult,
    reg_diff: dict,
    proc_diff: dict,
) -> BehaviorReport:
    """Classify malware behaviors and map them to MITRE ATT&CK techniques.

    Parameters
    ----------
    events:
        Filtered ProcMon events (output of
        :func:`analysis.noise_filter.filter_events`).
    pcap:
        Parsed PCAP results from :func:`parsers.pcap_parser.parse_pcap`.
    reg_diff:
        Dictionary with at least an ``"added"`` key containing new/modified
        registry keys observed during the run.
    proc_diff:
        Dictionary describing process changes during the run (reserved for
        future classifiers; not currently used).

    Returns
    -------
    BehaviorReport
        Techniques sorted by tactic priority (Execution → Persistence →
        Defense Evasion → Command and Control → Exfiltration → Impact),
        plus lists of suspicious artefacts.
    """
    report       = BehaviorReport()
    technique_map: dict[str, MitreTechnique] = {}

    try:
        _classify_file_events(events, technique_map, report)
    except Exception:
        pass

    try:
        _classify_registry_events(events, reg_diff, technique_map, report)
    except Exception:
        pass

    try:
        _classify_process_events(events, technique_map, report)
    except Exception:
        pass

    try:
        _classify_network(pcap, technique_map, report)
    except Exception:
        pass

    # Deduplicate suspicious artefact lists
    report.suspicious_files     = list(dict.fromkeys(report.suspicious_files))
    report.suspicious_registry  = list(dict.fromkeys(report.suspicious_registry))
    report.suspicious_network   = list(dict.fromkeys(report.suspicious_network))
    report.suspicious_processes = list(dict.fromkeys(report.suspicious_processes))

    # Sort techniques by tactic priority
    report.techniques = sorted(technique_map.values(), key=_tactic_key)

    return report
