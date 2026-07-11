"""Classify malware behaviors and map them to MITRE ATT&CK techniques."""

from __future__ import annotations

from dataclasses import dataclass, field

from parsers.procmon_csv import ProcMonEvent, EventCategory
from parsers.pcap_parser import PcapResult
# 자격증명/anti-VM 경로는 analysis/sensitive_paths.py 단일 소스 사용
# (노이즈 필터의 ReadFile carve-out 과 동일 기준 공유)
from analysis.sensitive_paths import (
    BROWSER_CRED_PATH_FRAGMENTS as _BROWSER_CRED_PATH_FRAGMENTS,
    BROWSER_CRED_FILENAMES as _BROWSER_CRED_FILENAMES,
    ANTI_VM_FILE_FRAGMENTS as _ANTI_VM_FILE_FRAGMENTS,
)


# ---------------------------------------------------------------------------
# FP allowlist — Windows JIT/UWP processes and analysis tools
# HollowsHunter flags JIT stubs in these as shellcode (PE=0, replaced=0) → FP
# 정의는 analysis/fp_allowlist.py 단일 소스 참조.
# ---------------------------------------------------------------------------

from analysis.fp_allowlist import HH_SYSTEM_FP_NAMES as _HH_FP_NAMES


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    technique_id:   str
    technique_name: str
    tactic:         str
    evidence:       list[str] = field(default_factory=list)
    reference:      str = ""
    sources:        list[str] = field(default_factory=list)


@dataclass
class BehaviorReport:
    techniques:          list[MitreTechnique] = field(default_factory=list)
    suspicious_files:    list[str]            = field(default_factory=list)
    suspicious_registry: list[str]            = field(default_factory=list)
    suspicious_network:  list[str]            = field(default_factory=list)
    suspicious_processes:list[str]            = field(default_factory=list)
    tag_map:             dict[str, list[str]] = field(default_factory=dict)
    # 실행 진단
    execution_verdict:  str       = "UNKNOWN"   # CONFIRMED / PARTIAL / EVADED / FAILED / UNKNOWN
    execution_details:  list[str] = field(default_factory=list)  # 판정 근거 목록
    # 분류기 실패 기록 (예외로 스킵된 카테고리 — 조용한 누락 방지)
    classify_errors:    list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tactic ordering (full ATT&CK kill chain)
# 순서는 analysis/attack_lookup.py 의 TACTICS 단일 소스를 따른다.
# (이전에는 Reconnaissance·Resource Development·Initial Access 가 누락돼
#  해당 전술 기법이 킬체인 순서를 무시하고 표 맨 아래로 밀리는 버그가 있었음)
# ---------------------------------------------------------------------------

from analysis.attack_lookup import TACTICS as _TACTICS

_TACTIC_ORDER: dict[str, int] = {tactic: idx for idx, tactic in enumerate(_TACTICS)}


def _tactic_key(technique: MitreTechnique) -> int:
    return _TACTIC_ORDER.get(technique.tactic, 99)


# ---------------------------------------------------------------------------
# File event matchers
# ---------------------------------------------------------------------------

_STARTUP_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\currentversion\\run",
    "\\startup",
    "\\start menu\\programs\\startup",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
)

# Expanded to include script types
_TEMP_EXEC_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".pif"}
)
_APPDATA_TEMP_FRAGMENTS: tuple[str, ...] = ("\\appdata\\", "\\temp\\")

_RANSOMWARE_EXTENSIONS: frozenset[str] = frozenset(
    {".locked", ".encrypted", ".crypt", ".enc", ".zzz", ".zepto"}
)

_WRITE_CREATE_OPS: frozenset[str] = frozenset({"WriteFile", "CreateFile"})

# Anti-VM/Sandbox 탐지 패턴 — T1497.001
_ANTI_VM_REG_FRAGMENTS: tuple[str, ...] = (
    "vmware, inc", "vmware tools", "vmware virtual",
    "\\services\\vboxsf", "\\services\\vmhgfs", "\\services\\vmmouse",
    "\\services\\vmrawdsk", "\\services\\vmusbmouse", "\\services\\vmvss",
    "\\services\\vmx_svga", "\\services\\vmxnet", "\\services\\vmxnet3",
    "oracle\\virtualbox", "\\hardware\\acpi\\dsdt\\vbox__",
    "\\hardware\\acpi\\fadt\\vbox__", "\\hardware\\acpi\\rsdt\\vbox__",
    "vbox gim", "innotek gmbh", "qemu",
    "\\system\\currentcontrolset\\services\\netkvm",
    "parallels", "prl_tools", "\\software\\xen", "xentools",
)
_REG_READ_OPS: frozenset[str] = frozenset({
    "RegOpenKey", "RegQueryKey", "RegQueryValue",
    "RegEnumKey", "RegEnumValue",
})
_FILE_READ_OPS: frozenset[str] = frozenset({
    "ReadFile", "QueryInformation",
    "QueryBasicInformationFile", "QueryAttributesFile",
})

# Browser credential paths (T1555.003) 는 analysis/sensitive_paths.py 참조
_BROWSER_PROC_NAMES: frozenset[str] = frozenset(
    {"chrome.exe", "chromium.exe", "msedge.exe", "firefox.exe",
     "opera.exe", "brave.exe", "iexplore.exe"}
)


def _file_extension(path: str) -> str:
    dot   = path.rfind(".")
    slash = max(path.rfind("\\"), path.rfind("/"))
    if dot > slash:
        return path[dot:].lower()
    return ""


def _classify_file_events(
    events: list[ProcMonEvent],
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    for ev in events:
        if ev.category != EventCategory.FILE:
            continue

        op    = ev.operation
        path  = ev.path
        lower = path.lower()
        ext   = _file_extension(path)
        # filename component (last segment after final backslash or slash)
        sep_idx = max(lower.rfind("\\"), lower.rfind("/"))
        fname   = lower[sep_idx + 1:] if sep_idx >= 0 else lower

        # T1547.001 – startup/run-key file placement
        if op in _WRITE_CREATE_OPS:
            if any(frag in lower for frag in _STARTUP_PATH_FRAGMENTS):
                _add_evidence(
                    technique_map, "T1547.001",
                    "Registry Run Keys / Startup Folder", "Persistence",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1547/001/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)
                _tag_entity(report.tag_map, lower, "T1547.001")

        # T1027 – executable/script dropped in AppData or Temp
        if op in _WRITE_CREATE_OPS:
            if ext in _TEMP_EXEC_EXTENSIONS and any(
                frag in lower for frag in _APPDATA_TEMP_FRAGMENTS
            ):
                _add_evidence(
                    technique_map, "T1027",
                    "Obfuscated Files or Information", "Defense Evasion",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1027/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)
                _tag_entity(report.tag_map, lower, "T1027")

        # T1486 – ransomware-style extension
        if op == "WriteFile" and ext in _RANSOMWARE_EXTENSIONS:
            _add_evidence(
                technique_map, "T1486",
                "Data Encrypted for Impact", "Impact",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1486/",
                process=ev.process,
            )
            report.suspicious_files.append(path)
            _tag_entity(report.tag_map, lower, "T1486")

        # T1070.004 – self-deletion
        if op == "DeleteFile":
            proc_stem = ev.process.lower().replace(".exe", "")
            if proc_stem and proc_stem in lower:
                _add_evidence(
                    technique_map, "T1070.004",
                    "File Deletion", "Defense Evasion",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1070/004/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)
                _tag_entity(report.tag_map, lower, "T1070.004")

        # T1497.001 – Virtualization/Sandbox Evasion: VM 아티팩트 파일 접근
        if op in _FILE_READ_OPS and any(frag in lower for frag in _ANTI_VM_FILE_FRAGMENTS):
            _add_evidence(
                technique_map, "T1497.001",
                "Virtualization/Sandbox Evasion: System Checks", "Defense Evasion",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1497/001/",
                process=ev.process,
            )
            report.suspicious_files.append(path)
            _tag_entity(report.tag_map, lower, "T1497.001")

        # T1555.003 – Credentials from Web Browsers
        # Exclude browser processes reading their own files
        if ev.process.lower() not in _BROWSER_PROC_NAMES:
            _is_cred_path = any(frag in lower for frag in _BROWSER_CRED_PATH_FRAGMENTS)
            _is_ff_cred   = ("\\mozilla\\firefox\\" in lower and fname in _BROWSER_CRED_FILENAMES)
            if _is_cred_path or _is_ff_cred:
                _add_evidence(
                    technique_map, "T1555.003",
                    "Credentials from Web Browsers", "Credential Access",
                    evidence=path,
                    reference="https://attack.mitre.org/techniques/T1555/003/",
                    process=ev.process,
                )
                report.suspicious_files.append(path)
                _tag_entity(report.tag_map, lower, "T1555.003")


# ---------------------------------------------------------------------------
# Registry event matchers
# ---------------------------------------------------------------------------

_REG_RUN_KEYS: tuple[str, ...] = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
)


def _classify_registry_events(
    events: list[ProcMonEvent],
    reg_diff: dict,
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:

    def _check_reg_path(path: str, detail: str = "", process: str = "") -> None:
        lower = path.lower()
        det   = detail.lower()

        if any(frag in lower for frag in _REG_RUN_KEYS):
            _add_evidence(
                technique_map, "T1547.001",
                "Registry Run Keys / Startup Folder", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1547/001/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1547.001")

        if "\\services\\" in lower:
            _add_evidence(
                technique_map, "T1543.003",
                "Windows Service", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1543/003/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1543.003")

        if "winlogon" in lower and ("userinit" in det or "shell" in det):
            _add_evidence(
                technique_map, "T1547.004",
                "Winlogon Helper DLL", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1547/004/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1547.004")

        if "appinit_dlls" in lower:
            _add_evidence(
                technique_map, "T1546.010",
                "AppInit DLLs", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/010/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1546.010")

        if "image file execution options" in lower and "debugger" in det:
            _add_evidence(
                technique_map, "T1546.012",
                "Image File Execution Options Injection", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/012/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1546.012")

        # T1562.001 – Defender / AV disable via registry
        _defender_keys = (
            "disableantispyware", "disablerealtimemonitoring",
            "disableav", "disablebehaviormonitoring",
            "disableioavprotection", "disableonaccessprotection",
        )
        if any(k in lower for k in _defender_keys):
            _add_evidence(
                technique_map, "T1562.001",
                "Disable or Modify Tools", "Defense Evasion",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1562/001/",
                process=process,
            )
            report.suspicious_registry.append(path)
            _tag_entity(report.tag_map, lower, "T1562.001")

    for ev in events:
        if ev.category != EventCategory.REGISTRY:
            continue
        if ev.operation == "RegSetValue":
            _check_reg_path(ev.path, ev.detail, process=ev.process)
        # T1497.001 – VM 아티팩트 레지스트리 쿼리 (Anti-VM 체크)
        if ev.operation in _REG_READ_OPS:
            _lower = ev.path.lower()
            if any(frag in _lower for frag in _ANTI_VM_REG_FRAGMENTS):
                _add_evidence(
                    technique_map, "T1497.001",
                    "Virtualization/Sandbox Evasion: System Checks", "Defense Evasion",
                    evidence=ev.path,
                    reference="https://attack.mitre.org/techniques/T1497/001/",
                    process=ev.process,
                )
                report.suspicious_registry.append(ev.path)
                _tag_entity(report.tag_map, _lower, "T1497.001")

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
# Process event matchers
# ---------------------------------------------------------------------------

_PROC_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # (fragment, technique_id, technique_name, tactic, reference)

    # ── Scripting interpreters ──────────────────────────────────────────────
    ("cmd.exe",        "T1059.003", "Windows Command Shell", "Execution",
     "https://attack.mitre.org/techniques/T1059/003/"),
    ("powershell.exe", "T1059.001", "PowerShell", "Execution",
     "https://attack.mitre.org/techniques/T1059/001/"),
    ("wscript.exe",    "T1059.005", "Visual Basic", "Execution",
     "https://attack.mitre.org/techniques/T1059/005/"),
    ("cscript.exe",    "T1059.005", "Visual Basic", "Execution",
     "https://attack.mitre.org/techniques/T1059/005/"),
    ("wmic.exe",       "T1047",     "Windows Management Instrumentation", "Execution",
     "https://attack.mitre.org/techniques/T1047/"),

    # ── Defense evasion / LOLBins ───────────────────────────────────────────
    ("rundll32.exe",         "T1218.011", "Rundll32", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1218/011/"),
    ("regsvr32.exe",         "T1218.010", "Regsvr32", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1218/010/"),
    ("mshta.exe",            "T1218.005", "Mshta", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1218/005/"),
    ("certutil.exe",         "T1140",     "Deobfuscate/Decode Files or Information", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1140/"),
    ("bitsadmin.exe",        "T1197",     "BITS Jobs", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1197/"),
    ("reg.exe",              "T1112",     "Modify Registry", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1112/"),
    ("aspnet_compiler.exe",  "T1055.012", "Process Hollowing", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1055/012/"),
    ("installutil.exe",      "T1218.004", "InstallUtil", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1218/004/"),
    ("msiexec.exe",          "T1218.007", "Msiexec", "Defense Evasion",
     "https://attack.mitre.org/techniques/T1218/007/"),

    # ── Persistence LOLBins ─────────────────────────────────────────────────
    ("schtasks.exe", "T1053.005", "Scheduled Task", "Persistence",
     "https://attack.mitre.org/techniques/T1053/005/"),
    ("at.exe",       "T1053.002", "At", "Persistence",
     "https://attack.mitre.org/techniques/T1053/002/"),
    ("sc.exe",       "T1543.003", "Windows Service", "Persistence",
     "https://attack.mitre.org/techniques/T1543/003/"),

    # ── Discovery LOLBins ───────────────────────────────────────────────────
    ("systeminfo.exe", "T1082",     "System Information Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1082/"),
    ("whoami.exe",     "T1033",     "System Owner/User Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1033/"),
    ("net.exe",        "T1087",     "Account Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1087/"),
    ("net1.exe",       "T1087",     "Account Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1087/"),
    ("ipconfig.exe",   "T1016",     "System Network Configuration Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1016/"),
    ("hostname.exe",   "T1082",     "System Information Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1082/"),
    ("arp.exe",        "T1016",     "System Network Configuration Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1016/"),
    ("route.exe",      "T1016",     "System Network Configuration Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1016/"),
    ("netstat.exe",    "T1049",     "System Network Connections Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1049/"),
    ("tasklist.exe",   "T1057",     "Process Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1057/"),
    ("nltest.exe",     "T1087.002", "Domain Account", "Discovery",
     "https://attack.mitre.org/techniques/T1087/002/"),
    ("quser.exe",      "T1033",     "System Owner/User Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1033/"),
    ("nslookup.exe",   "T1016",     "System Network Configuration Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1016/"),
    ("ping.exe",       "T1016",     "System Network Configuration Discovery", "Discovery",
     "https://attack.mitre.org/techniques/T1016/"),
]

_APPDATA_TEMP_PROC_FRAGS: tuple[str, ...] = ("\\appdata\\", "\\temp\\")


def _classify_powershell_cmdline(
    detail_lower: str,
    ev: ProcMonEvent,
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Deep-analyze PowerShell command-line flags for specific sub-techniques."""
    evidence = (ev.detail or "")[:300]

    # T1027.010 — Command Obfuscation (encoded command)
    if ("-encodedcommand" in detail_lower or " -enc " in detail_lower
            or " -ec " in detail_lower or "encodedcommand" in detail_lower):
        _add_evidence(
            technique_map, "T1027.010", "Command Obfuscation", "Defense Evasion",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1027/010/",
            process=ev.process,
        )

    # T1562.001 — Disable or Modify Tools (Set-MpPreference)
    if "set-mppreference" in detail_lower and "disable" in detail_lower:
        _add_evidence(
            technique_map, "T1562.001", "Disable or Modify Tools", "Defense Evasion",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1562/001/",
            process=ev.process,
        )

    # T1105 — Ingress Tool Transfer (download cradle patterns)
    _dl_kw = (
        "downloadstring", "downloadfile", "webclient",
        "invoke-webrequest", "invoke-restmethod",
        "system.net.webclient", "urldownloadtofile", "bitstransfer",
    )
    if any(kw in detail_lower for kw in _dl_kw):
        _add_evidence(
            technique_map, "T1105", "Ingress Tool Transfer", "Command and Control",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1105/",
            process=ev.process,
        )

    # T1059.001 — Execution Policy Bypass / hidden window
    _bypass_kw = (
        "-executionpolicy bypass", "-ep bypass", "-ep b",
        "-noprofile", " -nop ", " -w hidden", " -windowstyle hidden",
    )
    if any(kw in detail_lower for kw in _bypass_kw):
        _add_evidence(
            technique_map, "T1059.001",
            "PowerShell (Execution Policy Bypass)", "Execution",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1059/001/",
            process=ev.process,
        )

    # T1059.001 — IEX / Invoke-Expression (in-memory execution)
    if "invoke-expression" in detail_lower or " iex " in detail_lower or "(iex" in detail_lower:
        _add_evidence(
            technique_map, "T1059.001",
            "PowerShell (Invoke-Expression)", "Execution",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1059/001/",
            process=ev.process,
        )

    # T1548.002 — Bypass UAC
    _uac_kw = ("fodhelper", "eventvwr", "sdclt", "computerdefaults", "bypassuac")
    if any(kw in detail_lower for kw in _uac_kw):
        _add_evidence(
            technique_map, "T1548.002",
            "Bypass User Account Control", "Privilege Escalation",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1548/002/",
            process=ev.process,
        )


def _classify_process_events(
    events: list[ProcMonEvent],
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    for ev in events:
        if ev.category != EventCategory.PROCESS:
            continue
        if ev.operation != "Process Create":
            continue

        detail_lower = ev.detail.lower()
        path_lower   = ev.path.lower()

        # vssadmin delete shadows → T1490
        if "vssadmin" in detail_lower and "delete" in detail_lower:
            _add_evidence(
                technique_map, "T1490", "Inhibit System Recovery", "Impact",
                evidence=ev.detail,
                reference="https://attack.mitre.org/techniques/T1490/",
                process=ev.process,
            )
            report.suspicious_processes.append(ev.detail)

        # LOLBin / scripting interpreter patterns
        for frag, tid, tname, tactic, ref in _PROC_PATTERNS:
            if frag in detail_lower or frag in path_lower:
                _add_evidence(
                    technique_map, tid, tname, tactic,
                    evidence=ev.detail or ev.path,
                    reference=ref,
                    process=ev.process,
                )
                report.suspicious_processes.append(ev.detail or ev.path)
                _tag_entity(report.tag_map, frag, tid)
                break  # first match per event

        # PowerShell deep analysis — runs regardless of LOLBin match above
        if "powershell" in detail_lower or "powershell" in path_lower:
            _classify_powershell_cmdline(detail_lower, ev, technique_map, report)

        # net.exe sub-command intent
        if "net.exe" in detail_lower or "net1.exe" in detail_lower:
            if " group" in detail_lower or " localgroup" in detail_lower:
                _add_evidence(
                    technique_map, "T1069", "Permission Groups Discovery", "Discovery",
                    evidence=ev.detail,
                    reference="https://attack.mitre.org/techniques/T1069/",
                    process=ev.process,
                )
            if " share" in detail_lower:
                _add_evidence(
                    technique_map, "T1135", "Network Share Discovery", "Discovery",
                    evidence=ev.detail,
                    reference="https://attack.mitre.org/techniques/T1135/",
                    process=ev.process,
                )

        # Process launched from suspicious location
        if any(frag in detail_lower for frag in _APPDATA_TEMP_PROC_FRAGS):
            _add_evidence(
                technique_map, "T1059",
                "Command and Scripting Interpreter", "Execution",
                evidence=ev.detail,
                reference="https://attack.mitre.org/techniques/T1059/",
                process=ev.process,
            )
            report.suspicious_processes.append(ev.detail)


# ---------------------------------------------------------------------------
# Injection detection – hollows-hunter / pe-sieve
# ---------------------------------------------------------------------------

def _classify_injection(
    hh_result,          # HollowsHunterResult | None
    pe_sieve_results,   # list[PeSieveResult] | None
    technique_map: dict[str, MitreTechnique],
    report: BehaviorReport,
) -> None:
    """Map hollows-hunter / pe-sieve findings to MITRE T1055 injection techniques."""
    seen_pids: set[int] = set()

    def _handle(r) -> None:
        susp = getattr(r, "suspicious", 0)
        if susp == 0:
            return
        pid  = getattr(r, "pid", 0)
        if pid in seen_pids:
            return
        seen_pids.add(pid)

        pname        = getattr(r, "name", "") or f"PID {pid}"
        pname_lower  = pname.lower()
        replaced     = getattr(r, "replaced", 0)
        implanted_pe = getattr(r, "implanted_pe", 0)
        implanted_shc = getattr(r, "implanted_shc", 0)
        hooked       = getattr(r, "hooked", 0)

        # Windows JIT/UWP 및 분석 도구 오탐 제거:
        # PE=0, replaced=0 조건에서 HH가 JIT 컴파일 스텁을 셸코드로 잘못 탐지함
        if pname_lower in _HH_FP_NAMES and replaced == 0 and implanted_pe == 0:
            return

        ev_base = f"{pname} (PID {pid}): susp={susp}"

        # T1055.012 — Process Hollowing
        if replaced > 0 or implanted_pe > 0:
            _add_evidence(
                technique_map, "T1055.012", "Process Hollowing", "Defense Evasion",
                evidence=f"{ev_base}, replaced={replaced}, implanted_pe={implanted_pe}",
                reference="https://attack.mitre.org/techniques/T1055/012/",
                process=pname,
            )
            report.suspicious_processes.append(f"Process Hollowing: {pname}")
            _tag_entity(report.tag_map, pname_lower, "T1055.012")

        # T1055 — Shellcode injection
        if implanted_shc > 0:
            _add_evidence(
                technique_map, "T1055", "Process Injection (Shellcode)", "Defense Evasion",
                evidence=f"{ev_base}, shellcode={implanted_shc}",
                reference="https://attack.mitre.org/techniques/T1055/",
                process=pname,
            )
            report.suspicious_processes.append(f"Shellcode 주입: {pname}")
            _tag_entity(report.tag_map, pname_lower, "T1055")

        # T1056.001 — Keylogging (API hooks detected in suspicious process)
        # Only flag real hooks in non-FP processes (FP processes already filtered above)
        if hooked > 0:
            _add_evidence(
                technique_map, "T1056.001", "Keylogging", "Collection",
                evidence=f"{ev_base}, hooked={hooked}",
                reference="https://attack.mitre.org/techniques/T1056/001/",
                process=pname,
            )
            _tag_entity(report.tag_map, pname_lower, "T1056.001")

        # T1055 — generic (anything suspicious not covered above)
        if susp > 0 and replaced == 0 and implanted_pe == 0 and implanted_shc == 0:
            _add_evidence(
                technique_map, "T1055", "Process Injection", "Defense Evasion",
                evidence=ev_base,
                reference="https://attack.mitre.org/techniques/T1055/",
                process=pname,
            )
            _tag_entity(report.tag_map, pname_lower, "T1055")

    if hh_result:
        for r in (getattr(hh_result, "process_results", []) or []):
            _handle(r)

    if pe_sieve_results:
        for r in pe_sieve_results:
            _handle(r)


# ---------------------------------------------------------------------------
# Network matchers
# ---------------------------------------------------------------------------

_MULTICAST_IPS: frozenset[str] = frozenset({
    "224.0.0.252", "224.0.0.251", "239.255.255.250",
    "ff02::fb", "ff02::1:3", "ff02::2", "ff02::16",
})

_ANALYSIS_SERVICE_SUFFIXES_BC: tuple[str, ...] = (
    "abuse.ch", "virustotal.com", "alienvault.com", "shodan.io",
    "system-informer.com", "github.com", "githubusercontent.com",
    "phantom.app", "metamask.io", "xdefi.services",
)

# IP geolocation lookup domains → T1016
_GEOIP_DOMAINS: frozenset[str] = frozenset({
    "checkip.dyndns.org", "ipinfo.io", "reallyfreegeoip.org", "freegeoip.net",
    "api.ipify.org", "ipify.org", "ip-api.com", "geoip.nekudo.com",
    "whatismyip.com", "icanhazip.com", "ipecho.net", "myip.dnsomatic.com",
    "checkip.amazonaws.com", "api.ip.sb", "wtfismyip.com",
    "api.geoiplookup.net", "geoipify.whoisxmlapi.com",
})


def _is_analysis_domain_bc(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    for suffix in _ANALYSIS_SERVICE_SUFFIXES_BC:
        if d == suffix or d.endswith("." + suffix):
            return True
    return False


def _is_geoip_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in _GEOIP_DOMAINS:
        return True
    for gd in _GEOIP_DOMAINS:
        if d.endswith("." + gd):
            return True
    return False


def _is_private_ip(ip: str) -> bool:
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
    for conn in pcap.connections:
        if _is_private_ip(conn.dst_ip):
            continue
        if conn.dst_ip in _MULTICAST_IPS:
            continue
        if any(_is_analysis_domain_bc(d) for d in pcap.ip_to_domain.get(conn.dst_ip, [])):
            continue

        evidence = f"{conn.dst_ip}:{conn.dst_port}"

        # SMTP → Mail Protocol + Exfiltration
        if conn.dst_port in (25, 465, 587):
            _add_evidence(technique_map, "T1071.003",
                          "Application Layer Protocol: Mail Protocols", "Command and Control",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/003/")
            _add_evidence(technique_map, "T1048",
                          "Exfiltration Over Alternative Protocol (SMTP)", "Exfiltration",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1048/")
            report.suspicious_network.append(f"SMTP: {evidence}")
            _tag_entity(report.tag_map, conn.dst_ip, "T1071.003")
            _tag_entity(report.tag_map, conn.dst_ip, "T1048")

        # FTP → Exfiltration
        elif conn.dst_port in (21, 990):
            _add_evidence(technique_map, "T1048",
                          "Exfiltration Over Alternative Protocol (FTP)", "Exfiltration",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1048/")
            report.suspicious_network.append(f"FTP: {evidence}")
            _tag_entity(report.tag_map, conn.dst_ip, "T1048")

        elif conn.dst_port in (80, 8080):
            _add_evidence(technique_map, "T1071.001", "Web Protocols",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            _tag_entity(report.tag_map, conn.dst_ip, "T1071.001")
        elif conn.dst_port in (443, 8443):
            _add_evidence(technique_map, "T1071.001", "Web Protocols (HTTPS)",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            _tag_entity(report.tag_map, conn.dst_ip, "T1071.001")
        else:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol", "Command and Control",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1095/")
            _tag_entity(report.tag_map, conn.dst_ip, "T1095")

        if conn.suspicious_port:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol (의심 포트)", "Command and Control",
                          evidence=f"{conn.dst_ip}:{conn.dst_port} [{conn.proto}]",
                          reference="https://attack.mitre.org/techniques/T1095/")
            _tag_entity(report.tag_map, conn.dst_ip, "T1095")

        report.suspicious_network.append(evidence)

    # TLS SNI
    seen_sni: set[str] = set()
    for tls in pcap.tls_info:
        if tls.sni and tls.sni not in seen_sni:
            if _is_analysis_domain_bc(tls.sni):
                continue
            seen_sni.add(tls.sni)
            _add_evidence(technique_map, "T1071.001",
                          "Web Protocols (TLS SNI)", "Command and Control",
                          evidence=f"SNI={tls.sni} → {tls.dst_ip}:{tls.dst_port}",
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            report.suspicious_network.append(f"TLS SNI: {tls.sni}")
            _tag_entity(report.tag_map, tls.sni.lower(), "T1071.001")
            _tag_entity(report.tag_map, tls.dst_ip, "T1071.001")

    # DNS queries
    for q in pcap.dns_queries:
        if _is_analysis_domain_bc(q.name):
            continue

        # GeoIP lookup → T1016 (System Network Configuration Discovery)
        if _is_geoip_domain(q.name):
            _add_evidence(technique_map, "T1016",
                          "System Network Configuration Discovery (IP Geolocation)", "Discovery",
                          evidence=f"DNS: {q.name}",
                          reference="https://attack.mitre.org/techniques/T1016/")
            report.suspicious_network.append(f"GeoIP lookup: {q.name}")
            _tag_entity(report.tag_map, q.name.lower(), "T1016")
            continue

        _add_evidence(technique_map, "T1071.004", "DNS", "Command and Control",
                      evidence=q.name,
                      reference="https://attack.mitre.org/techniques/T1071/004/")
        _tag_entity(report.tag_map, q.name.lower(), "T1071.004")

    # DGA
    if pcap.suspicious_domains:
        for domain in pcap.suspicious_domains:
            _add_evidence(technique_map, "T1568.002",
                          "Domain Generation Algorithms", "Command and Control",
                          evidence=f"고엔트로피 도메인: {domain}",
                          reference="https://attack.mitre.org/techniques/T1568/002/")
            report.suspicious_network.append(f"DGA 의심: {domain}")
            _tag_entity(report.tag_map, domain.lower(), "T1568.002")

    # DNS tunneling
    if pcap.dns_tunnel_suspects:
        for base in pcap.dns_tunnel_suspects:
            _add_evidence(technique_map, "T1071.004",
                          "DNS (터널링 의심)", "Command and Control",
                          evidence=f"다수 서브도메인 쿼리: {base}",
                          reference="https://attack.mitre.org/techniques/T1071/004/")
            report.suspicious_network.append(f"DNS 터널링 의심: {base}")
            _tag_entity(report.tag_map, base.lower(), "T1071.004")

    # Beaconing
    if pcap.beacon_candidates:
        for bc in pcap.beacon_candidates:
            _add_evidence(technique_map, "T1071.001",
                          "Web Protocols (Beaconing)", "Command and Control",
                          evidence=(f"비콘 {bc.dst_ip}:{bc.dst_port} "
                                    f"— {bc.count}회, 평균 {bc.interval_avg}s, "
                                    f"지터 {bc.jitter_ratio:.1%}"),
                          reference="https://attack.mitre.org/techniques/T1071/001/")
            report.suspicious_network.append(
                f"비콘: {bc.dst_ip}:{bc.dst_port} ({bc.count}회, ~{bc.interval_avg}s 간격)")
            _tag_entity(report.tag_map, bc.dst_ip, "T1071.001")

    # TCP SYN without SYN-ACK — C2 응답 없음 (FLARE VM 환경에서 C2 오프라인)
    for ac in getattr(pcap, "attempted_connections", []):
        port_note = " [의심 포트]" if ac.suspicious_port else ""
        evidence  = f"{ac.dst_ip}:{ac.dst_port} (응답 없음, {ac.count}회 시도){port_note}"
        _add_evidence(
            technique_map, "T1095",
            "Non-Application Layer Protocol (C2 응답 없음)", "Command and Control",
            evidence=evidence,
            reference="https://attack.mitre.org/techniques/T1095/",
        )
        report.suspicious_network.append(f"[C2 시도 실패] {evidence}")
        _tag_entity(report.tag_map, ac.dst_ip, "T1095")

    # Large transfer / exfiltration — exclude analysis service IPs to reduce FPs
    external_ips = {
        c.dst_ip for c in pcap.connections
        if not _is_private_ip(c.dst_ip)
        and c.dst_ip not in _MULTICAST_IPS
        and not any(_is_analysis_domain_bc(d) for d in pcap.ip_to_domain.get(c.dst_ip, []))
    }
    large_transfers = [c for c in pcap.connections
                       if not _is_private_ip(c.dst_ip) and c.bytes_out > 100_000]
    if external_ips:
        _add_evidence(technique_map, "T1041",
                      "Exfiltration Over C2 Channel", "Exfiltration",
                      evidence=", ".join(sorted(external_ips)),
                      reference="https://attack.mitre.org/techniques/T1041/")
        for _ip in external_ips:
            _tag_entity(report.tag_map, _ip, "T1041")
    for c in large_transfers:
        report.suspicious_network.append(
            f"대용량 전송: {c.dst_ip}:{c.dst_port} {c.bytes_out:,} bytes")


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _tag_entity(tag_map: dict[str, list[str]], key: str, technique_id: str) -> None:
    """Register key → technique_id mapping for per-tab inline annotation in HTML report."""
    key = (key or "").strip().lower()
    if not key:
        return
    lst = tag_map.setdefault(key, [])
    if technique_id not in lst:
        lst.append(technique_id)


def _add_evidence(
    technique_map: dict[str, MitreTechnique],
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence: str,
    reference: str = "",
    source: str = "로컬룰",
    process: str = "",
) -> None:
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
    hh_result=None,         # HollowsHunterResult | None
    pe_sieve_results=None,  # list[PeSieveResult] | None
) -> BehaviorReport:
    """Classify malware behaviors and map them to MITRE ATT&CK techniques."""
    report        = BehaviorReport()
    technique_map: dict[str, MitreTechnique] = {}

    def _run(label: str, fn, *args) -> None:
        """분류기를 실행하되 예외 시 조용히 삼키지 않고 report에 기록한다.

        한 분류기의 예외로 해당 카테고리 기법이 통째로 누락되면
        MITRE 탭이 조용히 불완전해지므로 원인을 남긴다.
        """
        try:
            fn(*args)
        except Exception as exc:
            report.classify_errors.append(
                f"{label} 분류 실패: {type(exc).__name__}: {exc}"
            )

    _run("파일",       _classify_file_events,     events, technique_map, report)
    _run("레지스트리",  _classify_registry_events, events, reg_diff, technique_map, report)
    _run("프로세스",    _classify_process_events,  events, technique_map, report)
    _run("네트워크",    _classify_network,         pcap, technique_map, report)
    _run("인젝션",      _classify_injection,       hh_result, pe_sieve_results, technique_map, report)

    report.suspicious_files     = list(dict.fromkeys(report.suspicious_files))
    report.suspicious_registry  = list(dict.fromkeys(report.suspicious_registry))
    report.suspicious_network   = list(dict.fromkeys(report.suspicious_network))
    report.suspicious_processes = list(dict.fromkeys(report.suspicious_processes))

    report.techniques = sorted(technique_map.values(), key=_tactic_key)

    # ── 실행 진단 ──────────────────────────────────────────────────────────
    report.execution_verdict, report.execution_details = _assess_execution(
        events, pcap, technique_map, proc_diff,
    )

    return report


def _assess_execution(
    events: list[ProcMonEvent],
    pcap: PcapResult,
    technique_map: dict[str, MitreTechnique],
    proc_diff: dict,
) -> tuple[str, list[str]]:
    """샘플이 제대로 실행되었는지, 탐지 우회 가능성이 있는지 판정.

    Returns
    -------
    (verdict, details)
      verdict : "CONFIRMED" | "PARTIAL" | "EVADED" | "FAILED" | "UNKNOWN"
      details : 판정 근거 문자열 목록
    """
    details: list[str] = []

    total_events   = len(events)
    new_procs      = proc_diff.get("new_processes", []) if proc_diff else []
    non_wl_procs   = [p for p in new_procs if not getattr(p, "whitelisted", False)]

    has_anti_vm    = "T1497.001" in technique_map
    has_dns        = bool(pcap and pcap.dns_queries)
    has_conn       = bool(pcap and pcap.connections
                         and any(not _is_private_ip(c.dst_ip) for c in pcap.connections))
    has_attempted  = bool(pcap and getattr(pcap, "attempted_connections", []))
    has_beacon     = bool(pcap and pcap.beacon_candidates)
    has_smtp_ftp   = bool(pcap and (pcap.smtp_sessions or pcap.ftp_sessions))
    has_network    = has_dns or has_conn or has_attempted or has_beacon or has_smtp_ftp

    # 이벤트 수 요약
    details.append(f"ProcMon 이벤트 {total_events:,}건")
    details.append(f"신규 프로세스 {len(non_wl_procs)}개 (비화이트리스트)")

    if has_anti_vm:
        vm_evidence = technique_map["T1497.001"].evidence[:3]
        details.append(f"Anti-VM 체크 탐지 ({len(technique_map['T1497.001'].evidence)}건): "
                       + " / ".join(vm_evidence))

    if has_dns:
        details.append(f"DNS 쿼리 {len(pcap.dns_queries)}건")
    if has_conn:
        ext = [c for c in pcap.connections if not _is_private_ip(c.dst_ip)]
        details.append(f"외부 TCP/UDP 연결 {len(ext)}건")
    if has_attempted:
        details.append(f"C2 연결 시도(미응답) {len(pcap.attempted_connections)}건")
    if has_beacon:
        details.append(f"비콘 패턴 {len(pcap.beacon_candidates)}건")

    # ── 판정 ──────────────────────────────────────────────────────────────
    if has_anti_vm and not has_network:
        # Anti-VM 체크 후 네트워크 코드 진입 전 종료 — 이벤트 수와 무관하게 우선 판정
        verdict = "EVADED"
        details.append("→ 판정: VM/Sandbox 탐지 후 조기 종료 의심 (T1497.001)")
        details.append("  확인: Anti-VM 우회(FakeNet DHCP, MAC 변경), FLARE VM 아티팩트 제거")

    elif total_events < 15 and not non_wl_procs:
        # 거의 아무것도 일어나지 않음
        verdict = "FAILED"
        details.append("→ 판정: 샘플 실행 실패 의심 (이벤트 극소, 신규 프로세스 없음)")
        details.append("  확인: 아키텍처 불일치(x86/x64), 의존 DLL 누락, 실행 경로 오류")

    elif not has_network and total_events < 100:
        # 이벤트는 있지만 네트워크가 전무하고 이벤트도 적음
        verdict = "FAILED"
        details.append("→ 판정: 실행 실패 또는 극초기 종료 (네트워크 없음, 이벤트 적음)")
        details.append("  확인: 관리자 권한 필요, UAC 프롬프트 미처리, 실행 락 파일")

    elif has_attempted and not has_conn and not has_dns:
        # SYN만 있고 DNS도 없음 — IP 직접 접속 시도, 서버 오프라인
        verdict = "PARTIAL"
        details.append("→ 판정: C2 IP 직접 접속 시도 (DNS 없음, SYN만 관찰)")
        details.append("  확인: C2 IP가 오프라인 / 방화벽 차단 — FakeNet으로 트래픽 캡처 시도")

    elif has_network and (has_beacon or has_smtp_ftp or has_conn):
        verdict = "CONFIRMED"
        details.append("→ 판정: 실행 확인됨 (네트워크 활동 관찰)")

    elif has_network:
        verdict = "PARTIAL"
        details.append("→ 판정: 부분 실행 (네트워크 활동 있으나 C2 응답 없음)")

    else:
        verdict = "UNKNOWN"
        details.append("→ 판정: 불명확 (이벤트 있음, 네트워크 없음)")
        details.append("  확인: 장기 Sleep 후 C2 접속 / 조건부 실행 (특정 파일·레지스트리 필요)")

    return verdict, details
