"""Classify malware behaviors and map them to MITRE ATT&CK techniques."""

from __future__ import annotations

from dataclasses import dataclass, field

from parsers.procmon_csv import ProcMonEvent, EventCategory
from parsers.pcap_parser import PcapResult


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
    relevance_tier: int = 0   # 1=샘플 계보 2=상관 의심 3=환경 배경 (analysis.relevance)


@dataclass
class BehaviorReport:
    techniques:          list[MitreTechnique] = field(default_factory=list)
    suspicious_files:    list[str]            = field(default_factory=list)
    suspicious_registry: list[str]            = field(default_factory=list)
    suspicious_network:  list[str]            = field(default_factory=list)
    suspicious_processes:list[str]            = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tactic ordering (full ATT&CK kill chain)
# ---------------------------------------------------------------------------

_TACTIC_ORDER: dict[str, int] = {
    "Execution":            0,
    "Persistence":          1,
    "Privilege Escalation": 2,
    "Defense Evasion":      3,
    "Credential Access":    4,
    "Discovery":            5,
    "Lateral Movement":     6,
    "Collection":           7,
    "Command and Control":  8,
    "Exfiltration":         9,
    "Impact":               10,
}


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

# Browser credential paths — T1555.003
_BROWSER_CRED_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\google\\chrome\\user data\\default\\login data",
    "\\google\\chrome\\user data\\default\\cookies",
    "\\google\\chrome\\user data\\default\\web data",
    "\\microsoft\\edge\\user data\\default\\login data",
    "\\microsoft\\edge\\user data\\default\\cookies",
    "\\microsoft\\credentials\\",
    "\\microsoft\\protect\\",
)
_BROWSER_CRED_FILENAMES: frozenset[str] = frozenset(
    {"logins.json", "key4.db", "key3.db", "signons.sqlite"}
)
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


# ---------------------------------------------------------------------------
# Registry event matchers
# ---------------------------------------------------------------------------

_REG_RUN_KEYS: tuple[str, ...] = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
)


# ── T1543.003 (Windows Service) 판정 ─────────────────────────────────────────
# "\services\" 부분 문자열만 보면 서비스 생성과 무관한 키가 대량으로 걸린다.
# 특히 BAM/DAM(Background/Desktop Activity Moderator)은 프로그램이 실행될
# 때마다 커널이 실행 기록을 남기는 곳이라, 정상 실행조차 "서비스 생성"으로
# 오탐된다. 실제 서비스 등록·변경을 나타내는 값 이름일 때만 매핑한다.

# 서비스 생성/변경을 실제로 나타내는 값 이름
_SERVICE_PERSIST_VALUES: frozenset[str] = frozenset({
    "imagepath", "servicedll", "start", "type", "objectname",
    "displayname", "failureactions", "servicemain", "delayedautostart",
    "requiredprivileges", "userservicedll",
})

# 서비스 하위지만 등록 행위가 아닌 경로 (실행 기록·네트워크 설정·PnP 등)
_SERVICE_NOISE_FRAGMENTS: tuple[str, ...] = (
    "\\services\\bam\\",        # Background Activity Moderator — 실행 기록
    "\\services\\dam\\",        # Desktop Activity Moderator
    "\\services\\tcpip\\", "\\services\\tcpip6\\",
    "\\services\\netbt\\",
    "\\services\\dnscache\\",
    "\\services\\lanmanserver\\", "\\services\\lanmanworkstation\\",
    "\\services\\policies\\",
    "\\linkage\\", "\\enum\\", "\\security\\", "\\performance\\",
)


def _is_service_persistence_key(path_lower: str) -> bool:
    """레지스트리 경로가 실제 Windows 서비스 등록·변경을 나타내면 True."""
    if "\\services\\" not in path_lower:
        return False
    if any(frag in path_lower for frag in _SERVICE_NOISE_FRAGMENTS):
        return False

    tail = path_lower.split("\\services\\", 1)[1].strip("\\")
    if not tail:
        return False

    leaf = tail.rsplit("\\", 1)[-1]
    if leaf in _SERVICE_PERSIST_VALUES:
        return True
    # Services\<새이름> 키 자체의 생성도 서비스 등록 신호
    return "\\" not in tail


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

        if _is_service_persistence_key(lower):
            _add_evidence(
                technique_map, "T1543.003",
                "Windows Service", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1543/003/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "winlogon" in lower and ("userinit" in det or "shell" in det):
            _add_evidence(
                technique_map, "T1547.004",
                "Winlogon Helper DLL", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1547/004/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "appinit_dlls" in lower:
            _add_evidence(
                technique_map, "T1546.010",
                "AppInit DLLs", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/010/",
                process=process,
            )
            report.suspicious_registry.append(path)

        if "image file execution options" in lower and "debugger" in det:
            _add_evidence(
                technique_map, "T1546.012",
                "Image File Execution Options Injection", "Persistence",
                evidence=path,
                reference="https://attack.mitre.org/techniques/T1546/012/",
                process=process,
            )
            report.suspicious_registry.append(path)

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

    for ev in events:
        if ev.category == EventCategory.REGISTRY and ev.operation == "RegSetValue":
            _check_reg_path(ev.path, ev.detail, process=ev.process)

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
    from core.process_tracker import _ANALYSIS_TOOL_PROC_NAMES

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
        # 분석 도구 자신(hollows_hunter.exe, pe-sieve.exe, procmon.exe 등)은
        # 스캐너가 자기 메모리를 훑으며 남기는 아티팩트를 주입으로 오탐한다.
        # 리포트에 T1055/T1056 근거로 올라오면 안 되므로 여기서 제외한다.
        if pname.lower() in _ANALYSIS_TOOL_PROC_NAMES:
            return
        replaced     = getattr(r, "replaced", 0)
        implanted_pe = getattr(r, "implanted_pe", 0)
        implanted_shc = getattr(r, "implanted_shc", 0)
        hooked       = getattr(r, "hooked", 0)
        ev_base      = f"{pname} (PID {pid}): susp={susp}"

        # T1055.012 — Process Hollowing
        if replaced > 0 or implanted_pe > 0:
            _add_evidence(
                technique_map, "T1055.012", "Process Hollowing", "Defense Evasion",
                evidence=f"{ev_base}, replaced={replaced}, implanted_pe={implanted_pe}",
                reference="https://attack.mitre.org/techniques/T1055/012/",
                process=pname,
            )
            report.suspicious_processes.append(f"Process Hollowing: {pname}")

        # T1055 — Shellcode injection
        if implanted_shc > 0:
            _add_evidence(
                technique_map, "T1055", "Process Injection (Shellcode)", "Defense Evasion",
                evidence=f"{ev_base}, shellcode={implanted_shc}",
                reference="https://attack.mitre.org/techniques/T1055/",
                process=pname,
            )
            report.suspicious_processes.append(f"Shellcode 주입: {pname}")

        # T1056.001 — Keylogging (API hooks detected in suspicious process)
        if hooked > 0:
            _add_evidence(
                technique_map, "T1056.001", "Keylogging", "Collection",
                evidence=f"{ev_base}, hooked={hooked}",
                reference="https://attack.mitre.org/techniques/T1056/001/",
                process=pname,
            )

        # T1055 — generic (anything suspicious not covered above)
        if susp > 0 and replaced == 0 and implanted_pe == 0 and implanted_shc == 0:
            _add_evidence(
                technique_map, "T1055", "Process Injection", "Defense Evasion",
                evidence=ev_base,
                reference="https://attack.mitre.org/techniques/T1055/",
                process=pname,
            )

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

        # FTP → Exfiltration
        elif conn.dst_port in (21, 990):
            _add_evidence(technique_map, "T1048",
                          "Exfiltration Over Alternative Protocol (FTP)", "Exfiltration",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1048/")
            report.suspicious_network.append(f"FTP: {evidence}")

        elif conn.dst_port in (80, 8080):
            _add_evidence(technique_map, "T1071.001", "Web Protocols",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
        elif conn.dst_port in (443, 8443):
            _add_evidence(technique_map, "T1071.001", "Web Protocols (HTTPS)",
                          "Command and Control", evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1071/001/")
        else:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol", "Command and Control",
                          evidence=evidence,
                          reference="https://attack.mitre.org/techniques/T1095/")

        if conn.suspicious_port:
            _add_evidence(technique_map, "T1095",
                          "Non-Application Layer Protocol (의심 포트)", "Command and Control",
                          evidence=f"{conn.dst_ip}:{conn.dst_port} [{conn.proto}]",
                          reference="https://attack.mitre.org/techniques/T1095/")

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
            continue

        _add_evidence(technique_map, "T1071.004", "DNS", "Command and Control",
                      evidence=q.name,
                      reference="https://attack.mitre.org/techniques/T1071/004/")

    # DGA
    if pcap.suspicious_domains:
        for domain in pcap.suspicious_domains:
            _add_evidence(technique_map, "T1568.002",
                          "Domain Generation Algorithms", "Command and Control",
                          evidence=f"고엔트로피 도메인: {domain}",
                          reference="https://attack.mitre.org/techniques/T1568/002/")
            report.suspicious_network.append(f"DGA 의심: {domain}")

    # DNS tunneling
    if pcap.dns_tunnel_suspects:
        for base in pcap.dns_tunnel_suspects:
            _add_evidence(technique_map, "T1071.004",
                          "DNS (터널링 의심)", "Command and Control",
                          evidence=f"다수 서브도메인 쿼리: {base}",
                          reference="https://attack.mitre.org/techniques/T1071/004/")
            report.suspicious_network.append(f"DNS 터널링 의심: {base}")

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

    # Large transfer / exfiltration
    external_ips = {c.dst_ip for c in pcap.connections if not _is_private_ip(c.dst_ip)}
    large_transfers = [c for c in pcap.connections
                       if not _is_private_ip(c.dst_ip) and c.bytes_out > 100_000]
    if external_ips:
        _add_evidence(technique_map, "T1041",
                      "Exfiltration Over C2 Channel", "Exfiltration",
                      evidence=", ".join(sorted(external_ips)),
                      reference="https://attack.mitre.org/techniques/T1041/")
    for c in large_transfers:
        report.suspicious_network.append(
            f"대용량 전송: {c.dst_ip}:{c.dst_port} {c.bytes_out:,} bytes")


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

# 분석 도구가 자기 자신을 남긴 흔적 — 근거로 올리면 안 된다.
# (예: Explorer 가 Temp 에 푼 Procmon64.exe 가 T1027 난독화 근거로 잡히는 문제)
_ANALYSIS_ARTIFACT_TOKENS: tuple[str, ...] = (
    "procmon", "procexp", "pe-sieve", "pe_sieve", "hollows_hunter",
    "hollows-hunter", "systeminformer", "processhacker", "tshark",
    "dumpcap", "wireshark", "zoomit", "winpmem", "volatility",
)


def _is_analysis_artifact_evidence(text: str) -> bool:
    t = (text or "").lower()
    return any(tok in t for tok in _ANALYSIS_ARTIFACT_TOKENS)


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
    # 분석 도구 흔적은 근거에서 제외 — 발생 프로세스와 대상 경로 모두 확인
    if _is_analysis_artifact_evidence(process) or _is_analysis_artifact_evidence(evidence):
        return
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

    try:
        _classify_injection(hh_result, pe_sieve_results, technique_map, report)
    except Exception:
        pass

    report.suspicious_files     = list(dict.fromkeys(report.suspicious_files))
    report.suspicious_registry  = list(dict.fromkeys(report.suspicious_registry))
    report.suspicious_network   = list(dict.fromkeys(report.suspicious_network))
    report.suspicious_processes = list(dict.fromkeys(report.suspicious_processes))

    report.techniques = sorted(technique_map.values(), key=_tactic_key)

    return report
