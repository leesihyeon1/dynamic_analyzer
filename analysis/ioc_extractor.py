"""Extract Indicators of Compromise (IOCs) from dynamic analysis data.

Combines ProcMon events, PCAP results, registry diff, and process diff into a
single :class:`IOCReport` suitable for threat-intel sharing or further pivoting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from parsers.procmon_csv import ProcMonEvent, EventCategory
from parsers.pcap_parser import PcapResult


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IOCReport:
    """All IOCs extracted from a single dynamic analysis run."""

    ip_addresses:  list[str] = field(default_factory=list)   # external IPs
    domains:       list[str] = field(default_factory=list)   # external hostnames
    dropped_files: list[str] = field(default_factory=list)   # files written by sample
    registry_keys: list[str] = field(default_factory=list)   # new/modified reg keys
    mutexes:       list[str] = field(default_factory=list)
    urls:          list[str] = field(default_factory=list)    # full HTTP URLs


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918, loopback, and link-local addresses.

    Covers 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x.
    """
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


# Noisy TLD / domain suffixes that indicate Microsoft / OS infrastructure
_NOISY_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "akadns.net",
    "msftncsi.com",
    "msedge.net",
    "azure.com",
    "live.com",
    "office.com",
    "office365.com",
    "msn.com",
    "bing.com",
    ".local",
    ".arpa",
    "wns.windows.com",
    "trafficmanager.net",
)


def _is_noisy_domain(domain: str) -> bool:
    """Return True if *domain* is a well-known Microsoft / OS infrastructure host.

    Filters out domains ending with any suffix in :data:`_NOISY_DOMAIN_SUFFIXES`.
    """
    lower = domain.lower()
    for suffix in _NOISY_DOMAIN_SUFFIXES:
        if lower == suffix or lower.endswith("." + suffix.lstrip(".")):
            return True
    return False


# Executable / script extensions that indicate a dropped payload
_DROPPED_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"}
)

# Windows system directory prefixes (lowercased) – files in these dirs are not IOCs
_SYSTEM_PATH_PREFIXES: tuple[str, ...] = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\sysnative",
    r"c:\windows\winsxs",
    r"c:\program files\",
    r"c:\program files (x86)\",
)

# Registry path fragments that indicate persistence / injection
_INTERESTING_REG_FRAGMENTS: tuple[str, ...] = (
    "run",
    "services",
    "winlogon",
    "appinit",
)

# Ops that constitute a file being written to disk
_WRITE_OPS: frozenset[str] = frozenset({"WriteFile", "CreateFile"})


def _file_extension(path: str) -> str:
    """Return the lowercased file extension from *path*, including the dot."""
    dot   = path.rfind(".")
    slash = max(path.rfind("\\"), path.rfind("/"))
    if dot > slash and dot != -1:
        return path[dot:].lower()
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_iocs(
    events: list[ProcMonEvent],
    pcap: PcapResult,
    reg_diff: dict,
    proc_diff: dict,
) -> IOCReport:
    """Extract IOCs from all dynamic analysis data sources.

    Parameters
    ----------
    events:
        Filtered ProcMon events.
    pcap:
        Parsed PCAP results.
    reg_diff:
        Dictionary with an ``"added"`` key containing new/modified registry
        entries observed during the run.  Each entry may be a dict with a
        ``"path"`` key, or a plain string.
    proc_diff:
        Dictionary describing process changes (reserved for future use,
        e.g. mutex extraction from proc handles).

    Returns
    -------
    IOCReport
        Deduplicated IOC report.
    """
    report = IOCReport()

    # ------------------------------------------------------------------
    # IP addresses (external only)
    # ------------------------------------------------------------------
    try:
        for ip in pcap.raw_ips:
            if not _is_private_ip(ip):
                report.ip_addresses.append(ip)
        report.ip_addresses = sorted(set(report.ip_addresses))
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Domains (filter out MS / OS infrastructure)
    # ------------------------------------------------------------------
    try:
        for domain in pcap.raw_domains:
            if domain and not _is_noisy_domain(domain):
                report.domains.append(domain)
        report.domains = sorted(set(report.domains))
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Dropped files (written executables / scripts outside system dirs)
    # ------------------------------------------------------------------
    try:
        for ev in events:
            if ev.category != EventCategory.FILE:
                continue
            if ev.operation not in _WRITE_OPS:
                continue

            path  = ev.path
            lower = path.lower()
            ext   = _file_extension(path)

            if ext not in _DROPPED_EXTENSIONS:
                continue

            if any(lower.startswith(pfx) for pfx in _SYSTEM_PATH_PREFIXES):
                continue

            report.dropped_files.append(path)

        report.dropped_files = list(dict.fromkeys(report.dropped_files))
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Registry keys (persistence-related)
    # ------------------------------------------------------------------
    try:
        added_entries = reg_diff.get("added", [])
        for entry in added_entries:
            try:
                if isinstance(entry, dict):
                    path = entry.get("path", "")
                else:
                    path = str(entry)

                lower = path.lower()
                if any(frag in lower for frag in _INTERESTING_REG_FRAGMENTS):
                    report.registry_keys.append(path)
            except Exception:
                continue

        report.registry_keys = list(dict.fromkeys(report.registry_keys))
    except Exception:
        pass

    # ------------------------------------------------------------------
    # URLs (constructed from HTTP requests)
    # ------------------------------------------------------------------
    try:
        for req in pcap.http_requests:
            try:
                if req.host:
                    url = f"http://{req.host}{req.path or '/'}"
                    report.urls.append(url)
            except Exception:
                continue

        report.urls = list(dict.fromkeys(report.urls))
    except Exception:
        pass

    # Mutexes: not available from ProcMon CSV alone; left empty unless
    # proc_diff provides them.
    try:
        mutexes = proc_diff.get("mutexes", [])
        if mutexes:
            report.mutexes = list(dict.fromkeys(str(m) for m in mutexes))
    except Exception:
        pass

    return report
