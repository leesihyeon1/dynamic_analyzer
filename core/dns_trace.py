"""DNS-Client ETW 3008 질의 완료 이벤트를 분석 실행 구간에 수집한다.

이벤트 3008 은 요청 프로세스 컨텍스트(ProcessId)와 질의 이름·유형·결과
(QueryResults, QueryStatus)를 담는다. Dnscache(svchost) 대리 송신 때문에
PCAP↔ProcMon 포트 매칭으로는 알 수 없는 실제 요청 PID를 얻는 경로다.
"""
import atexit
import ipaddress
import json
import os
import re
import subprocess
import uuid

from parsers.dns_correlator import AttributedDnsQuery, merge_dns_attributions

SESSION_PREFIX = "DynamicAnalyzerDNS-"
_STALE_RE = re.compile(r"^\s*(" + re.escape(SESSION_PREFIX) + r"[0-9A-Za-z]+)\b", re.MULTILINE)

# 상태 코드 → 설명 (윈도 DNS 오류 코드)
_STATUS_TEXT = {
    0: "",
    87: "잘못된 매개변수",
    1460: "시간 초과",
    9002: "SERVFAIL",
    9003: "NXDOMAIN (존재하지 않는 도메인)",
    9501: "응답 레코드 없음",
    9560: "시간 초과",
    11001: "호스트 없음",
}


def cleanup_stale_sessions(timeout: int = 15) -> list[str]:
    """이전 실행이 강제 종료되어 남은 DynamicAnalyzerDNS-* ETW 세션을 정리한다.

    정리한 세션 이름 목록을 반환한다. logman 이 없거나 실패하면 빈 목록.
    """
    try:
        out = subprocess.run(["logman", "query", "-ets"], capture_output=True,
                             timeout=timeout, encoding="utf-8", errors="replace").stdout or ""
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    stopped = []
    for name in sorted(set(_STALE_RE.findall(out))):
        try:
            r = subprocess.run(["logman", "stop", name, "-ets"], capture_output=True, timeout=timeout)
            if r.returncode == 0:
                stopped.append(name)
        except (OSError, subprocess.SubprocessError):
            continue
    return stopped


def parse_query_results(text) -> list[str]:
    """3008 QueryResults 문자열 → 응답 IP 목록.

    예: "type:  5 cdn.example.net;::ffff:203.0.113.10;::ffff:203.0.113.20;"
    'type:' 항목(CNAME 등)은 버리고, IPv4-mapped 접두사를 제거한다.
    """
    out: list[str] = []
    for part in str(text or "").split(";"):
        part = part.strip()
        if not part or part.lower().startswith("type:"):
            continue
        if part.lower().startswith("::ffff:"):
            part = part[7:]
        try:
            ip = str(ipaddress.ip_address(part.split("%", 1)[0]))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def _process_name(pid: int, processes) -> str:
    name = (processes or {}).get(pid)
    if name:
        return name
    try:
        import psutil
        return psutil.Process(pid).name()
    except Exception:
        return f"pid_{pid}"


def rows_from_json_lines(text: str, processes=None) -> list[AttributedDnsQuery]:
    """PowerShell 이 출력한 JSON 라인 → AttributedDnsQuery 목록 (깨진 줄은 건너뜀)."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            pid = int(data["pid"])
            name = str(data["name"]).rstrip(".")
        except (ValueError, KeyError, TypeError):
            continue
        if not name or pid <= 0:
            continue
        status = None
        try:
            if str(data.get("status", "")).strip() != "":
                status = int(data["status"])
        except (TypeError, ValueError):
            status = None
        answers = parse_query_results(data.get("results", ""))
        try:
            ts = float(data.get("time", 0)) / 1000
        except (TypeError, ValueError):
            ts = 0.0
        note = _STATUS_TEXT.get(status, f"상태 코드 {status}") if status not in (None, 0) else ""
        rows.append(AttributedDnsQuery(
            pid, _process_name(pid, processes), name, str(data.get("type", "")),
            answers=answers, timestamp=ts, note=note, status=status, source="etw",
        ))
    return rows


class DnsTrace:
    def __init__(self, output):
        self.path = output / "dns-client.etl"
        self.session = SESSION_PREFIX + uuid.uuid4().hex
        self.active = False
        self.stale_cleaned: list[str] = []

    def start(self):
        # 강제 종료로 남은 이전 세션 정리 (실패해도 진행)
        try:
            self.stale_cleaned = cleanup_stale_sessions()
        except Exception:
            self.stale_cleaned = []
        cmd = ["logman", "start", self.session, "-ets", "-p", "Microsoft-Windows-DNS-Client",
               "0xffffffffffffffff", "5", "-o", str(self.path), "-f", "bincirc", "-max", "32"]
        self.active = subprocess.run(cmd, capture_output=True, timeout=15).returncode == 0
        if self.active:
            atexit.register(self.stop)
        return self.active

    def stop(self):
        if self.active:
            subprocess.run(["logman", "stop", self.session, "-ets"], check=True,
                           capture_output=True, timeout=20)
            self.active = False
            atexit.unregister(self.stop)

    def queries(self, processes, existing=None):
        """ETL 의 3008 이벤트 → AttributedDnsQuery 목록.

        processes: {pid: 이름} — 없으면 psutil 로, 그래도 없으면 pid_N 으로 표기.
        existing: (선택) 이미 수집된 귀속 행 목록. 주면 (이름, ±2초) 중복을
                  제자리에서 병합하고 중복이 아닌 새 행만 반환한다.
        이벤트가 하나도 없으면 빈 목록을 반환한다 (오류 아님).
        """
        script = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
    $events = Get-WinEvent -Path $env:DA_DNS_ETL -Oldest -FilterXPath '*[System[EventID=3008]]'
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or
        $_.Exception.Message -match 'No events were found') { exit 0 }
    throw
}
foreach ($e in $events) {
    $xml=[xml]$e.ToXml()
    $data=@{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name]=$d.InnerText }
    if ($data.QueryName -and $e.ProcessId -gt 0) {
        @{name=$data.QueryName;pid=$e.ProcessId;type=$data.QueryType;
          status=$data.QueryStatus;results=$data.QueryResults;
          time=([DateTimeOffset]$e.TimeCreated).ToUnixTimeMilliseconds()} | ConvertTo-Json -Compress
    }
}
"""
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             env=dict(os.environ, DA_DNS_ETL=str(self.path)), capture_output=True,
                             check=True, timeout=60, encoding="utf-8", errors="replace")
        rows = rows_from_json_lines(out.stdout, processes)
        if existing is not None:
            return merge_dns_attributions(existing, rows)
        return rows
