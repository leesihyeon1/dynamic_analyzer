"""DNS-Client ETW 3008 질의 완료 이벤트를 분석 실행 구간에 수집한다."""
import atexit
import json
import os
import subprocess
import uuid

from parsers.dns_correlator import AttributedDnsQuery


class DnsTrace:
    def __init__(self, output):
        self.path = output / "dns-client.etl"
        self.session = "DynamicAnalyzerDNS-" + uuid.uuid4().hex
        self.active = False

    def start(self):
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

    def queries(self, processes):
        script = """
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Get-WinEvent -Path $env:DA_DNS_ETL -Oldest | Where-Object Id -eq 3008 | ForEach-Object {
    $xml=[xml]$_.ToXml()
    $data=@{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name]=$d.InnerText }
    if ($data.QueryName -and $_.ProcessId -gt 0) {
        @{name=$data.QueryName;pid=$_.ProcessId;type=$data.QueryType;time=([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds()} | ConvertTo-Json -Compress
    }
}
"""
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             env=dict(os.environ, DA_DNS_ETL=str(self.path)), capture_output=True,
                             check=True, timeout=60, encoding="utf-8", errors="replace")
        rows = []
        for line in out.stdout.splitlines():
            data = json.loads(line)
            pid = int(data["pid"])
            rows.append(AttributedDnsQuery(pid, processes.get(pid) or "DNS-Client ETW",
                        data["name"], str(data["type"]), timestamp=data["time"]/1000))
        return rows
