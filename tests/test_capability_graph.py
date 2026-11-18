"""실제 프로토콜 근거와 포트 번호를 혼동하지 않는지, 세션을 올바른 프로세스에 붙이는지 확인한다."""
import unittest
from pathlib import Path
from dataclasses import replace
from parsers.pcap_parser import FtpSession, HTTPRequest, TLSInfo, _parse_ftp_raw, _parse_smtp_raw
from exporters.capability_graph import _collect
from tools.demo_report import build_result
from tempfile import TemporaryDirectory


def _lines(groups, pid):
    """pid 의 관측을 '동작 | 대상 | 상세' 문자열로 펼친다 (None = 프로세스 미확인)."""
    return [f"{action} | {target} | {detail}"
            for (action, _icon), targets in groups.get(pid, {}).items()
            for (target, _), (detail, _count, _level) in targets.items()]


def _all(groups):
    return "\n".join(line for pid in groups for line in _lines(groups, pid))


class CapabilityDiagramTests(unittest.TestCase):
    def test_protocol_evidence_and_process_scope(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as d:
            result = build_result(Path(d))
            groups, _procs, names, _lineage, _loaders = _collect(result)
            loader = "\n".join(_lines(groups, 7144))
            self.assertIn("TCP 소켓 | 93.184.216.34:587", loader)
            self.assertNotIn("SMTP", _all(groups))              # 포트 587 만으로 SMTP 라 하지 않는다
            self.assertNotIn("msedgewebview2.exe", {names.get(pid, "") for pid in groups})
            self.assertIn("lua51.dll", _all(groups).lower())
            result.pcap_result.ftp_sessions = [FtpSession("10.0.0.1","10.0.0.2",21, uploaded=["secret<test>.txt"])]
            result.pcap_result.http_requests = [HTTPRequest("POST","example.test","/post","agent",authorization="fixture-secret")]
            result.pcap_result.tls_info = [TLSInfo("example.test","10.0.0.2",443,ja3="example-ja3")]
            groups = _collect(result).groups
            unattributed = "\n".join(_lines(groups, None))
            for expected in ("FTP STOR | secret<test>.txt", "HTTP POST", "TLS ClientHello", "example-ja3"):
                self.assertIn(expected, unattributed)
            self.assertNotIn("fixture-secret", _all(groups))     # 인증 헤더는 보고서에 싣지 않는다

    def test_exact_socket_owner_and_ambiguous_reuse(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as d:
            result = build_result(Path(d))
            src, dst = "10.0.0.1", "10.0.0.2"
            session = _parse_smtp_raw(b"EHLO data.example.test\r\n", src, dst, 587)
            self.assertFalse(session.has_data)
            session.src_port = 51234
            result.pcap_result.smtp_sessions = [session]
            event = replace(result.filtered_events[0], operation="TCP Send", process="updater.exe",
                            pid=7144, path=f"{src}:51234 -> {dst}:587")
            result.procmon_events.append(event)
            groups = _collect(result).groups
            self.assertIn("EHLO/HELO data.example.test", "\n".join(_lines(groups, 7144)))
            self.assertNotIn("SMTP DATA", _all(groups))
            # 같은 소켓을 다른 PID 도 썼다면 어느 쪽인지 단정하지 않는다
            result.procmon_events.append(replace(event, pid=3476))
            groups = _collect(result).groups
            self.assertIn("EHLO/HELO data.example.test", "\n".join(_lines(groups, None)))
            self.assertNotIn("EHLO/HELO", "\n".join(_lines(groups, 7144)))

    def test_full_ftp_filename_from_command(self):
        session = _parse_ftp_raw(b"STOR files/my report.txt\r\nRETRIEVE invalid\r\n",
                                 "10.0.0.1", "10.0.0.2", 21)
        self.assertEqual(session.uploaded, ["files/my report.txt"])
        self.assertEqual(session.downloaded, [])
