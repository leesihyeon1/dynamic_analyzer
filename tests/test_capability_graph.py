"""실제 프로토콜 근거와 포트 번호를 혼동하지 않는지 확인한다."""
import unittest
from pathlib import Path
from dataclasses import replace
from parsers.pcap_parser import FtpSession, HTTPRequest, TLSInfo, _parse_ftp_raw, _parse_smtp_raw
from exporters.capability_graph import capability_preview_html
from tools.demo_report import build_result
from tempfile import TemporaryDirectory


class CapabilityDiagramTests(unittest.TestCase):
    def test_protocol_evidence_and_process_scope(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as d:
            result = build_result(Path(d))
            view = capability_preview_html(result)
            self.assertIn("TCP 소켓", view)
            self.assertIn("93.184.216.34:587", view)
            self.assertNotIn("SMTP", view)
            self.assertNotIn("msedgewebview2.exe", view)
            self.assertIn("lua51.dll", view.lower())
            result.pcap_result.ftp_sessions = [FtpSession("10.0.0.1","10.0.0.2",21, uploaded=["secret<test>.txt"])]
            result.pcap_result.http_requests = [HTTPRequest("POST","example.test","/post","agent",authorization="fixture-secret")]
            result.pcap_result.tls_info = [TLSInfo("example.test","10.0.0.2",443,ja3="example-ja3")]
            view = capability_preview_html(result)
            packet_group = view.split("aria-label='패킷 캡처 관측 관계'")[1]
            for expected in ("프로세스 귀속 미확인","FTP STOR","secret&lt;test&gt;.txt","HTTP POST","TLS ClientHello","example-ja3"):
                self.assertIn(expected, packet_group)
            self.assertNotIn("fixture-secret", view)

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
            view = capability_preview_html(result)
            lane = view.split("aria-label='updater.exe 관측 관계'")[1].split("</section>")[0]
            self.assertIn("EHLO/HELO data.example.test", lane)
            self.assertNotIn("SMTP DATA", view)
            result.procmon_events.append(replace(event, pid=3476))
            view = capability_preview_html(result)
            packet_group = view.split("aria-label='패킷 캡처 관측 관계'")[1]
            self.assertIn("EHLO/HELO data.example.test", packet_group)
            self.assertNotIn("EHLO/HELO", view.split("aria-label='패킷 캡처 관측 관계'")[0])

    def test_full_ftp_filename_from_command(self):
        session = _parse_ftp_raw(b"STOR files/my report.txt\r\nRETRIEVE invalid\r\n",
                                 "10.0.0.1", "10.0.0.2", 21)
        self.assertEqual(session.uploaded, ["files/my report.txt"])
        self.assertEqual(session.downloaded, [])
