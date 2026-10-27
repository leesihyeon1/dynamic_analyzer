"""실행 성공 표시와 실제 산출물 상태가 다른 경우를 검증한다."""
import json
import tempfile
import unittest
from pathlib import Path

from core.result_summary import load_result


class ResultSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.folder = Path(self.temp.name)
        self.data = {
            "sample": "C:\\samples\\ping.exe", "timeout": 60, "duration": 407.5,
            "sample_pid": 6568, "all_pids": [6568], "errors": [],
            "tools_used": {"procmon": True, "tshark": True},
            "events_summary": {"total": 0, "filtered": 0},
            "network": {"packets_loaded": 145, "connections": []},
            "mitre_techniques": [{"id": "T1055", "name": "Injection", "evidence": ["CAPA", "[AI] test"]}],
            "process_network_map": [{"pid": 4424, "process": "ollama.exe", "remote_ip": "192.0.2.1", "remote_port": 443}],
        }

    def tearDown(self):
        self.assertEqual(self.folder.parent, Path(__file__).resolve().parent)
        self.temp.cleanup()

    def save(self):
        (self.folder / "ping_dynamic_report.json").write_text(json.dumps(self.data), encoding="utf-8")
        (self.folder / "ping_dynamic_report.html").write_text("<html></html>", encoding="utf-8")

    def test_missing_csv_overrides_tool_used_flag(self):
        self.save()
        (self.folder / "procmon.pml").write_bytes(b"test fixture")
        summary = load_result(self.folder)
        self.assertEqual(summary.title, "부분 수집 · 확인 필요")
        self.assertEqual(summary.collection[0][1], "변환 결과 없음")
        self.assertEqual(summary.connections[0][-1], "대상 외 PID")
        self.assertIn("AI 해석", summary.techniques[0][2])
        self.assertEqual(summary.subtitle, "모니터링 60초  ·  전체 소요 6분 47초  ·  PID 6568")

    def test_csv_with_parsed_events_is_not_marked_missing(self):
        self.data["events_summary"] = {"total": 12, "filtered": 4}
        self.data["process_network_map"] = []
        self.save()
        (self.folder / "procmon.csv").write_text("header\nrow", encoding="utf-8")
        summary = load_result(self.folder)
        self.assertEqual(summary.title, "분석 결과 확인")
        self.assertEqual(summary.metrics["ProcMon 이벤트"], "12")

    def test_disabled_procmon_without_artifact_is_not_failure(self):
        self.data["tools_used"]["procmon"] = False
        self.data["process_network_map"] = []
        self.save()
        self.assertFalse(load_result(self.folder).warnings)

    def test_missing_report_still_lists_artifacts(self):
        (self.folder / "procmon.pml").write_bytes(b"fixture")
        summary = load_result(self.folder)
        self.assertTrue(summary.warnings)
        self.assertEqual(summary.artifacts[0][0], "procmon.pml")

    def test_empty_csv_is_incomplete(self):
        self.save()
        (self.folder / "procmon.csv").touch()
        self.assertEqual(load_result(self.folder).collection[0][1], "변환 결과 없음")

    def test_bad_report_is_rejected(self):
        self.save()
        (self.folder / "ping_dynamic_report.json").write_text("[]", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_result(self.folder)


if __name__ == "__main__":
    unittest.main()
