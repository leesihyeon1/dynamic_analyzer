"""실행 성공 표시와 실제 산출물 상태가 다른 경우, 새 JSON 블록(판정·수집 상태·프로세스 행위)을 검증한다."""
import json
import tempfile
import unittest
from pathlib import Path

from core.result_summary import load_result, list_recent_results


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
        self.assertEqual(summary.collection[0][0], "ProcMon")
        self.assertEqual(summary.collection[0][1], "fail")
        self.assertIn("변환 결과 없음", summary.collection[0][2])
        # 계보 정보가 없는 기록은 배경으로 표시하고 샘플 통신으로 단정하지 않는다
        self.assertEqual(summary.connections[0][0], "배경")
        self.assertTrue(any("단정하지 마세요" in w for w in summary.warnings))
        self.assertIn("AI 해석", summary.techniques[0][3])
        self.assertIn("관찰 60초", summary.subtitle)
        self.assertIn("전체 소요 6분 47초", summary.subtitle)
        self.assertIn("PID 6568", summary.subtitle)

    def test_csv_with_parsed_events_is_not_marked_missing(self):
        self.data["events_summary"] = {"total": 12, "filtered": 4}
        self.data["process_network_map"] = []
        self.save()
        (self.folder / "procmon.csv").write_text("header\nrow", encoding="utf-8")
        summary = load_result(self.folder)
        self.assertEqual(summary.title, "분석 결과 확인")
        self.assertEqual(summary.metrics["ProcMon 이벤트"], "12")
        self.assertEqual(summary.collection[0][1], "ok")

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
        self.assertEqual(summary.collection[0][1], "fail")

    def test_empty_csv_is_incomplete(self):
        self.save()
        (self.folder / "procmon.csv").touch()
        row = load_result(self.folder).collection[0]
        self.assertEqual(row[1], "fail")
        self.assertIn("변환 결과 없음", row[2])

    def test_bad_report_is_rejected(self):
        self.save()
        (self.folder / "ping_dynamic_report.json").write_text("[]", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_result(self.folder)

    def test_new_blocks_drive_verdict_processes_and_collection(self):
        self.data.update({
            "report_stage": "preliminary",
            "sample_sha256": "ab" * 32,
            "verdict": {"level": "mal", "label": "악성 · MALICIOUS", "score": 87, "indicators": [
                {"level": "mal", "cat": "지속성", "title": "Run 키 등록", "ev": "HKCU\\...\\Run", "tid": "T1547.001"}]},
            "lineage_pids": [6568, 7000],
            "injected_pids": [7000],
            "process_diff": {"new_processes": [
                {"pid": 6568, "ppid": 900, "name": "WScript.exe", "cmdline": ["C:\\W\\WScript.exe", "C:\\s\\a b.js"]},
                {"pid": 7000, "ppid": 6568, "name": "updater.exe", "cmdline": "updater.exe"},
                {"pid": 8100, "ppid": 1, "name": "svchost.exe", "relevance_tier": 3}]},
            "process_behaviors": {"7000": {"name": "updater.exe", "files_written": ["C:\\x.dll"], "files_written_count": 5,
                                           "tcp_conns": ["198.51.100.7:587"]}},
            "process_network_map": [{"pid": 7000, "process": "updater.exe", "remote_ip": "198.51.100.7", "remote_port": 587},
                                    {"pid": 8100, "process": "svchost.exe", "remote_ip": "203.0.113.9", "remote_port": 443}],
            "collection_status": [{"tool": "ProcMon", "state": "ok", "detail": "이벤트 10건"},
                                  {"tool": "패킷 캡처", "state": "fail", "detail": "패킷 0개", "warn": "캡처 확인"}],
            "ai_analysis": {"pending": True, "provider": "nvidia", "model": "google/gemma-4-31b-it"},
        })
        self.save()
        summary = load_result(self.folder)
        self.assertEqual((summary.verdict_level, summary.score), ("mal", 87))
        self.assertEqual(summary.indicators[0]["tid"], "T1547.001")
        self.assertEqual(summary.report_stage, "preliminary")
        self.assertEqual(summary.ai_state, "pending")
        self.assertEqual(summary.title, "1차 결과 — AI 해석 대기 중")
        self.assertIn("1차 보고서", summary.subtitle)
        self.assertEqual(summary.sha256, "ab" * 32)
        self.assertIn("캡처 확인", summary.warnings)
        procs = {p.pid: p for p in summary.processes}
        self.assertTrue(procs[6568].is_sample)
        self.assertEqual(procs[6568].cmdline, 'C:\\W\\WScript.exe "C:\\s\\a b.js"')
        self.assertTrue(procs[7000].injected)
        self.assertEqual(procs[7000].tier, 1)
        self.assertEqual(procs[7000].files, 5)
        self.assertEqual(procs[8100].tier, 3)
        # 샘플 계보 연결이 배경 연결보다 먼저
        self.assertEqual([c[0] for c in summary.connections], ["샘플 계보", "배경"])

    def test_ai_sections_are_extracted(self):
        self.data["ai_analysis"] = {"model": "x/y", "response": "## 핵심 요약\n로더가 DLL 을 떨궜다.\n\n**결론**\n악성.\n\n마이터 기법 목록\nT1|a|b|c"}
        self.save()
        summary = load_result(self.folder)
        self.assertEqual(summary.ai_state, "done")
        self.assertEqual([t for t, _b in summary.ai_summary], ["핵심 요약", "결론"])

    def test_recent_results_reads_index(self):
        root = self.folder / "results"
        a = root / "invoice_20261118_140212_000001"
        b = root / "ping_20261027_150200_000001"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        (a / "index.json").write_text(json.dumps({"sample": "invoice.js", "level": "mal"}), encoding="utf-8")
        (root / "ui-preview").mkdir()
        items = list_recent_results(root)
        self.assertEqual({i.sample for i in items}, {"invoice.js", "ping"})
        self.assertEqual({i.sample: i.level for i in items}["invoice.js"], "mal")


if __name__ == "__main__":
    unittest.main()
