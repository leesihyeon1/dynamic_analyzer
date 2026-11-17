"""중지 요청과 배경 활동 오귀속 회귀 검사."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.orchestrator import AnalysisConfig, AnalysisResult, _compute_activity_verdict, _stop_requested
from parsers.pcap_parser import PcapResult, NetworkConnection
from parsers.procmon_csv import ProcMonEvent, EventCategory
from core.orchestrator import _scan_procmon_once


class OrchestratorControlTests(unittest.TestCase):
    def test_pipeline_preserves_each_socket(self):
        events = [ProcMonEvent(time_str="12:00:00", process="sample.exe", pid=10,
                              operation="TCP Send", path=f"10.0.0.1:{port} -> 192.0.2.1:https",
                              result="SUCCESS", detail="", category=EventCategory.NETWORK)
                  for port in (50001, 50002)]
        _, connections = _scan_procmon_once(events, set(), {10})
        self.assertEqual({c.local_port for c in connections}, {50001, 50002})
        self.assertEqual({c.remote_port for c in connections}, {443})

    def test_monitor_and_skip_requests(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            self.assertFalse(_stop_requested(root))
            (root / "STOP").write_text("monitor", encoding="utf-8")
            self.assertTrue(_stop_requested(root))
            self.assertFalse(_stop_requested(root, optional=True))
            (root / "STOP").write_text("skip", encoding="utf-8")
            self.assertTrue(_stop_requested(root, optional=True))

    def test_background_activity_does_not_activate_sample(self):
        result = AnalysisResult(AnalysisConfig(sample_path=Path("sample.exe"), output_dir=Path("results")))
        result.sample_pid = 10
        result.lineage_pids = {10}
        result.process_diff = {"new_processes": [SimpleNamespace(pid=20, name="background.exe")]}
        result.pcap_result = PcapResult(connections=[NetworkConnection("TCP", "10.0.0.1", "192.0.2.1", 443)])
        result.analysis_pcap = PcapResult()
        self.assertFalse(_compute_activity_verdict(result)[0])
        result.process_network_map = [SimpleNamespace(pid=10)]
        self.assertTrue(_compute_activity_verdict(result)[0])
