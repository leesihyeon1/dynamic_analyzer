"""통합 행위 그래프 — 실행 흐름과 행위가 한 그래프에 올바르게 붙고, 노드가 겹치지 않는지 확인한다."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from exporters.behavior_graph import behavior_graph_html, build_behavior_graph, walk
from tools.demo_report import build_result


def _proc(root, name):
    return next(n for n in walk(root) if n.kind == "proc" and n.label == name)


class BehaviorGraphTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory(dir=Path(__file__).parent)
        self.result = build_result(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_process_flow_carries_its_behaviors(self):
        root, _, _ = build_behavior_graph(self.result, sample_name="invoice.js")
        # 판정 카드 → 샘플 → 로더 → rundll32 → chrome 순으로 실행 흐름이 이어진다
        chain = ["WScript.exe", "updater.exe", "rundll32.exe", "chrome.exe"]
        parent = root
        for name in chain:
            child = next(c for c in parent.children if c.kind == "proc")
            self.assertEqual(child.label, name)
            self.assertEqual((child.attach, child.edge), ("flow", "실행"))
            parent = child
        # 행위는 그 행위를 한 프로세스 옆에 붙는다
        loader = _proc(root, "updater.exe")
        beside = {c.label: c for c in loader.children if c.attach == "comb"}
        self.assertEqual(beside["93.184.216.34:587"].edge, "연결")
        self.assertEqual(beside["lua51.dll"].edge, "사이드로딩")
        self.assertIn("로더", loader.sub)
        sample = _proc(root, "WScript.exe")
        self.assertIn("샘플", sample.sub)
        dropped = {c.label: c.edge for c in sample.children if c.attach == "comb"}
        self.assertEqual(dropped.get("updater.exe"), "드롭")
        # 자식 프로세스로 그려진 실행은 행위 노드로 다시 그리지 않는다
        self.assertNotIn("rundll32.exe", {c.label for c in loader.children if c.attach == "comb"})
        # 계보 밖 프로세스는 그리지 않는다
        self.assertFalse(any("msedgewebview2" in n.label.lower() for n in walk(root)))
        # 판정 카드 옆에는 탐지 근거가 붙는다
        self.assertTrue(any(c.kind == "sig" and c.level == 2 for c in root.children))

    def test_nodes_do_not_overlap(self):
        root, width, height = build_behavior_graph(self.result, sample_name="invoice.js")
        boxes = [(n.left, n.top, n.left + n.w, n.top + n.h, n.label) for n in walk(root)]
        for i, a in enumerate(boxes):
            self.assertTrue(0 <= a[0] and a[2] <= width and 0 <= a[1] and a[3] <= height, a)
            for b in boxes[i + 1:]:
                overlap = a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]
                self.assertFalse(overlap, (a, b))

    def test_single_svg_and_summary_hides_evidence(self):
        detailed = behavior_graph_html(self.result, sample_name="invoice.js")
        self.assertEqual(detailed.count("<svg"), 1)
        self.assertIn("ProcMon ·", detailed)            # 상세판 툴팁에는 원문 근거
        summary = behavior_graph_html(self.result, sample_name="invoice.js", include_evidence=False)
        self.assertEqual(summary.count("<svg"), 1)
        self.assertNotIn("ProcMon ·", summary)
        self.assertIn("bgGo(7144)", summary)             # 노드에서 프로세스 상세로 이동

    def test_empty_result(self):
        self.result.lineage_pids = []
        self.result.sample_pid = None
        self.result.process_diff = {"new_processes": []}
        self.result.filtered_events = []
        self.result.process_network_map = []
        self.result.dns_attributed = []
        self.result.sideload_findings = []
        self.result.injection_findings = []
        self.result.pcap_result = None      # 귀속 미확인 통신(응답 없는 DNS)도 없앤다
        html = behavior_graph_html(self.result, verdict={"level": "ok", "score": 0, "indicators": []})
        self.assertIn("그래프로 표시할 행위가 없습니다", html)


if __name__ == "__main__":
    unittest.main()
