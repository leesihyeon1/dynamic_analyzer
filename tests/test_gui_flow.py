"""샘플을 실행하지 않고 GUI 진행 표시·조기 종료·도구 점검 반영을 검증한다."""
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

import gui
from gui import AnalyzerGUI, STOP_FILE


class GUIFlowTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        with patch.object(AnalyzerGUI, "run_preflight"), patch.object(AnalyzerGUI, "refresh_recent"):
            self.app = AnalyzerGUI(self.root)
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)

    def tearDown(self):
        for callback in self.root.tk.call("after", "info"):
            self.root.tk.call("after", "cancel", callback)
        self.root.destroy()
        self.temp.cleanup()

    def test_log_lines_advance_stepper_and_observe_clock(self):
        app = self.app
        app.running = True
        for line in ("[1/6] 사전 스냅샷 수집 중...", "[2/6] 모니터링 시작...", "[3/6] 샘플 실행: a.js",
                     "[4/6] 모니터링 중... (90초)  Ctrl+C로 조기 종료 가능"):
            app.on_line(line)
        self.assertEqual(app.stage, "observe")
        self.assertEqual(app.observe_total, 90)
        self.assertEqual(app.stepper.states["snap"], "done")
        self.assertEqual(app.stepper.states["observe"], "active")
        app.on_line("[분석] ProcMon CSV 파싱...")
        self.assertEqual(app.stage, "analyze")
        self.assertEqual(app.stepper.states["observe"], "done")
        # 로그에 나오지 않은 단계는 생략 표시
        self.assertEqual(app.stepper.states["scan"], "skipped")

    def test_preliminary_report_line_loads_result_once(self):
        app = self.app
        app.running = True
        app.output = Path(self.temp.name)
        with patch.object(app, "request_result") as load:
            app.on_line("[보고서] 1차 보고서 저장 완료 — AI 해석은 끝나는 대로 반영")
            app.on_line("[보고서] 1차 보고서 저장 완료")
        load.assert_called_once()
        self.assertEqual(app.stage, "report")

    def test_stop_request_escalates_from_monitor_to_skip(self):
        app = self.app
        app.running = True
        app.output = Path(self.temp.name)
        app.stage = "observe"
        app.request_stop()
        self.assertEqual((app.output / STOP_FILE).read_text(encoding="utf-8"), "monitor")
        with patch("gui.messagebox.askyesno", return_value=True):
            app.request_stop()
        self.assertEqual((app.output / STOP_FILE).read_text(encoding="utf-8"), "skip")
        self.assertEqual(str(app.stop_button.cget("state")), "disabled")

    def test_stop_after_monitoring_asks_before_skipping(self):
        app = self.app
        app.running = True
        app.output = Path(self.temp.name)
        app.stage = "analyze"
        with patch("gui.messagebox.askyesno", return_value=False):
            app.request_stop()
        self.assertFalse((app.output / STOP_FILE).exists())

    def test_missing_tools_are_unchecked_and_restored(self):
        app = self.app
        self.assertTrue(app.options["procmon"].get())
        app.show_preflight({"admin": True, "procmon": None, "tshark": "C:/t/tshark.exe", "ai": "m", "ai_model": "m"})
        self.assertFalse(app.options["procmon"].get())
        self.assertEqual(str(app.checks["procmon"].cget("state")), "disabled")
        app.show_preflight({"admin": True, "procmon": "C:/t/Procmon.exe", "tshark": "C:/t/tshark.exe", "ai": "m", "ai_model": "m"})
        self.assertTrue(app.options["procmon"].get())

    def test_log_classification(self):
        self.assertEqual(AnalyzerGUI.classify("      [오류] 캡처 파일 없음"), "err")
        self.assertEqual(AnalyzerGUI.classify("[!] 샘플 비활성 추정"), "warn")
        self.assertEqual(AnalyzerGUI.classify("[4/6] 모니터링 중... (60초)"), "stage")
        self.assertEqual(AnalyzerGUI.classify("      5s 경과 / 잔여 55s..."), "muted")

    def test_tail_log_reads_split_utf8_and_returns_code(self):
        log = Path(self.temp.name) / "run.log"
        text = "[1/6] 사전 스냅샷\n[완료] 총 소요 3초".encode("utf-8")
        log.write_bytes(b"")
        chunks = [text[:5], text[5:9], text[9:]]   # 한글 바이트 중간에서 잘린 조각
        state = {"n": 0}

        def poll():
            n = state["n"]
            state["n"] += 1
            if n < len(chunks):
                with log.open("ab") as fh:
                    fh.write(chunks[n])
                return None
            return 0
        lines = []
        with patch("gui.time.sleep"):
            code = gui.tail_log(log, poll, lines.append)
        self.assertEqual(code, 0)
        self.assertEqual(lines, ["[1/6] 사전 스냅샷", "[완료] 총 소요 3초"])

    def test_sample_launch_failure_exit_code_is_explained(self):
        app = self.app
        app.running = True
        app.output = Path(self.temp.name)
        app.started_at = 0.0
        with patch.object(app, "request_result"), patch.object(app, "refresh_recent"):
            app.finish_run("done", 2)
        self.assertIn("샘플을 실행하지 못했습니다", app.status.get())
        self.assertEqual(app.verdict_label.cget("text"), "샘플 실행 실패")
        self.assertFalse(app.running)

    def test_final_reload_is_queued_while_preliminary_load_runs(self):
        app = self.app
        app.loading = True
        app.request_result(Path(self.temp.name))
        self.assertEqual(app._reload_pending, (Path(self.temp.name), False))

    def test_build_command_maps_options(self):
        cmd = gui.build_command(Path("C:/s/a.exe"), Path("C:/r/out"), 120, procmon=False, tshark=True, ph=False,
                                keylog=False, ai=False, memdump=True, fakenet=False)
        self.assertIn("--no-procmon", cmd)
        self.assertIn("--no-ai", cmd)
        self.assertIn("--memdump", cmd)
        self.assertEqual(cmd[cmd.index("--timeout") + 1], "120")
        pcap = gui.build_command(Path("C:/s/c.pcapng"), Path("C:/r/o"), 60, procmon=True, tshark=True, ph=True,
                                 keylog=True, ai=True, memdump=False, fakenet=False)
        self.assertIn("--pcap", pcap)


if __name__ == "__main__":
    unittest.main()
