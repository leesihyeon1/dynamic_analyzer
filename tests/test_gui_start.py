"""실제 샘플을 실행하지 않고 시작 버튼의 탭 전환을 검증한다."""
import tkinter as tk
import unittest
from unittest.mock import patch

from gui import AnalyzerGUI


class GUIStartTests(unittest.TestCase):
    def test_start_selects_registered_log_tab_before_launching_worker(self):
        root = tk.Tk()
        root.withdraw()
        try:
            app = AnalyzerGUI(root)
            for filename in ("C:/fixture.exe", "C:/fixture.pcapng", "C:/fixture.doc", "C:/fixture.DOCX", "C:/fixture.xlsm", "C:/fixture.pdf", "C:/fixture.js"):
                with self.subTest(filename=filename):
                    app.running = False
                    app.path.set(filename)
                    app.tabs.select(app.overview)
                    with patch("gui.Path.is_file", return_value=True), \
                         patch("gui.messagebox.askyesno", return_value=True), \
                         patch("gui.threading.Thread") as worker:
                        app.start()
                    self.assertEqual(app.tabs.select(), str(app.log_tab))
                    self.assertTrue(app.running)
                    worker.return_value.start.assert_called_once()
        finally:
            for callback in root.tk.call("after", "info"):
                root.tk.call("after", "cancel", callback)
            root.destroy()


if __name__ == "__main__":
    unittest.main()
