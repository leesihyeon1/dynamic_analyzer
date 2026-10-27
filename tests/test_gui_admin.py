"""GUI 권한 유지와 분석 프로세스 승격을 검증한다."""
import queue
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as N
from unittest.mock import Mock, patch
from gui import AnalyzerGUI

class GUIAdminTests(unittest.TestCase):
    def test_worker_elevates_and_forwards_log(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            app=N(output=Path(d),events=queue.Queue())
            windll=N(shell32=N(IsUserAnAdmin=lambda: False))
            def launch(command, output, callback):
                callback("분석 로그")
                return 0
            with patch('gui.sys.platform','win32'), patch('gui.ctypes.windll',windll,create=True), patch('core.elevated_runner.run_elevated',side_effect=launch) as run, patch('gui.subprocess.Popen') as direct:
                AnalyzerGUI.run_command(app,['python','-u','analyzer.py','sample.doc'])
            run.assert_called_once(); direct.assert_not_called()
            events=list(app.events.queue)
            self.assertIn(('line','분석 로그'),events)
            self.assertIn(('done',0),events)

    def test_uac_cancel_reports_error(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as d:
            app=N(output=Path(d),events=queue.Queue())
            windll=N(shell32=N(IsUserAnAdmin=lambda: False))
            with patch('gui.sys.platform','win32'), patch('gui.ctypes.windll',windll,create=True), patch('core.elevated_runner.run_elevated',side_effect=OSError('권한 요청 취소')):
                AnalyzerGUI.run_command(app,[])
            self.assertIn(('error','권한 요청 취소'),list(app.events.queue))

    def test_main_does_not_request_elevation(self):
        import gui
        fake=Mock()
        with patch('gui.sys.argv',['gui.py']), patch('gui.sys.platform','win32'), patch.dict('sys.modules',{'tkinterdnd2':N(TkinterDnD=N(Tk=lambda:fake))}), patch('gui.AnalyzerGUI') as app:
            gui.main()
        app.assert_called_once_with(fake)
        fake.mainloop.assert_called_once()
