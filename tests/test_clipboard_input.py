import unittest
from types import SimpleNamespace as N
from unittest.mock import Mock, patch
from gui import AnalyzerGUI

class ClipboardInputTests(unittest.TestCase):
    def app(self):
        return N(running=False,loading=False,path=Mock(),root=Mock())

    def test_explorer_file(self):
        app=self.app()
        with patch('core.clipboard_files.read_copied_files',return_value=['C:/한글 문서.doc']), patch('gui.Path.is_file',return_value=True):
            self.assertEqual(AnalyzerGUI.paste_file(app),'break')
        self.assertIn('한글 문서.doc',app.path.set.call_args.args[0])
        app.root.clipboard_get.assert_not_called()

    def test_quoted_text_path(self):
        app=self.app(); app.root.clipboard_get.return_value='"C:/test file.doc"'
        with patch('core.clipboard_files.read_copied_files',return_value=[]), patch('gui.Path.is_file',return_value=True):
            AnalyzerGUI.paste_file(app)
        self.assertNotIn('"',app.path.set.call_args.args[0])

    def test_multiple_files_rejected(self):
        app=self.app()
        with patch('core.clipboard_files.read_copied_files',side_effect=ValueError('파일 하나만')), patch('gui.messagebox.showerror') as error:
            AnalyzerGUI.paste_file(app)
        app.path.set.assert_not_called(); error.assert_called_once()

    def test_running_does_not_read_clipboard(self):
        app=self.app(); app.running=True
        with patch('core.clipboard_files.read_copied_files') as read:
            AnalyzerGUI.paste_file(app)
        read.assert_not_called()
