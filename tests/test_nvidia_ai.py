"""외부 전송 없이 NVIDIA 요청·인증 오류·응답 처리를 검증한다."""
import json
import urllib.error
import unittest
from unittest.mock import patch

from core.ai_analyzer import NvidiaAnalyzer, NVIDIA_ENDPOINT, _NoApiRedirect, ai_analysis_to_dict, create_ai_analyzer
from core.config_loader import get_ai_cfg, save_ai_settings


class NvidiaTests(unittest.TestCase):
    def setUp(self):
        self.network = patch("core.ai_analyzer.urllib.request.build_opener")
        self.opener = self.network.start().return_value
        self.addCleanup(self.network.stop)
        self.prompt = patch("core.ai_analyzer._build_prompt", return_value="process and IP summary")
        self.prompt.start()
        self.addCleanup(self.prompt.stop)
        self.behavior = patch("core.ai_analyzer._build_behavioral_text", return_value="")
        self.behavior.start()
        self.addCleanup(self.behavior.stop)

    def respond(self, content="analysis", finish_reason="stop"):
        self.opener.open.return_value.__enter__.return_value.read.return_value = json.dumps({
            "choices": [{"message": {"content": content}, "finish_reason": finish_reason}]
        }).encode()

    def test_request_uses_approved_endpoint_and_summary(self):
        self.respond()
        result = NvidiaAnalyzer("test-key").analyze(object(), timeout=17)
        self.assertFalse(result.error)
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, NVIDIA_ENDPOINT)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(json.loads(request.data)["messages"], [{"role": "user", "content": "process and IP summary"}])
        self.assertEqual(self.opener.open.call_args.kwargs["timeout"], 17)
        exported = ai_analysis_to_dict(result)
        self.assertEqual(exported["provider"], "nvidia")
        self.assertNotIn("test-key", json.dumps(exported))

    def test_missing_key_makes_no_request(self):
        result = NvidiaAnalyzer().analyze(object())
        self.assertTrue(result.error)
        self.opener.open.assert_not_called()

    def test_api_key_is_redacted_from_prompt_and_result(self):
        self.respond(content="analysis test-key")
        with patch("core.ai_analyzer._build_prompt", return_value="summary test-key"):
            result = NvidiaAnalyzer("test-key").analyze(object())
        self.assertNotIn("test-key", self.opener.open.call_args.args[0].data.decode())
        self.assertNotIn("test-key", json.dumps(ai_analysis_to_dict(result)))

    def test_http_error_does_not_expose_body_or_credentials(self):
        for status in (401, 403, 410, 429, 500):
            with self.subTest(status=status):
                self.opener.open.side_effect = urllib.error.HTTPError(NVIDIA_ENDPOINT, status, "test-key", {}, None)
                result = NvidiaAnalyzer("test-key").analyze(object())
                self.assertIn(str(status), result.error)
                self.assertNotIn("test-key", result.error)

    def test_empty_content_is_reported_as_error(self):
        self.respond(content=None)
        self.assertTrue(NvidiaAnalyzer("test-key").analyze(object()).error)

    def test_length_limit_is_visible(self):
        self.respond(finish_reason="length")
        result = NvidiaAnalyzer("test-key").analyze(object())
        self.assertIn("토큰 한도", result.response)

    def test_redirect_is_not_followed(self):
        self.assertIsNone(_NoApiRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))

    @patch("core.config_loader.get_ai_cfg", return_value={"api_key": "test-key", "model": "chosen/model"})
    def test_factory_defaults_to_nvidia(self, _config):
        analyzer = create_ai_analyzer()
        self.assertIsInstance(analyzer, NvidiaAnalyzer)
        self.assertEqual(analyzer.model, "chosen/model")

    @patch("core.config_loader.load_config", return_value={"ai": {"api_key": "config-key", "model": "config/model"}})
    def test_config_has_priority_over_environment(self, _config):
        with patch.dict("os.environ", {"NVIDIA_API_KEY": "env-key", "NVIDIA_MODEL": "env/model"}):
            self.assertEqual(get_ai_cfg()["api_key"], "config-key")
            self.assertEqual(get_ai_cfg()["model"], "config/model")

    @patch("core.config_loader.load_config", return_value={"ai": {"api_key": "", "model": ""}})
    def test_empty_config_uses_environment(self, _config):
        with patch.dict("os.environ", {"NVIDIA_API_KEY": "env-key", "NVIDIA_MODEL": "env/model"}):
            self.assertEqual(get_ai_cfg()["api_key"], "env-key")
            self.assertEqual(get_ai_cfg()["model"], "env/model")

    @patch("core.config_loader.CONFIG_PATH")
    def test_gui_save_preserves_other_sections_and_existing_key(self, path):
        original = {"_comment": "keep", "tools": {"path": "unchanged"},
                    "virustotal": {"api_key": "fixture-vt-key"},
                    "ai": {"_comment": "keep ai comment", "api_key": "fixture-key", "model": "old/model"}}
        path.exists.return_value = True
        path.read_text.return_value = json.dumps(original)
        save_ai_settings("new/model")
        saved = json.loads(path.write_text.call_args.args[0])
        self.assertEqual(saved["tools"], original["tools"])
        self.assertEqual(saved["virustotal"], original["virustotal"])
        self.assertEqual(saved["ai"]["api_key"], "fixture-key")
        self.assertEqual(saved["ai"]["model"], "new/model")
        self.assertEqual(saved["ai"]["_comment"], "keep ai comment")

    @patch("core.config_loader.CONFIG_PATH")
    def test_gui_save_updates_key_in_config(self, path):
        path.exists.return_value = True
        path.read_text.return_value = '{"ai":{"api_key":"old-fixture"}}'
        save_ai_settings("model", "new-fixture")
        self.assertEqual(json.loads(path.write_text.call_args.args[0])["ai"]["api_key"], "new-fixture")

    @patch("core.config_loader.CONFIG_PATH")
    def test_invalid_config_is_not_overwritten(self, path):
        path.exists.return_value = True
        path.read_text.return_value = 'not valid JSON'
        with self.assertRaises(ValueError):
            save_ai_settings("model", "fixture")
        path.write_text.assert_not_called()


if __name__ == "__main__":
    unittest.main()
