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

    @patch("core.ai_analyzer.nvidia_model_candidates", return_value=["first", "second"])
    def test_empty_reasoning_response_retries_and_reads_text_parts(self, _candidates):
        def reply(content, reason):
            return json.dumps({"choices": [{"message": {"content": content}, "finish_reason": reason}]}).encode()
        self.opener.open.return_value.__enter__.return_value.read.side_effect = [
            reply(None, "length"), reply([{"type": "text", "text": "분석 완료"}], "stop")]
        result = NvidiaAnalyzer("test-key", "first").analyze(object())
        self.assertFalse(result.error)
        self.assertEqual(result.model, "second")
        self.assertIn("분석 완료", result.response)

    @patch("core.ai_analyzer.time.sleep")
    @patch("core.ai_analyzer.nvidia_model_candidates", return_value=["primary", "backup"])
    def test_disconnect_retries_then_uses_backup(self, _models, _sleep):
        from http.client import RemoteDisconnected
        self.respond()
        self.opener.open.side_effect = [RemoteDisconnected(), urllib.error.URLError(RemoteDisconnected()),
                                       self.opener.open.return_value]
        result = NvidiaAnalyzer("test-key", "primary").analyze(object())
        self.assertFalse(result.error)
        self.assertEqual([json.loads(call.args[0].data)["model"] for call in self.opener.open.call_args_list],
                         ["primary", "primary", "backup"])
        self.assertEqual(result.model, "backup")

    @patch("core.ai_analyzer.time.sleep")
    @patch("core.ai_analyzer.nvidia_model_candidates", return_value=["primary"])
    def test_persistent_disconnect_is_bounded(self, _models, _sleep):
        from http.client import RemoteDisconnected
        self.opener.open.side_effect = RemoteDisconnected()
        result = NvidiaAnalyzer("test-key", "primary").analyze(object())
        self.assertIn("세 차례", result.error)
        self.assertEqual(self.opener.open.call_count, 3)

    def test_empty_content_is_reported_as_error(self):
        self.respond(content=None)
        self.assertTrue(NvidiaAnalyzer("test-key").analyze(object()).error)

    @patch("core.ai_analyzer.nvidia_model_candidates", return_value=["test-model"])
    def test_prompt_failure_recovers_with_observed_evidence(self, _models):
        from types import SimpleNamespace as NS
        result = NS(behavior_report=NS(techniques=[
            NS(technique_id="T1055", sources=["로컬룰"], evidence=["fixture evidence"])]))
        self.respond()
        with patch("core.ai_analyzer._build_prompt", side_effect=AttributeError("test-key")):
            ai = NvidiaAnalyzer("test-key").analyze(result)
        self.assertFalse(ai.error)
        self.assertIn("fixture evidence", json.loads(self.opener.open.call_args.args[0].data)["messages"][0]["content"])
        self.assertIn("근거 요약", ai.response)

    def test_internal_error_identifies_stage_without_secret(self):
        with patch("core.ai_analyzer._build_prompt", side_effect=AttributeError("test-key")):
            ai = NvidiaAnalyzer("test-key").analyze(object())
        self.assertIn("분석 자료 구성 실패", ai.error)
        self.assertIn("AttributeError", ai.error)
        self.assertNotIn("test-key", ai.error)
        self.opener.open.assert_not_called()

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
