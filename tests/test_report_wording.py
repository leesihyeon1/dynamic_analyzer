"""보고서 화면 문구 — 내부 용어·식별자가 다시 새어 나오지 않는지, 숨긴 행을 다시 펼칠 수 있는지 확인한다."""
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from analysis.relevance import TIER_SHORT
from exporters import evidence_tab, html_report
from exporters.html_report import generate_html_report
from tools.demo_report import build_result

# 화면에 보이면 안 되는 말 — 분석가가 아닌 사람도 읽을 수 있게 바꾼 용어와 코드 내부 이름
_JARGON = ("계보", "귀속", "인젝션", "쉘코드", "엔트로피", "베이스라인", "관련도", "단명",
           "execution_verdict", "MALICIOUS", "SUSPICIOUS", "BROWSER_INFRA", "IP 룩업", "focus 편입",
           "로컬룰", "사이드로딩탐지")


def _visible_text(html: str) -> str:
    html = re.sub(r"<(script|style)\b.*?</\1>", " ", html, flags=re.S | re.I)
    html = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    return re.sub(r"<[^>]+>", " ", html)


class ReportWordingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = TemporaryDirectory(dir=Path(__file__).parent)
        out = Path(cls._tmp.name)
        result = build_result(out)
        generate_html_report(result, str(out / "demo_dynamic_report.html"))
        cls.pages = {name: (out / name).read_text(encoding="utf-8")
                     for name in ("demo_dynamic_report.html", "demo_dynamic_report_detailed.html")}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_tier_labels_are_one_vocabulary(self):
        self.assertEqual({t: meta[0] for t, meta in html_report._TIER_META.items()}, TIER_SHORT)
        self.assertEqual({t: badge[0] for t, badge in evidence_tab._TIER_BADGE.items()}, TIER_SHORT)

    def test_no_jargon_or_internal_names_on_screen(self):
        for name, page in self.pages.items():
            text = _visible_text(page)
            for word in _JARGON:
                with self.subTest(page=name, word=word):
                    self.assertNotIn(word, text)

    def test_hidden_rows_can_be_shown_again(self):
        for name, page in self.pages.items():
            with self.subTest(page=name):
                # 평상시 활동은 처음에 숨기므로 다시 펼칠 단추가 화면에 있어야 한다
                self.assertIn("setTierFilter(2)", page)
                self.assertIn("data-tierlevel='3'", page)
                self.assertIn("id='scope-note'", page)

    def test_duplicates_removed(self):
        detailed = self.pages["demo_dynamic_report_detailed.html"]
        self.assertNotIn("class='atk'", detailed)                 # 탭마다 반복되던 ATT&CK 블록
        self.assertNotIn('class="metric-grid"', detailed)         # 판정 요약과 겹치던 헤더 지표
        self.assertNotIn("<th>실행 경로</th><th>명령줄</th>", detailed)
        self.assertEqual(detailed.count("<section class='bg'"), 1)  # 행위 그래프는 하나

    def test_summary_keeps_verdict_evidence(self):
        # 요약판은 접힌 부록을 지우지만, 판정 근거 목록은 부록이 아니라 판정의 근거다
        summary = self.pages["demo_dynamic_report.html"]
        self.assertIn("class='va-block'", summary)
        self.assertIn("악성 근거", _visible_text(summary))


if __name__ == "__main__":
    unittest.main()
