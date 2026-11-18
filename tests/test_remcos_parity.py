"""ANY.RUN Remcos 분석과 대조해 드러난 결함의 회귀 검사.

정적 분석 원본 보존 · Edge 업데이트 소음 · DGA 오판정 · 패밀리 지문/수집 행위 ·
일반 사용자 권한 실행 옵션 · YARA 공유 모드 대체 · 캡처 정책.
"""
import hashlib
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest.mock import patch

from parsers.procmon_csv import EventCategory, ProcMonEvent

U = r"C:\Users\chll9"
REMCOS = r"C:\ProgramData\Remcos\remcos.exe"
EDGE_SETUP = (r"C:\Program Files (x86)\Microsoft\EdgeUpdate\Install"
              r"\{1A31E23B-6C44-4951-9D11-CF0DC1DD62F1}\EDGEMITMP_D3D79.tmp\setup.exe")


def _ev(proc, pid, op, path, cat, detail=""):
    return ProcMonEvent("23:14:31.0", proc, pid, op, path, "SUCCESS", detail, cat)


def _remcos_result():
    events = [
        _ev("ggggg.exe", 9408, "RegSetValue", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Rmc-YAFLUV",
            EventCategory.REGISTRY, f'Type: REG_SZ, Data: "{REMCOS}"'),
        _ev("ggggg.exe", 9408, "CreateFile", REMCOS, EventCategory.FILE, "OpenResult: Created"),
        _ev("remcos.exe", 6316, "WriteFile", r"C:\ProgramData\Remcos\logs.dat", EventCategory.FILE, "Offset: 0"),
        _ev("remcos.exe", 6316, "WriteFile", U + r"\AppData\Roaming\Screenshots\time_20261118_231433.jpg",
            EventCategory.FILE, "Offset: 0"),
        # 계보 밖 프로세스가 같은 이름의 파일을 써도 패밀리 근거가 아니다
        _ev("notepad.exe", 1111, "WriteFile", r"C:\Temp\remcos\logs.dat", EventCategory.FILE, "Offset: 0"),
    ]
    from analysis.behavior_classifier import BehaviorReport
    return NS(filtered_events=events, procmon_events=events, lineage_pids={9408, 6316},
              registry_diff={"added": [(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                        "Rmc-YAFLUV", f'"{REMCOS}"')]},
              mem_forensics={}, behavior_report=BehaviorReport(),
              ioc_report=NS(dropped_files=[REMCOS]))


class DgaTests(unittest.TestCase):
    def test_repeated_c2_lookups_are_not_dga_or_tunnel(self):
        from parsers.pcap_parser import _base_domain, _dns_reasons, _is_excluded_dns_name, _subdomain_entropy
        names = ["vn168s.in.net"] * 40 + [p + ".vn168s.in.net" for p in ("api", "c2", "app", "www")]
        base_names = {}
        for n in names:
            base_names.setdefault(_base_domain(n), set()).add(n)
        self.assertEqual(_base_domain("api.vn168s.in.net"), "vn168s.in.net")   # in.net 은 공개 접미사
        for n in set(names):
            self.assertEqual(_dns_reasons(n, _subdomain_entropy(n), base_names), [], n)
        self.assertTrue(_is_excluded_dns_name("DESKTOP-V1V0RUB._dosvc._tcp.local"))
        self.assertIn("dga", _dns_reasons("xk3j9qz8w1p0vbn7tqa.com", 3.9, {}))
        many = {"example.org": {f"{i:04x}a.t.example.org" for i in range(25)}}
        self.assertIn("tunnel", _dns_reasons("0001a.t.example.org", 1.0, many))

    def test_dga_technique_only_for_entropy_names(self):
        from analysis.behavior_classifier import BehaviorReport, _classify_network
        from parsers.pcap_parser import DNSQuery, PcapResult
        pcap = PcapResult(dns_queries=[DNSQuery("vn168s.in.net", "A", entropy=2.58, suspicious=True,
                                                reasons=["tunnel"])],
                          suspicious_domains=["vn168s.in.net"], dga_domains=[])
        tmap = {}
        _classify_network(pcap, tmap, BehaviorReport())
        self.assertNotIn("T1568.002", tmap)
        pcap.dga_domains = ["xk3j9qz8w1p0vbn7tqa.com"]
        _classify_network(pcap, tmap, BehaviorReport())
        self.assertIn("T1568.002", tmap)


class EdgeNoiseTests(unittest.TestCase):
    def setUp(self):
        from analysis import relevance as R
        self.R = R

        class Stale:   # 오래된 평상시 기준 — 새 Edge 설치 파일을 모른다
            def has_exe(self, p): return False
            def has_process(self, n): return False
            def has_file(self, p): return False
        self.ctx = R.RelevanceContext(lineage_pids={9408, 6316}, baseline=Stale())
        self.ctx.lineage_names = {"ggggg.exe", "remcos.exe"}
        self.ctx.lineage_paths = {R.normalize_path(REMCOS)}
        self.ctx.pid_names = {7436: "setup.exe"}
        self.ctx.pid_exes = {7436: EDGE_SETUP}

    def test_builtin_profile_applies_even_with_baseline(self):
        R, ctx = self.R, self.ctx
        self.assertEqual(R.tier_process(NS(pid=7436, name="setup.exe", exe=EDGE_SETUP, ppid=7244), ctx),
                         R.TIER_BACKGROUND)
        self.assertEqual(R.tier_process(NS(pid=7244, name="microsoftedgeupdate.exe", exe="", ppid=1), ctx),
                         R.TIER_BACKGROUND)
        self.assertEqual(R.tier_file(r"C:\Program Files (x86)\Microsoft\Edge\Application\157\msedge.dll", ctx),
                         R.TIER_BACKGROUND)
        self.assertEqual(R.tier_file(U + r"\AppData\Local\Temp\{B5FB9AF7}-MicrosoftEdge_X64_157.0.exe", ctx),
                         R.TIER_BACKGROUND)
        # 샘플 행위는 그대로
        self.assertEqual(R.tier_process(NS(pid=6316, name="remcos.exe", exe=REMCOS, ppid=9408), ctx),
                         R.TIER_SAMPLE)
        self.assertEqual(R.tier_file(REMCOS, ctx), R.TIER_SAMPLE)

    def test_common_name_demoted_only_when_every_exe_is_background(self):
        R, ctx = self.R, self.ctx
        self.assertEqual(R._process_name_tier("setup.exe", ctx), R.TIER_BACKGROUND)
        ctx.pid_names[1234] = "setup.exe"
        ctx.pid_exes[1234] = U + r"\Downloads\setup.exe"
        self.assertEqual(R._process_name_tier("setup.exe", ctx), R.TIER_CORRELATED)

    def test_edge_service_reregistration_is_vendor_activity(self):
        from analysis.behavior_classifier import _vendor_service_names
        events = [
            _ev("services.exe", 700, "RegSetValue",
                r"HKLM\System\CurrentControlSet\Services\MicrosoftEdgeElevationService\ImagePath",
                EventCategory.REGISTRY, r'Type: REG_EXPAND_SZ, Data: "C:\Program Files (x86)\Microsoft'
                                        r'\Edge\Application\157.0.4341.60\elevation_service.exe"'),
            _ev("services.exe", 700, "RegSetValue", r"HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath",
                EventCategory.REGISTRY, r'Type: REG_EXPAND_SZ, Data: "C:\ProgramData\evil\svc.exe"'),
        ]
        self.assertEqual(_vendor_service_names(events), {"microsoftedgeelevationservice"})

    def test_capture_policy_turns_off_edge_updates(self):
        from core import vm_setup
        labels = {p.label for p in vm_setup._policies()}
        self.assertTrue({"Edge 자동 업데이트", "Edge 업데이트 확인"} <= labels)


class SamplePreservationTests(unittest.TestCase):
    def test_hash_and_copy_survive_self_deletion(self):
        from core.orchestrator import _preserve_sample
        with TemporaryDirectory(dir=Path(__file__).parent) as d:
            d = Path(d)
            sample = d / "ggggg.exe"
            sample.write_bytes(b"MZ" + b"\x90" * 4096)
            result = NS(sample_sha256="", sample_copy=None, errors=[])
            _preserve_sample(NS(sample_path=sample, output_dir=d / "out"), result, lambda *_: None)
            sample.unlink()                     # Remcos 처럼 실행 직후 원본을 지운다
            self.assertEqual(result.sample_sha256, hashlib.sha256(b"MZ" + b"\x90" * 4096).hexdigest())
            self.assertTrue(result.sample_copy.is_file())
            self.assertEqual(result.sample_copy.suffix, ".evd")   # 실수 실행 방지
            self.assertEqual(result.errors, [])

    def test_yara_falls_back_to_reading_bytes(self):
        from analysis import yara_scanner
        calls = []

        class Compiled:
            def match(self, filepath=None, data=None, timeout=60):
                calls.append("data" if data is not None else "path")
                if data is None:
                    raise RuntimeError("could not open file")
                return []
        with TemporaryDirectory(dir=Path(__file__).parent) as d:
            f = Path(d) / "remcos.exe"
            f.write_bytes(b"MZ")
            with patch.dict(sys.modules, {"yara": types.ModuleType("yara")}):
                yara_scanner._scan_single(Compiled(), f)
        self.assertEqual(calls, ["path", "data"])


class MalwareTraitTests(unittest.TestCase):
    def test_remcos_fingerprint_and_collection_behaviors(self):
        from analysis.malware_traits import add_trait_techniques, find_traits
        result = _remcos_result()
        traits = find_traits(result)
        (fam,) = traits["families"]
        self.assertEqual((fam["name"], fam["confidence"], fam["matched"]), ("Remcos RAT", "HIGH", 3))
        self.assertFalse(any("notepad" in e for e in fam["evidence"]))
        tids = {b["technique_id"] for b in traits["behaviors"]}
        self.assertEqual(tids, {"T1113", "T1056.001"})
        add_trait_techniques(result, traits)
        got = {t.technique_id: t for t in result.behavior_report.techniques}
        self.assertTrue(any(e.startswith("[remcos.exe]") and e.lower().endswith("화면 캡처 이미지 저장")
                            for e in got["T1113"].evidence))
        self.assertIn(U + r"\AppData\Roaming\Screenshots\time_20261118_231433.jpg",
                      result.ioc_report.dropped_files)

    def test_no_family_from_outside_lineage(self):
        from analysis.malware_traits import find_traits
        result = _remcos_result()
        result.lineage_pids = {1}
        result.registry_diff = {}
        self.assertEqual(find_traits(result)["families"], [])

    def test_family_reaches_verdict(self):
        from analysis.malware_traits import find_traits
        from exporters.report_visuals import build_indicators
        result = _remcos_result()
        result.malware_traits = find_traits(result)
        inds = build_indicators(result)
        self.assertTrue(any(i["cat"] == "악성코드 패밀리" and i["level"] == "mal" and "Remcos" in i["title"]
                            for i in inds))


class UnelevatedOptionTests(unittest.TestCase):
    def test_cli_and_gui_pass_the_option(self):
        import gui
        cmd = gui.build_command(Path("C:/s/a.exe"), Path("C:/r/o"), 60, procmon=True, tshark=True, ph=False,
                                keylog=True, ai=False, memdump=False, fakenet=False, unelevated=True)
        self.assertIn("--unelevated", cmd)
        cmd = gui.build_command(Path("C:/s/a.exe"), Path("C:/r/o"), 60, procmon=True, tshark=True, ph=False,
                                keylog=True, ai=False, memdump=False, fakenet=False)
        self.assertNotIn("--unelevated", cmd)
        from analyzer import build_parser
        self.assertTrue(build_parser().parse_args(["x.exe", "--unelevated"]).unelevated)

    def test_launcher_falls_back_safely(self):
        from core import unelevated
        with patch.object(unelevated, "_WIN", False):
            self.assertIsNone(unelevated.launch_unelevated(["x.exe"]))
            self.assertFalse(unelevated.needs_unelevation())


class AiFallbackTests(unittest.TestCase):
    def test_slow_model_never_used_as_fallback(self):
        from core import ai_analyzer as A
        catalog = ["mistralai/mistral-large-4-1t-a52b", "google/gemma-4-31b-it", "qwen/qwen2.5-72b-instruct"]
        with patch.object(A, "list_nvidia_models", return_value=catalog):
            auto = A.nvidia_model_candidates("u", "k", "qwen/qwen2.5-72b-instruct")
            chosen = A.nvidia_model_candidates("u", "k", "mistralai/mistral-large-4-1t-a52b")
        self.assertNotIn("mistralai/mistral-large-4-1t-a52b", auto)
        self.assertEqual(chosen[0], "mistralai/mistral-large-4-1t-a52b")   # 직접 지정하면 쓴다


if __name__ == "__main__":
    unittest.main()
