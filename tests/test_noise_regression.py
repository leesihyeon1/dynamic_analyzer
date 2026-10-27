"""실제 샘플 실행 없이 정상 노이즈와 중요 증거 보존 검증."""
import unittest
from types import SimpleNamespace as NS
from parsers.procmon_csv import ProcMonEvent as E, EventCategory as C
from analysis.noise_filter import filter_events
from analysis.process_network_map import build_netstat_proc_map, filter_process_connections
from core.orchestrator import _find_suspicious_activity_pids
from exporters.html_report import _compute_display_procs


def event(name="sample.exe", op="WriteFile", path=r"C:\Users\test\AppData\Local\Temp\cache.tmp", cat=C.FILE, result="SUCCESS"):
    return E("", name, 42, op, path, result, "", cat)


class NoiseRegressionTests(unittest.TestCase):
    def test_temp_noise_not_promoted(self):
        for e in [event("chrome.exe"), event("chrome.exe", "CreateFile"),
                  event(op="WriteFile", path=r"C:\Windows\Temp\drop.exe", result="ACCESS DENIED")]:
            self.assertEqual(_find_suspicious_activity_pids([e], {99}), set())

    def test_executable_drop_promoted(self):
        e = event(path=r"C:\Windows\Temp\drop.exe")
        self.assertEqual(_find_suspicious_activity_pids([e], {99}), {42})

    def test_tracked_system_persistence_retained(self):
        e = event("svchost.exe", "RegSetValue", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Test", C.REGISTRY)
        self.assertEqual(filter_events([e], {42}), [e])

    def test_bootexecute_retained_and_promoted(self):
        e = event(op="RegSetValue", path=r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute", cat=C.REGISTRY)
        self.assertEqual(filter_events([e], {42}), [e])
        self.assertEqual(_find_suspicious_activity_pids([e], {99}), {42})

    def test_tracked_system_network_retained(self):
        e = event("svchost.exe", "TCP Connect", "10.0.0.1:12 -> 8.8.8.8:443", C.NETWORK)
        self.assertEqual(filter_events([e], {42}), [e])
        self.assertEqual(filter_events([e]), [])

    def test_focus_excludes_unrelated(self):
        self.assertEqual(filter_events([event()], {99}), [])

    def test_netstat_tools_removed_but_tracked_name_preserved(self):
        snaps = [[("8.8.8.8", 443, 42, "procmon64.exe"), ("1.1.1.1", 443, 43, "ollama.exe")]]
        self.assertEqual(build_netstat_proc_map(snaps), [])
        self.assertEqual([c.pid for c in build_netstat_proc_map(snaps, focus_pids={42})], [42])

    def test_common_network_focus(self):
        cons = [NS(pid=42, process="svchost.exe"), NS(pid=43, process="chrome.exe")]
        self.assertEqual(filter_process_connections(cons, {42}), cons[:1])

    def test_no_evidence_does_not_promote_all_processes(self):
        r = NS(process_diff={"new_processes": [NS(pid=42, ppid=1, name="chrome.exe")]}, sample_pid=None, filtered_events=[])
        self.assertEqual(_compute_display_procs(r), ([], 1))

    def test_sample_child_preserved_without_events(self):
        procs = [NS(pid=42, ppid=1, name="sample.exe"), NS(pid=43, ppid=42, name="svchost.exe")]
        r = NS(process_diff={"new_processes": procs}, sample_pid=42, filtered_events=[])
        self.assertEqual(_compute_display_procs(r), (procs, 0))

if __name__ == "__main__":
    unittest.main()
