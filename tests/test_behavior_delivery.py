import unittest
import tempfile
import json
from pathlib import Path
from types import SimpleNamespace as N
from parsers.pcap_parser import PcapResult, NetworkConnection
from parsers.procmon_csv import ProcMonEvent as E, EventCategory as C
from analysis.network_scope import sample_network_view, refresh_tracked_events
from analysis.behavior_classifier import classify_behaviors, BehaviorReport, MitreTechnique
from exporters.html_report import _file_events_html, _registry_events_html
from exporters.json_report import save_json_report
from core.orchestrator import AnalysisConfig, AnalysisResult

class DeliveryTests(unittest.TestCase):
    def test_network_scope_and_ambiguity(self):
        p=PcapResult(connections=[NetworkConnection('TCP','10.0.0.1','8.8.8.8',443,src_port=5000)])
        e=E('', 'sample.exe',42,'TCP Connect','10.0.0.1:5000 -> 8.8.8.8:443','SUCCESS','',C.NETWORK)
        self.assertEqual(sample_network_view(p,[e],{42}).connections,p.connections)
        self.assertEqual(sample_network_view(p,[e],{99}).connections,[])
        other=E('', 'browser.exe',99,e.operation,e.path,'SUCCESS','',C.NETWORK)
        self.assertEqual(sample_network_view(p,[e,other],{42}).connections,[])
        self.assertEqual(len(p.connections),1)

    def test_unattributed_network_not_classified(self):
        p=PcapResult(connections=[NetworkConnection('TCP','10.0.0.1','8.8.8.8',443)])
        scoped=sample_network_view(p,[],{42})
        r=classify_behaviors([],scoped,{}, {'new_processes':[]})
        self.assertFalse(r.techniques)
        self.assertNotEqual(r.execution_verdict,'CONFIRMED')

    def test_external_connection_is_not_exfiltration(self):
        p=PcapResult(connections=[NetworkConnection('TCP','10.0.0.1','8.8.8.8',443)])
        r=classify_behaviors([],p,{}, {})
        self.assertNotIn('T1041',[t.technique_id for t in r.techniques])

    def test_late_pid_and_full_path_reach_file_tab(self):
        path='C:\\'+'a'*130+'\\payload.exe'
        e=E('', 'svchost.exe',42,'WriteFile',path,'SUCCESS','',C.FILE)
        r=N(procmon_events=[e],filtered_events=[],all_pids={42},sample_pid=42,process_diff={},behavior_report=None)
        refresh_tracked_events(r)
        html,count=_file_events_html(r)
        self.assertEqual(count,1)
        self.assertIn(path,html)

    def test_registry_failure_visible(self):
        e=E('', 'sample.exe',42,'RegSetValue',r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Test','ACCESS DENIED','Data: payload.exe',C.REGISTRY)
        r=N(filtered_events=[e],registry_diff={},behavior_report=None)
        self.assertIn('ACCESS DENIED',_registry_events_html(r))

    def test_json_preserves_all_evidence_and_sources(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as d:
            r=AnalysisResult(AnalysisConfig(None,Path(d)))
            r.behavior_report=BehaviorReport()
            t=MitreTechnique('T0000','test','test',evidence=[str(i) for i in range(15)],sources=['ProcMon'])
            r.behavior_report.techniques=[t]
            f=Path(d)/'report.json'
            save_json_report(r,str(f))
            row=json.loads(f.read_text(encoding='utf-8'))['mitre_techniques'][0]
            self.assertEqual(row['evidence'],t.evidence)
            self.assertEqual(row['sources'],['ProcMon'])
