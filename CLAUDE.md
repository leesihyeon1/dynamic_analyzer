# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Windows malware dynamic-analysis automation tool (Noriben.py style). One command runs a sample under monitoring (ProcMon, tshark/FakeNet-NG, pe-sieve, hollows-hunter), then parses everything into MITRE ATT&CK mappings, IOCs, and an HTML/JSON report. Windows-only; requires an admin shell and is meant to run inside an analysis VM (FLARE VM). Comments, docstrings, console output, and commit messages are in Korean — keep that convention.

## Commands

There is no build step, linter, or test suite. Development is run-and-inspect:

```powershell
pip install -r requirements.txt

python analyzer.py --check-tools          # verify which external tools are detected
python analyzer.py --list-interfaces      # tshark interface list
python analyzer.py malware.exe            # full analysis (admin PowerShell required)
python analyzer.py malware.exe --timeout 120 --memdump --ai

# Fastest iteration loop without running a sample or needing admin:
python analyzer.py --pcap capture.pcapng --no-procmon --no-tshark
```

Reports land in `results/<name>_<timestamp>/` and the HTML opens automatically (`--no-open` to disable).

## Architecture

Pipeline with four layers, driven end-to-end by `core/orchestrator.py::run_analysis(config, on_status)`:

1. **`analyzer.py`** — CLI entry point. Parses args into an `AnalysisConfig`, calls `run_analysis`, then hands the result to exporters and opens the report.
2. **`core/`** — collectors/controllers that run external tools and produce raw artifacts: ProcMon (`procmon.py` → PML → CSV), packet capture (`tshark_capture.py`) or `fakenet_integrator.py` as an alternative, registry snapshots (`registry_snapshot.py`), process tracking (`process_tracker.py`, plus `process_watcher.py` which polls every 1s to pe-sieve-scan new PIDs before they exit), injection scanners (`pesieve_scanner.py`, `hollows_hunter.py`), TLS key capture (`tls_keylog.py` via SSLKEYLOGFILE), memory dump + Volatility3 (`memory_forensics.py`), and Ollama AI analysis (`ai_analyzer.py`).
3. **`parsers/`** — turn raw artifacts into structured events: `procmon_csv.py` → `ProcMonEvent`s, `pcap_parser.py` → connections/DNS/TLS SNI/HTTP/SMTP/FTP (scapy if installed, tshark fallback otherwise), `pesieve_result.py` → pe-sieve/hollows-hunter JSON.
4. **`analysis/`** — interpretation: `noise_filter.py` (strip system + analysis-tool events), `behavior_classifier.py` (behavior patterns → MITRE ATT&CK, merged with CAPA/VirusTotal/AI-derived techniques), `ioc_extractor.py`, `process_network_map.py`, `injection_classifier.py`, `yara_scanner.py` + `capa_analyzer.py` (re-analysis of dumped `.shc`/`.bin` shellcode).
5. **`exporters/`** — `html_report.py` (single ~4400-line module generating the entire tabbed dark-theme report with inline CSS/JS) and `json_report.py`.

The Hunt tab in the HTML report queries abuse.ch APIs live. To dodge `file://` CORS, `analyzer.py` launches `core/hunt_relay.py` as a detached background HTTP server (default port 18080, configured under `hunt.serve_port` in `config.json`) that serves the report and relays the API calls.

## Key conventions

- **Graceful degradation everywhere.** Every external tool (ProcMon, tshark, pe-sieve, hollows-hunter, CAPA, winpmem, Volatility3, FakeNet-NG, Ollama, scapy, yara-python) is auto-detected via `find_*()` helpers checking PATH plus known `C:\Tools\...` directories; if missing, that feature is skipped with a console note, never a crash. New integrations must follow this pattern. Heavy imports are deferred inside `run_analysis` for the same reason.
- **`config.json`** (loaded by `core/config_loader.py`) holds tool paths, CAPA/VirusTotal settings, and Hunt tab services. `analysis/attack_lookup.py` is the T-ID → name/tactic lookup table.
- **False-positive suppression is a recurring concern** (see `noise_filter.py` and recent commit history): analysis tools themselves (ProcMon, tshark, System Informer…) generate events and injection-scanner hits that must be excluded, while genuine system-process activity caused by the sample must be kept. When touching detection or filtering logic, check both directions.
- Output encoding: entry point reconfigures stdout/stderr to UTF-8; console UI uses `rich`.
