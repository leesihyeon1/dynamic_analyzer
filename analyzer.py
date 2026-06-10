"""
dynamic_analyzer — Windows 악성코드 동적 분석 도구

사용법:
  python analyzer.py malware.exe
  python analyzer.py malware.exe --timeout 120
  python analyzer.py malware.exe --no-procmon          # ProcMon 없이
  python analyzer.py malware.exe --no-tshark           # 패킷 캡처 없이
  python analyzer.py malware.exe --interface 2         # tshark 인터페이스 번호 지정
  python analyzer.py malware.exe -o C:\\results\\      # 출력 디렉터리
  python analyzer.py --list-interfaces                 # tshark 인터페이스 목록 확인
  python analyzer.py --check-tools                     # 사용 가능한 도구 확인

  # Wireshark에서 미리 캡처한 PCAP 파일 분석
  python analyzer.py malware.exe --pcap capture.pcap
  python analyzer.py malware.exe --pcap capture.pcapng --no-tshark

  # PCAP만 단독 분석 (샘플 실행 없이)
  python analyzer.py --pcap capture.pcapng --no-procmon --no-tshark

요구사항:
  - 관리자 권한으로 실행 (ProcMon, tshark 모두 필요)
  - FLARE VM 또는 동적 분석 전용 VM 환경 권장
  - pip install -r requirements.txt
  - PCAP 분석: pip install scapy  (.pcap / .pcapng 모두 지원)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.table   import Table
from rich         import box

console = Console()


def _open_report(html_path, console) -> None:
    """
    리포트를 브라우저로 엽니다.

    config.json > hunt.serve_port > 0 이면 hunt_relay.py 를 백그라운드
    프로세스로 실행해 로컬 HTTP 서버 + abuse.ch API 릴레이를 제공합니다.
    → file:// CORS 및 VM 방화벽 우회 (Python 프로세스가 직접 API 호출).
    serve_port == 0 이면 os.startfile() 로 직접 열기합니다.
    """
    import os, sys, subprocess, webbrowser
    from pathlib import Path as _Path

    try:
        from core.config_loader import get_hunt_cfg
        serve_port = get_hunt_cfg().get("serve_port", 18080)
    except Exception:
        serve_port = 18080

    if serve_port and serve_port > 0:
        directory = str(html_path.parent)
        filename  = html_path.name

        # ── 기존 릴레이 프로세스 종료 (포트 재사용) ─────────────────
        try:
            import psutil as _ps
            for conn in _ps.net_connections(kind="inet"):
                if getattr(conn.laddr, "port", None) == serve_port and conn.status == "LISTEN":
                    try:
                        _ps.Process(conn.pid).terminate()
                    except Exception:
                        pass
        except Exception:
            pass

        # ── hunt_relay.py 백그라운드 실행 ────────────────────────────
        relay_py = _Path(__file__).parent / "core" / "hunt_relay.py"
        try:
            subprocess.Popen(
                [sys.executable, str(relay_py),
                 "--port", str(serve_port), "--dir", directory],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except Exception as exc:
            console.print(f"  [yellow]⚠ 릴레이 서버 시작 실패: {exc} — file:// 로 열기[/yellow]")
            try:
                os.startfile(str(html_path))
            except Exception as exc2:
                console.print(f"  [yellow]리포트 자동 열기 실패: {exc2}[/yellow]")
            return

        # 릴레이 프로세스가 포트를 바인딩할 시간 확보
        import time as _t
        _t.sleep(1.2)

        url = f"http://127.0.0.1:{serve_port}/{filename}"
        webbrowser.open(url)
        console.print(
            f"  [dim]Hunt 릴레이 →[/dim] [blue]{url}[/blue]  "
            f"[dim](abuse.ch API 릴레이 활성 / 백그라운드 실행 중)[/dim]"
        )
    else:
        # serve_port = 0 → 직접 열기 (CORS 주의)
        try:
            os.startfile(str(html_path))
            console.print("  [dim]브라우저에서 리포트를 열었습니다.[/dim]")
        except Exception as exc:
            console.print(f"  [yellow]리포트 자동 열기 실패: {exc}[/yellow]")


def _check_admin() -> bool:
    """Windows 관리자 권한 여부 확인"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _print_tool_status() -> None:
    """설치된 도구 상태 출력"""
    from core.procmon        import find_procmon
    from core.tshark_capture import find_tshark, get_capture_interface
    from core.registry_snapshot import AVAILABLE as REG_AVAIL
    from core.process_tracker import find_process_hacker

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("도구",        style="white",  width=22)
    tbl.add_column("상태",        style="white",  width=10)
    tbl.add_column("경로 / 비고", style="dim",    ratio=1)

    pm = find_procmon()
    tbl.add_row("ProcMon",
                "[green]✔ 발견[/green]" if pm else "[red]✘ 없음[/red]",
                pm or "PATH 또는 C:\\Tools\\SysinternalsSuite\\")

    ts = find_tshark()
    tbl.add_row("tshark (Wireshark)",
                "[green]✔ 발견[/green]" if ts else "[red]✘ 없음[/red]",
                ts or "PATH 또는 C:\\Program Files\\Wireshark\\")

    ph = find_process_hacker()
    tbl.add_row("Process Hacker / System Informer",
                "[green]✔ 발견[/green]" if ph else "[yellow]△ 선택[/yellow]",
                ph or "C:\\Tools\\processhacker\\ (없어도 psutil로 대체)")

    tbl.add_row("Registry Snapshot (winreg)",
                "[green]✔ 내장[/green]" if REG_AVAIL else "[red]✘ Windows 전용[/red]",
                "Python 표준 라이브러리")

    console.print(tbl)


def _list_interfaces() -> None:
    """tshark 캡처 인터페이스 목록 출력"""
    from core.tshark_capture import find_tshark
    import subprocess
    ts = find_tshark()
    if not ts:
        console.print("[red]tshark를 찾을 수 없습니다.[/red]")
        return
    try:
        r = subprocess.run([ts, "-D"], capture_output=True, text=True, timeout=10)
        console.print("[bold]tshark 캡처 인터페이스 목록:[/bold]")
        console.print(r.stdout or r.stderr)
    except Exception as e:
        console.print(f"[red]인터페이스 조회 실패: {e}[/red]")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Windows 악성코드 동적 분석 — ProcMon + tshark + Regshot + Process Hacker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python analyzer.py malware.exe
  python analyzer.py malware.exe --timeout 120 --interface 2
  python analyzer.py malware.exe --no-tshark -o C:\\results\\
  python analyzer.py --check-tools
  python analyzer.py --list-interfaces
""",
    )
    p.add_argument("input", nargs="?", help="분석할 EXE 파일 경로")
    p.add_argument("--timeout", "-t", type=int, default=60, metavar="SEC",
                   help="모니터링 시간 (초, 기본: 60)")
    p.add_argument("--output", "-o", metavar="DIR",
                   help="출력 디렉터리 (기본: results/<파일명>_<timestamp>/)")
    p.add_argument("--interface", "-i", metavar="NUM",
                   help="tshark 캡처 인터페이스 번호 (기본: 자동 감지)")

    # 도구 비활성화
    g = p.add_argument_group("도구 선택 (기본: 모두 사용)")
    g.add_argument("--no-procmon",  action="store_true", help="ProcMon 스킵")
    g.add_argument("--no-tshark",   action="store_true", help="tshark 스킵")
    g.add_argument("--no-ph",       action="store_true", help="Process Hacker GUI 실행 안 함")
    g.add_argument("--no-export",   action="store_true", help="파일 저장 없이 콘솔 출력만")
    g.add_argument("--no-open",     action="store_true", help="분석 완료 후 HTML 리포트 자동 열기 비활성화")

    # PCAP 입력
    pg = p.add_argument_group("PCAP 분석")
    pg.add_argument("--pcap", metavar="FILE",
                    help="Wireshark 등에서 미리 캡처한 PCAP/PCAPng 파일 경로. "
                         "지정 시 tshark 캡처 대신 해당 파일로 네트워크 분석 수행")

    # 유틸리티
    p.add_argument("--check-tools",      action="store_true", help="도구 설치 상태 확인 후 종료")
    p.add_argument("--list-interfaces",  action="store_true", help="tshark 인터페이스 목록 후 종료")

    return p


def main() -> None:
    args = build_parser().parse_args()

    # ── 유틸리티 모드 ──────────────────────────────────────────────
    if args.check_tools:
        console.rule("[bold white]🔧 도구 상태 확인")
        _print_tool_status()
        sys.exit(0)

    if args.list_interfaces:
        _list_interfaces()
        sys.exit(0)

    # ── scapy 가용성 확인 (PCAP 분석 필수) ──────────────────────
    try:
        import scapy  # noqa: F401
    except ImportError:
        console.print(
            "[yellow]⚠ scapy 미설치 — PCAP 분석이 비활성화됩니다.[/yellow]\n"
            "  설치: [bold]pip install scapy[/bold]"
        )

    # ── 입력 검증 ────────────────────────────────────────────────
    sample_path = None
    if args.input:
        sample_path = Path(args.input)
        if not sample_path.exists():
            console.print(f"[red][!] 파일 없음: {sample_path}[/red]")
            sys.exit(1)

    # ── 외부 PCAP 검증 ──────────────────────────────────────────
    external_pcap = None
    if args.pcap:
        external_pcap = Path(args.pcap)
        if not external_pcap.exists():
            console.print(f"[red][!] PCAP 파일 없음: {external_pcap}[/red]")
            sys.exit(1)
        suffix = external_pcap.suffix.lower()
        if suffix not in (".pcap", ".pcapng", ".cap"):
            console.print(
                f"[yellow]⚠ 알 수 없는 확장자: {suffix} "
                f"— .pcap / .pcapng / .cap 파일을 권장합니다.[/yellow]"
            )

    # ── 관리자 권한 경고 ────────────────────────────────────────
    if not _check_admin():
        console.print("[yellow]⚠ 관리자 권한 없음 — ProcMon·tshark 일부 기능이 제한될 수 있습니다.[/yellow]")

    # ── 출력 디렉터리 ───────────────────────────────────────────
    import time as _time
    ts_str = _time.strftime("%Y%m%d_%H%M%S")
    if args.output:
        out_dir = Path(args.output)
    else:
        stem = sample_path.stem if sample_path else "monitor"
        out_dir = Path("results") / f"{stem}_{ts_str}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── 캡처 최적화 자동 적용 (스냅샷 복원 후 매번) ────────────────
    from core.vm_setup import apply_capture_policies
    _ok, _fail = apply_capture_policies()
    if _ok:
        console.print(
            f"  [dim][캡처 최적화][/dim] "
            + "  ".join(f"[green]{x}[/green]" for x in _ok)
        )
    if _fail:
        console.print(
            f"  [dim][캡처 최적화 일부 실패 — 관리자 권한 필요][/dim] "
            + "  ".join(f"[yellow]{x}[/yellow]" for x in _fail)
        )

    # ── 분석 시작 ───────────────────────────────────────────────
    label = sample_path.name if sample_path else "전체 시스템 모니터링"
    console.rule(f"[bold white]🧪 dynamic_analyzer — {label}")
    if sample_path:
        console.print(f"  대상   : {sample_path.resolve()}")
    else:
        console.print(f"  대상   : [yellow]지정 없음 — 모니터링 시작 후 직접 실행하세요[/yellow]")
    if external_pcap:
        console.print(f"  PCAP   : {external_pcap.resolve()}")
    console.print(f"  출력   : {out_dir.resolve()}")
    console.print(f"  timeout: {args.timeout}초")
    console.print()

    from core.orchestrator import AnalysisConfig, run_analysis

    config = AnalysisConfig(
        sample_path   = sample_path,
        output_dir    = out_dir,
        timeout       = args.timeout,
        interface     = args.interface,
        no_procmon    = args.no_procmon,
        no_tshark     = args.no_tshark,
        no_ph         = args.no_ph,
        external_pcap = external_pcap,
    )

    def on_status(msg: str) -> None:
        console.print(f"  {msg}")

    result = run_analysis(config, on_status=on_status)
    console.print()

    # ── 요약 출력 ───────────────────────────────────────────────
    techs = result.behavior_report.techniques if result.behavior_report else []
    ioc   = result.ioc_report

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tbl.add_column(style="dim")
    tbl.add_column()
    tbl.add_row("MITRE 기법",    f"[red]{len(techs)}건[/red]" if techs else "[green]없음[/green]")
    tbl.add_row("외부 IP",       f"[orange3]{len(ioc.ip_addresses)}개[/orange3]" if ioc and ioc.ip_addresses else "[green]없음[/green]")
    tbl.add_row("드롭 파일",     f"[orange3]{len(ioc.dropped_files)}개[/orange3]" if ioc and ioc.dropped_files else "[green]없음[/green]")
    tbl.add_row("레지스트리 추가", f"{len(result.registry_diff.get('added', []))}건")
    tbl.add_row("신규 프로세스",  f"{len(result.process_diff.get('new_processes', []))}개")
    tbl.add_row("ProcMon 이벤트", f"{len(result.procmon_events):,}개 → 필터 후 {len(result.filtered_events):,}개")
    console.print(tbl)

    if techs:
        console.print()
        console.print("[bold red]탐지된 MITRE ATT&CK 기법:[/bold red]")
        for t in techs:
            ref = t.reference or f"https://attack.mitre.org/techniques/{t.technique_id.replace('.','/')}/"
            console.print(f"  [red]✔ {t.technique_id}[/red]  {t.technique_name}  [dim]{t.tactic}[/dim]")
            console.print(f"      [dim blue]{ref}[/dim blue]")

    # ── 파일 저장 ───────────────────────────────────────────────
    if not args.no_export:
        console.print()
        console.print("[*] 결과 저장 중...")

        from exporters.json_report import save_json_report
        from exporters.html_report import generate_html_report

        stem      = sample_path.stem if sample_path else "monitor"
        json_path = out_dir / f"{stem}_dynamic_report.json"
        html_path = out_dir / f"{stem}_dynamic_report.html"

        save_json_report(result, str(json_path))
        console.print(f"  [green]JSON[/green] → {json_path}")

        generate_html_report(result, str(html_path))
        console.print(f"  [green]HTML[/green] → {html_path}")

        if not args.no_open:
            _open_report(html_path, console)

    console.rule("[bold white]분석 완료")


if __name__ == "__main__":
    main()
