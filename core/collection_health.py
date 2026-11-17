"""수집 도구별 상태를 "실제로 데이터를 남겼는가" 기준으로 판정한다.

tools_used 는 "도구를 찾았고 켰다" 는 뜻일 뿐이라, 켜졌는데 아무것도 못 남긴 경우
(ProcMon 이벤트 0건, 패킷 0개 등)를 정상처럼 보이게 한다. 이 모듈은 산출물과 수치를
근거로 ok / partial / fail / off 를 매겨 JSON·HTML·GUI 가 같은 판단을 쓰게 한다.
"""
from __future__ import annotations

from pathlib import Path


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return ""


def collection_status(result) -> list[dict]:
    """[{tool, state, detail, warn?}] — state: ok | partial | fail | off."""
    cfg = result.config
    tools = getattr(result, "tools_used", None) or {}
    errors = " ".join(str(e) for e in (getattr(result, "errors", None) or []))
    out_dir = Path(getattr(cfg, "output_dir", "."))
    rows: list[dict] = []

    def add(tool: str, state: str, detail: str, warn: str = "") -> None:
        row = {"tool": tool, "state": state, "detail": detail}
        if warn:
            row["warn"] = warn
        rows.append(row)

    pcap_only = bool(getattr(cfg, "external_pcap", None)) and not getattr(cfg, "sample_path", None)

    # ── ProcMon ──
    total = len(getattr(result, "procmon_events", None) or [])
    kept = len(getattr(result, "filtered_events", None) or [])
    pml, csv = out_dir / "procmon.pml", out_dir / "procmon.csv"
    if getattr(cfg, "no_procmon", False) or pcap_only:
        add("ProcMon", "off", "사용 안 함")
    elif total:
        add("ProcMon", "ok", f"이벤트 {total:,}건 · 노이즈 제거 후 {kept:,}건")
    elif "ProcMon" in errors or not tools.get("procmon"):
        add("ProcMon", "fail", "시작·변환 실패 — 실행 로그의 [ProcMon] 줄 확인",
            "ProcMon 이 이벤트를 남기지 못해 파일·레지스트리·프로세스 행위를 판단할 수 없습니다.")
    else:
        detail = (f"PML {_fmt(_size(pml))}, CSV {_fmt(_size(csv))} — 파싱된 이벤트 0건" if pml.exists()
                  else "PML 없음 — 캡처가 시작되지 않았을 수 있음")
        add("ProcMon", "fail", detail, "ProcMon 이벤트가 0건입니다. 캡처·필터·CSV 변환 상태를 확인하세요.")

    # ── 패킷 캡처 ──
    pr = getattr(result, "pcap_result", None)
    packets = int(getattr(pr, "packets_loaded", 0) or 0) if pr else 0
    parse_error = str(getattr(pr, "parse_error", "") or "") if pr else ""
    conns = len(getattr(pr, "connections", None) or []) if pr else 0
    if getattr(cfg, "external_pcap", None):
        add("패킷 캡처", "ok" if packets else "fail",
            f"외부 PCAP {Path(cfg.external_pcap).name} · 패킷 {packets:,}개" + (f" · {parse_error}" if parse_error else ""))
    elif getattr(cfg, "no_tshark", False) and not getattr(cfg, "use_fakenet", False):
        add("패킷 캡처", "off", "사용 안 함")
    elif parse_error:
        add("패킷 캡처", "fail", f"파싱 실패 — {parse_error}", f"네트워크 파싱 실패: {parse_error}")
    elif packets:
        add("패킷 캡처", "ok", f"패킷 {packets:,}개 · 연결 {conns:,}개")
    elif tools.get("tshark") or tools.get("fakenet"):
        add("패킷 캡처", "fail", "캡처는 켜졌지만 패킷 0개 — 캡처 인터페이스(--interface) 확인",
            "패킷이 하나도 없습니다. 네트워크 행위가 없었다고 단정하지 말고 캡처 인터페이스를 확인하세요.")
    else:
        add("패킷 캡처", "fail", "tshark 를 찾지 못했거나 시작 실패", "패킷 캡처가 동작하지 않았습니다.")

    # ── DNS 프로세스 귀속 (ETW) ──
    dns = getattr(result, "dns_attributed", None) or []
    attributed = sum(1 for q in dns if getattr(q, "attributed", False))
    if "dns_etw" not in tools:
        add("DNS 귀속", "off", "사용 안 함")
    elif tools.get("dns_etw"):
        add("DNS 귀속", "ok" if attributed or not dns else "partial",
            f"질의 {len(dns)}건 중 프로세스 귀속 {attributed}건" if dns else "DNS-Client ETW 수집 · 질의 없음")
    else:
        add("DNS 귀속", "partial", "DNS-Client ETW 시작 실패 — ProcMon UDP 이벤트로만 귀속")

    # ── 레지스트리 스냅샷 ──
    diff = getattr(result, "registry_diff", None) or {}
    if tools.get("registry_snapshot"):
        add("레지스트리 스냅샷", "ok",
            f"추가 {len(diff.get('added', []))} · 변경 {len(diff.get('modified', []))} · 삭제 {len(diff.get('deleted', []))}")
    else:
        add("레지스트리 스냅샷", "off", "사용 불가 (winreg 없음)")

    # ── 메모리 스캔 ──
    ps = getattr(result, "pe_sieve_results", None) or []
    if tools.get("pe_sieve"):
        failed = sum(1 for r in ps if getattr(r, "error", ""))
        state = "ok" if ps and not failed else ("partial" if ps else "ok")
        add("pe-sieve", state, f"프로세스 {len(ps)}개 스캔" + (f" · 오류 {failed}개" if failed else "")
            if ps else "스캔할 신규 프로세스 없음 (모두 종료되었을 수 있음)")
    else:
        add("pe-sieve", "off", "설치되지 않음")
    hh = getattr(result, "hh_result", None)
    if tools.get("hollows_hunter"):
        err = str(getattr(hh, "error", "") or "") if hh else "결과 없음"
        add("hollows-hunter", "fail" if err else "ok", err or "전체 프로세스 스캔 완료")
    else:
        add("hollows-hunter", "off", "설치되지 않음")

    # ── TLS 키 로그 ──
    if tools.get("tls_keylog"):
        keys = int(getattr(result, "tls_key_count", 0) or 0)
        dec = len(getattr(result, "decrypted_requests", None) or [])
        add("TLS 키 로그", "ok" if keys else "partial",
            f"세션 키 {keys}개 · 복호화 요청 {dec}개" if keys else
            "기록된 키 없음 — Schannel(WinHTTP·.NET) 통신은 SSLKEYLOGFILE 로 복호화되지 않음")
    else:
        add("TLS 키 로그", "off", "사용 안 함")

    if getattr(cfg, "use_fakenet", False):
        fn = getattr(result, "fakenet_result", None) or {}
        add("FakeNet-NG", "ok" if tools.get("fakenet") else "fail",
            "가짜 응답 제공" + (f" · DNS {len(fn.get('dns', []))}건" if isinstance(fn, dict) and fn.get("dns") else "")
            if tools.get("fakenet") else "시작 실패 — 실제 네트워크도 캡처되지 않았을 수 있음")

    if getattr(cfg, "use_memdump", False):
        mem = getattr(result, "mem_forensics", None) or {}
        err = str(mem.get("error", "") or "") if isinstance(mem, dict) else ""
        add("메모리 포렌식", "fail" if err or not mem else "ok",
            err or (f"malfind {len(mem.get('malfind', []))}건 · netscan {len(mem.get('netscan', []))}건"
                    if mem else "결과 없음"))

    # ── 정적·외부 보강 ──
    for key, name in (("capa", "CAPA"), ("virustotal", "VirusTotal"), ("yara", "YARA")):
        if key not in tools:
            continue
        text = str(tools[key])
        state = ("fail" if any(w in text for w in ("오류", "실패")) else
                 "off" if any(w in text for w in ("비활성", "미설치", "건너뜀", "없음", "미실행", "샘플 없음", "API 키")) else "ok")
        add(name, state, text)

    ai = getattr(result, "ai_analysis", None) or {}
    if not getattr(cfg, "use_ai", False):
        add("AI 해석", "off", "사용 안 함")
    elif isinstance(ai, dict) and ai.get("pending"):
        add("AI 해석", "partial", "진행 중 — 끝나면 보고서가 갱신됩니다")
    elif isinstance(ai, dict) and ai.get("error"):
        add("AI 해석", "fail", str(ai["error"])[:300])
    elif isinstance(ai, dict) and ai.get("response"):
        add("AI 해석", "ok", f"{ai.get('model', '')} · {ai.get('elapsed_sec', 0)}초 · 입력 {ai.get('prompt_chars', 0):,}자")
    else:
        add("AI 해석", "off", "실행되지 않음")
    return rows
