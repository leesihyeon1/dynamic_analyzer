"""
fakenet_integrator.py — FakeNet-NG 연동

FakeNet-NG는 FLARE-VM에 기본 탑재되는 네트워크 시뮬레이터입니다.
DNS 리다이렉션 + HTTP/HTTPS/FTP/SMTP 등 가짜 서버를 실행해
악성코드가 C2에 보내는 모든 트래픽을 가로챕니다.

tshark/SSLKEYLOGFILE과 달리 TLS를 자체적으로 종단(terminate)하므로
Schannel/WinHTTP 기반 악성코드의 HTTPS 트래픽도 평문으로 볼 수 있습니다.

사용:
  integrator = FakeNetIntegrator(output_dir)
  if integrator.is_available():
      integrator.start()
      # ... 샘플 실행 ...
      integrator.stop()
      data = integrator.get_result()
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── FakeNet-NG 설치 경로 탐색 ────────────────────────────────────────────

_FAKENET_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\FakeNet-NG\fakenet.exe"),
    Path(r"C:\Tools\fakenet-ng\fakenet.exe"),
    Path(r"C:\Tools\FakeNet\fakenet.exe"),
    Path(r"C:\Program Files\FakeNet-NG\fakenet.exe"),
    Path(r"C:\flare-vm\fakenet-ng\fakenet.exe"),
]

_FAKENET_CONFIG_CANDIDATES: list[Path] = [
    Path(r"C:\Tools\FakeNet-NG\configs\default.ini"),
    Path(r"C:\Tools\fakenet-ng\configs\default.ini"),
]


def find_fakenet() -> Optional[Path]:
    """FakeNet-NG 실행파일 경로 자동 탐색."""
    found = shutil.which("fakenet.exe") or shutil.which("fakenet")
    if found:
        return Path(found)
    for c in _FAKENET_CANDIDATES:
        if c.is_file():
            return c
    return None


def find_fakenet_config() -> Optional[Path]:
    """FakeNet-NG 기본 설정 파일 탐색."""
    for c in _FAKENET_CONFIG_CANDIDATES:
        if c.is_file():
            return c
    return None


# ── 결과 데이터 클래스 ───────────────────────────────────────────────────

@dataclass
class FakeNetDnsEntry:
    queried_domain: str
    resolved_to:    str   = "127.0.0.1"   # FakeNet-NG는 항상 루프백으로 응답


@dataclass
class FakeNetHttpRequest:
    proto:         str   = "HTTP"     # HTTP or HTTPS
    src_ip:        str   = ""
    src_port:      int   = 0
    dst_port:      int   = 80
    method:        str   = ""
    host:          str   = ""
    path:          str   = ""
    user_agent:    str   = ""
    content_type:  str   = ""
    body_preview:  str   = ""         # 앞 512바이트


@dataclass
class FakeNetTcpSession:
    """HTTP/HTTPS 이외의 TCP 세션 (바이너리 C2 프로토콜 등)"""
    proto:     str  = "TCP"
    src_ip:    str  = ""
    dst_port:  int  = 0
    raw_bytes: str  = ""   # hex 문자열, 앞 256바이트


@dataclass
class FakeNetResult:
    dns_queries:    list[FakeNetDnsEntry]     = field(default_factory=list)
    http_requests:  list[FakeNetHttpRequest]  = field(default_factory=list)
    tcp_sessions:   list[FakeNetTcpSession]   = field(default_factory=list)
    pcap_path:      Optional[Path]            = None
    log_path:       Optional[Path]            = None
    elapsed_sec:    float = 0.0
    error:          str   = ""


# ── 로그 파서 ────────────────────────────────────────────────────────────

# FakeNet-NG 로그 라인 예시:
#   [2024-01-15 12:34:56.789] [   DNS  ] Resolving: malware.c2.com -> 127.0.0.1
#   [2024-01-15 12:34:56.789] [  HTTP  ] 192.168.1.100:54321 -> GET /beacon HTTP/1.1
#   [2024-01-15 12:34:56.789] [ HTTPS  ] 192.168.1.100:54322 -> POST /check HTTP/1.1
#   [2024-01-15 12:34:56.789] [   TCP  ] 192.168.1.100:54323 -> 0.0.0.0:4444

_RE_TIMESTAMP = re.compile(r"^\[[\d\-: .]+\]\s*")
_RE_TAG       = re.compile(r"\[\s*(\w+)\s*\]")
_RE_DNS       = re.compile(r"Resolv(?:ing|ed)[:\s]+(\S+)\s*(?:->|to)\s*(\S+)", re.IGNORECASE)
_RE_HTTP_CONN = re.compile(
    r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*"
    r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP",
    re.IGNORECASE,
)
_RE_HOST_HDR  = re.compile(r"Host:\s*(\S+)", re.IGNORECASE)
_RE_UA_HDR    = re.compile(r"User-Agent:\s*(.+)", re.IGNORECASE)
_RE_TCP_CONN  = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*\S+:(\d+)")


def parse_fakenet_log(log_path: Path) -> FakeNetResult:
    """FakeNet-NG 로그 파일을 파싱하여 구조화된 결과 반환."""
    result = FakeNetResult(log_path=log_path)
    if not log_path.exists():
        result.error = f"로그 파일 없음: {log_path}"
        return result

    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        result.error = str(e)
        return result

    current_http: Optional[FakeNetHttpRequest] = None

    for line in lines:
        # 태그(프로토콜) 추출
        tag_m = _RE_TAG.search(line)
        tag   = tag_m.group(1).upper() if tag_m else ""
        # 타임스탬프 제거한 내용
        body  = _RE_TIMESTAMP.sub("", line).strip()

        # ── DNS ──────────────────────────────────────────────────────
        if tag == "DNS":
            m = _RE_DNS.search(body)
            if m:
                domain   = m.group(1).rstrip(".")
                resolved = m.group(2)
                result.dns_queries.append(FakeNetDnsEntry(
                    queried_domain=domain,
                    resolved_to=resolved,
                ))

        # ── HTTP / HTTPS ──────────────────────────────────────────────
        elif tag in ("HTTP", "HTTPS"):
            m = _RE_HTTP_CONN.search(body)
            if m:
                if current_http:
                    result.http_requests.append(current_http)
                dst_port = 443 if tag == "HTTPS" else 80
                current_http = FakeNetHttpRequest(
                    proto=tag,
                    src_ip=m.group(1),
                    src_port=int(m.group(2)),
                    dst_port=dst_port,
                    method=m.group(3).upper(),
                    path=m.group(4),
                )
            elif current_http:
                # 헤더 라인
                h = _RE_HOST_HDR.search(body)
                if h:
                    current_http.host = h.group(1)
                ua = _RE_UA_HDR.search(body)
                if ua:
                    current_http.user_agent = ua.group(1).strip()

        # ── TCP (바이너리 세션) ───────────────────────────────────────
        elif tag == "TCP":
            m = _RE_TCP_CONN.search(body)
            if m:
                result.tcp_sessions.append(FakeNetTcpSession(
                    src_ip=m.group(1),
                    dst_port=int(m.group(3)),
                ))

    # 마지막 HTTP 요청 처리
    if current_http:
        result.http_requests.append(current_http)

    return result


# ── 통합 관리 클래스 ─────────────────────────────────────────────────────

class FakeNetIntegrator:
    """FakeNet-NG 실행·중지·결과 수집을 관리하는 클래스."""

    def __init__(
        self,
        output_dir: Path,
        fakenet_path: Optional[Path] = None,
        config_path: Optional[Path] = None,
        timeout: int = 120,
    ) -> None:
        self.output_dir   = Path(output_dir)
        self.fakenet_path = fakenet_path or find_fakenet()
        self.config_path  = config_path  or find_fakenet_config()
        self.timeout      = timeout
        self._proc: Optional[subprocess.Popen] = None
        self._start_time: float = 0.0
        self._log_path:   Optional[Path] = None

    def is_available(self) -> bool:
        return self.fakenet_path is not None and self.fakenet_path.is_file()

    def start(self) -> bool:
        """FakeNet-NG를 백그라운드로 시작."""
        if not self.is_available():
            return False

        self.output_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.output_dir / "fakenet.log"
        self._log_path = log_file

        cmd = [str(self.fakenet_path)]
        if self.config_path and self.config_path.is_file():
            cmd += ["-c", str(self.config_path)]
        # 출력 디렉터리 지정 (FakeNet-NG 1.4+)
        cmd += ["-o", str(self.output_dir)]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=open(log_file, "w", encoding="utf-8"),
                stderr=subprocess.STDOUT,
                cwd=str(self.fakenet_path.parent),
            )
            self._start_time = time.monotonic()
            time.sleep(2.0)   # 바인딩 대기
            return self._proc.poll() is None
        except Exception:
            return False

    def stop(self) -> FakeNetResult:
        """FakeNet-NG 종료 후 결과 반환."""
        elapsed = round(time.monotonic() - self._start_time, 1) if self._start_time else 0.0

        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        # PCAP 탐색 (FakeNet-NG가 캡처한 파일)
        pcap_path: Optional[Path] = None
        for pat in ("*.pcap", "*.pcapng"):
            found = sorted(self.output_dir.glob(pat), key=lambda p: p.stat().st_mtime)
            if found:
                pcap_path = found[-1]
                break

        # 로그 파싱
        if self._log_path and self._log_path.exists():
            result = parse_fakenet_log(self._log_path)
        else:
            # FakeNet-NG가 output_dir에 생성한 로그 파일 자동 탐색
            logs = sorted(self.output_dir.glob("fakenet*.log"), key=lambda p: p.stat().st_mtime)
            result = parse_fakenet_log(logs[-1]) if logs else FakeNetResult()

        result.pcap_path  = pcap_path
        result.elapsed_sec = elapsed
        return result

    def status(self) -> str:
        if not self.is_available():
            return f"미설치 (탐색 경로: {_FAKENET_CANDIDATES[0].parent})"
        if self._proc and self._proc.poll() is None:
            return f"실행 중 (PID {self._proc.pid})"
        return f"설치됨 ({self.fakenet_path})"


def fakenet_result_to_dict(r: FakeNetResult) -> dict:
    """FakeNetResult를 JSON 직렬화 가능한 dict로 변환."""
    return {
        "dns_queries": [
            {"domain": e.queried_domain, "resolved": e.resolved_to}
            for e in r.dns_queries
        ],
        "http_requests": [
            {
                "proto": h.proto, "src_ip": h.src_ip,
                "dst_port": h.dst_port, "method": h.method,
                "host": h.host, "path": h.path,
                "user_agent": h.user_agent,
            }
            for h in r.http_requests
        ],
        "tcp_sessions": [
            {"src_ip": t.src_ip, "dst_port": t.dst_port}
            for t in r.tcp_sessions
        ],
        "pcap_path": str(r.pcap_path) if r.pcap_path else "",
        "elapsed_sec": r.elapsed_sec,
        "error": r.error,
    }
