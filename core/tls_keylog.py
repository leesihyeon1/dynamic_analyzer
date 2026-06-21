"""
tls_keylog.py — SSLKEYLOGFILE 기반 TLS 세션 복호화

동작 방식:
  - 샘플 실행 전 SSLKEYLOGFILE=<path> 환경변수 주입
  - Python ssl / Go crypto/tls / NSS(Firefox·Chrome) 기반 앱이 키를 자동 기록
  - tshark가 해당 키로 PCAP을 복호화하여 평문 HTTP 추출

한계:
  - Windows Schannel (WinHTTP / WinINet / SSPI) 기반 악성코드는 미지원
  - 독자 TLS 구현 사용 악성코드도 미지원
  - 위 경우에는 FakeNet-NG 방식(fakenet_integrator.py)을 사용할 것
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DecryptedRequest:
    """TLS 복호화된 HTTP 요청 (SSLKEYLOGFILE 방식)"""
    method:            str
    host:              str
    path:              str
    dst_ip:            str  = ""
    dst_port:          int  = 0
    user_agent:        str  = ""
    content_type:      str  = ""
    body_preview:      str  = ""        # 요청 바디 앞 256바이트
    resp_status:       int  = 0
    resp_content_type: str  = ""
    resp_body_preview: str  = ""        # 응답 바디 앞 256바이트


class TLSKeyLogger:
    """SSLKEYLOGFILE 환경변수 주입 및 복호화 관리."""

    def __init__(self, output_dir: Path) -> None:
        self.keylog_path = Path(output_dir) / "tls_keylog.txt"
        self._available: Optional[bool] = None

    # ── 환경변수 ───────────────────────────────────────────────────────
    def get_env(self, base_env: Optional[dict] = None) -> dict:
        """샘플 실행 환경변수에 SSLKEYLOGFILE을 주입한 dict 반환."""
        env = dict(base_env if base_env is not None else os.environ)
        env["SSLKEYLOGFILE"] = str(self.keylog_path)
        return env

    def has_keys(self) -> bool:
        """키가 기록되었는지 확인."""
        try:
            return self.keylog_path.exists() and self.keylog_path.stat().st_size > 0
        except Exception:
            return False

    def key_count(self) -> int:
        """기록된 키 세션 수 반환."""
        try:
            if not self.keylog_path.exists():
                return 0
            count = 0
            with open(self.keylog_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        count += 1
            return count
        except Exception:
            return 0

    # ── PCAP 복호화 ────────────────────────────────────────────────────
    def decrypt_pcap(
        self,
        pcap_path: Path,
        tshark_path: Path,
        timeout: int = 120,
    ) -> list[DecryptedRequest]:
        """
        tshark로 PCAP을 복호화하여 HTTP 요청/응답 목록을 반환.

        tshark에 -o tls.keylog_file 옵션을 전달해 TLS를 복호화한다.
        """
        if not self.has_keys():
            return []
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            return []

        keylog_str = str(self.keylog_path)
        tshark_str = str(tshark_path)

        # ── Pass 1: 복호화된 HTTP 요청 ───────────────────────────────
        req_fields = [
            "ip.dst",               # 0
            "tcp.dstport",          # 1
            "http.host",            # 2
            "http.request.method",  # 3
            "http.request.uri",     # 4
            "http.user_agent",      # 5
            "http.content_type",    # 6
            "http.file_data",       # 7  요청 바디
        ]
        req_cmd = [
            tshark_str, "-r", str(pcap_path),
            "-o", f"tls.keylog_file:{keylog_str}",
            "-T", "fields",
        ]
        for f in req_fields:
            req_cmd += ["-e", f]
        req_cmd += [
            "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n",
            "-Y", "http.request",
        ]

        requests: list[DecryptedRequest] = []
        try:
            r = subprocess.run(
                req_cmd, capture_output=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
            for ln in r.stdout.splitlines():
                cols = ln.split("\t")
                def _c(i: int) -> str:
                    return cols[i].strip() if i < len(cols) else ""
                method = _c(3)
                if not method:
                    continue
                port_s = _c(1)
                requests.append(DecryptedRequest(
                    dst_ip=_c(0),
                    dst_port=int(port_s) if port_s.isdigit() else 443,
                    host=_c(2),
                    method=method,
                    path=_c(4),
                    user_agent=_c(5),
                    content_type=_c(6),
                    body_preview=_c(7)[:256],
                ))
        except Exception:
            pass

        # ── Pass 2: 복호화된 HTTP 응답 (요청과 순서 대응) ────────────
        resp_fields = [
            "http.response.code",   # 0
            "http.content_type",    # 1
            "http.file_data",       # 2  응답 바디
        ]
        resp_cmd = [
            tshark_str, "-r", str(pcap_path),
            "-o", f"tls.keylog_file:{keylog_str}",
            "-T", "fields",
        ]
        for f in resp_fields:
            resp_cmd += ["-e", f]
        resp_cmd += [
            "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n",
            "-Y", "http.response",
        ]
        try:
            r2 = subprocess.run(
                resp_cmd, capture_output=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
            resp_rows = [ln.split("\t") for ln in r2.stdout.splitlines() if ln.strip()]
            for i, req in enumerate(requests):
                if i < len(resp_rows):
                    row = resp_rows[i]
                    def _r(j: int) -> str:
                        return row[j].strip() if j < len(row) else ""
                    code_s = _r(0)
                    if code_s.isdigit():
                        req.resp_status = int(code_s)
                    req.resp_content_type = _r(1)
                    req.resp_body_preview = _r(2)[:256]
        except Exception:
            pass

        return requests

    def summary(self) -> str:
        """상태 요약 문자열."""
        if not self.has_keys():
            return "키 없음 (Schannel 기반 또는 TLS 미사용 가능성)"
        cnt = self.key_count()
        return f"TLS 세션 키 {cnt}개 기록됨 ({self.keylog_path.name})"
