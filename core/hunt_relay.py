"""
hunt_relay.py — Hunt 탭 API 릴레이 + 리포트 파일 서빙 서버

리포트 생성 후 백그라운드 프로세스로 실행됩니다:
    python hunt_relay.py --port 18080 --dir <report_dir>

기능
----
- GET  /*                    HTML·CSS·JS 리포트 파일 서빙
- POST /hunt/relay/<svc>     abuse.ch API 릴레이
  svc: mb | tf | uh_url | uh_host | feodo

CORS 우회 방식
--------------
브라우저 → 로컬 HTTP 서버 (127.0.0.1:PORT) → Python urllib → abuse.ch
브라우저의 CORS·방화벽 제한을 Python 프로세스 레이어에서 우회합니다.
"""
from __future__ import annotations

import argparse
import http.server
import json
import socket
import socketserver
import sys
import urllib.error
import urllib.request

# svc 키 → upstream URL 매핑
_ENDPOINTS: dict[str, str] = {
    "mb":      "https://mb-api.abuse.ch/api/v1/",
    "tf":      "https://threatfox-api.abuse.ch/api/v1/",
    "uh_url":  "https://urlhaus-api.abuse.ch/v1/url/",
    "uh_host": "https://urlhaus-api.abuse.ch/v1/host/",
    "feodo":   "https://feodotracker.abuse.ch/api/v1/host_info/",
}


def _cors(handler) -> None:
    """CORS 응답 헤더를 추가합니다."""
    handler.send_header("Access-Control-Allow-Origin",  "*")
    handler.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")


class _RelayHandler(http.server.SimpleHTTPRequestHandler):
    """파일 서빙 + /hunt/relay/* POST 릴레이 핸들러"""

    # ── OPTIONS (CORS preflight) ──────────────────────────────────────
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        _cors(self)
        self.end_headers()

    # ── POST /hunt/relay/<svc> ────────────────────────────────────────
    def do_POST(self) -> None:
        if not self.path.startswith("/hunt/relay/"):
            self.send_error(405, "Method Not Allowed")
            return

        svc = self.path[len("/hunt/relay/"):]
        upstream = _ENDPOINTS.get(svc)
        if not upstream:
            self.send_error(400, f"Unknown service key: {svc!r}")
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""
        ct     = self.headers.get("Content-Type", "application/x-www-form-urlencoded")

        try:
            req = urllib.request.Request(
                upstream, data=body, method="POST",
                headers={
                    "Content-Type": ct,
                    "User-Agent":   "dynamic_analyzer/1.5",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                rct = resp.headers.get("Content-Type", "application/json")

            self.send_response(200)
            self.send_header("Content-Type", rct)
            _cors(self)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        except urllib.error.URLError as exc:
            self._relay_error(str(exc.reason))
        except Exception as exc:
            self._relay_error(str(exc))

    def _relay_error(self, msg: str) -> None:
        body = json.dumps({"relay_error": msg}).encode()
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        _cors(self)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── 로그 숨김 ──────────────────────────────────────────────────────
    def log_message(self, fmt, *args) -> None:
        pass


def _make_handler(directory: str):
    """directory 를 바인딩한 _RelayHandler 클래스를 반환합니다."""
    class _H(_RelayHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)
    return _H


def main() -> None:
    ap = argparse.ArgumentParser(description="Hunt 탭 릴레이 서버")
    ap.add_argument("--port", type=int, default=18080, help="수신 포트 (기본: 18080)")
    ap.add_argument("--dir",  default=".",             help="HTML 리포트 디렉터리")
    args = ap.parse_args()

    handler = _make_handler(args.dir)
    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer(("127.0.0.1", args.port), handler) as httpd:
            httpd.serve_forever()
    except OSError as e:
        # 포트 충돌 등 — 조용히 종료 (caller 가 fallback 처리)
        sys.exit(1)


if __name__ == "__main__":
    main()
