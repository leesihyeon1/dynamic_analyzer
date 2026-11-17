"""
hunt_relay.py — Hunt 탭 API 릴레이 + 리포트 파일 서빙 서버

리포트 생성 후 백그라운드 프로세스로 실행됩니다:
    python hunt_relay.py --port 18080 --dir <report_dir>

기능
----
- GET/HEAD /*                리포트 폴더 안의 파일만 서빙 (디렉터리 목록 없음)
- POST /hunt/relay/<svc>     abuse.ch API 릴레이 (+ 선택: IP 국가/ASN 조회)
  svc: mb | tf | uh_url | uh_host | feodo | geo

CORS 우회 방식
--------------
브라우저 → 로컬 HTTP 서버 (127.0.0.1:PORT, 리포트와 같은 오리진) → Python urllib → abuse.ch
리포트를 이 서버가 서빙하므로 릴레이 호출은 같은 오리진 요청이다. 그래서 CORS 허용
헤더(Access-Control-Allow-Origin)를 붙이지 않는다 — 다른 웹사이트가 이 릴레이를 쓰지 못한다.

보안
----
- 127.0.0.1 에만 바인딩한다.
- Host 헤더가 127.0.0.1:PORT / localhost:PORT 가 아니면 403 (DNS 리바인딩 차단).
- POST 는 Origin(있으면)이 같은 오리진이어야 하고, Sec-Fetch-Site 가 cross-site 면 거부.
- Content-Length 는 0..65536 만 허용 (음수·과대 값으로 읽기가 멈추는 것 방지).
- 리포트 폴더 밖(심볼릭 링크 포함)·숨김 파일은 404. 디렉터리 목록은 내보내지 않는다.
- 리포트 화면용 파일(html/css/js/json/이미지/텍스트)이 아니거나 하위 폴더(dumps/, evidence/)의
  파일은 항상 다운로드(attachment)로 내보내고, 실행 가능한 확장자에는 .bin 을 덧붙인다.
- abuse.ch 인증 키(config.json hunt.auth_key 또는 환경변수 ABUSECH_AUTH_KEY)는 이 프로세스가
  upstream 요청에 Auth-Key 헤더로 붙인다. 리포트 HTML 에는 키가 들어가지 않는다.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# 프로젝트 루트를 import 경로에 — core.config_loader 사용 (스크립트로 직접 실행되므로)
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# svc 키 → upstream URL 매핑 (abuse.ch 만 — 인증 키는 이 호스트들에만 붙인다)
_ENDPOINTS: dict[str, str] = {
    "mb":      "https://mb-api.abuse.ch/api/v1/",
    "tf":      "https://threatfox-api.abuse.ch/api/v1/",
    "uh_url":  "https://urlhaus-api.abuse.ch/v1/url/",
    "uh_host": "https://urlhaus-api.abuse.ch/v1/host/",
    "feodo":   "https://feodotracker.abuse.ch/api/v1/host_info/",
}
_ABUSE_HOST_SUFFIX = ".abuse.ch"
_GEO_DEFAULT_URL = "http://ip-api.com/batch?fields=status,country,countryCode,org,as,query"

MAX_BODY = 64 * 1024            # 요청 본문 상한
MAX_UPSTREAM = 8 * 1024 * 1024  # upstream 응답 상한

# 브라우저 안에서 그대로 보여줘도 되는 리포트 구성 파일 (리포트 폴더 최상위만)
_INLINE_EXT = {".html", ".htm", ".css", ".js", ".json", ".png", ".jpg", ".jpeg", ".gif",
               ".svg", ".ico", ".txt", ".log", ".csv"}
# 다운로드 시 원래 확장자로 저장되면 더블클릭 한 번에 실행되는 형식 — .bin 을 덧붙인다
_EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
             ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msp", ".jar", ".cpl", ".shc",
             ".pif", ".reg", ".docm", ".xlsm", ".pptm", ".iso", ".img", ".vhd", ".appx", ".msix"}


def _load_settings() -> dict:
    """인증 키·지오 조회 설정 — config_loader 가 없거나 실패해도 동작한다."""
    out = {"auth_key": "", "geo_lookup": False, "geo_url": _GEO_DEFAULT_URL}
    try:
        from core.config_loader import get_hunt_cfg, get_hunt_auth_key
        hunt = get_hunt_cfg() or {}
        out["auth_key"] = get_hunt_auth_key() or ""
        out["geo_lookup"] = bool(hunt.get("geo_lookup", False))
        url = str(hunt.get("geo_url") or _GEO_DEFAULT_URL)
        if url.lower().startswith(("http://", "https://")):
            out["geo_url"] = url
    except Exception:
        out["auth_key"] = (os.environ.get("ABUSECH_AUTH_KEY") or "").strip()
    return out


def _download_name(real: str, root: str) -> tuple[bool, str]:
    """(inline 허용 여부, 다운로드 파일명)."""
    name = os.path.basename(real)
    ext = os.path.splitext(name)[1].lower()
    top_level = os.path.dirname(real) == root
    if top_level and ext in _INLINE_EXT:
        return True, name
    if ext in _EXEC_EXT:
        name += ".bin"
    return False, name


class _RelayHandler(http.server.SimpleHTTPRequestHandler):
    """파일 서빙 + /hunt/relay/* POST 릴레이 핸들러"""

    settings: dict = {"auth_key": "", "geo_lookup": False, "geo_url": _GEO_DEFAULT_URL}
    server_version = "HuntRelay"
    sys_version = ""

    # ── 공통 검사 ─────────────────────────────────────────────────────
    def _port(self) -> int:
        try:
            return int(self.server.server_address[1])
        except Exception:
            return 0

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        port = self._port()
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _origin_ok(self) -> bool:
        port = self._port()
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            return False
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        return True

    def _reject(self, code: int, msg: str) -> None:
        body = json.dumps({"relay_error": msg}, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def end_headers(self) -> None:
        for k, v in getattr(self, "_extra_headers", None) or ():
            self.send_header(k, v)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    # ── 파일 서빙 ─────────────────────────────────────────────────────
    def send_head(self):
        self._extra_headers = []
        if not self._host_ok():
            self.send_error(403, "Forbidden host")
            return None
        if self.path.startswith("/hunt/"):
            self.send_error(405, "Method Not Allowed")
            return None
        root = os.path.realpath(self.directory)
        real = os.path.realpath(self.translate_path(self.path))
        if real != root and not real.startswith(root + os.sep):
            self.send_error(404, "Not Found")
            return None
        rel_parts = os.path.relpath(real, root).split(os.sep)
        if any(part.startswith(".") and part not in (".",) for part in rel_parts):
            self.send_error(404, "Not Found")
            return None
        if os.path.isfile(real):
            inline, dl_name = _download_name(real, root)
            if inline:
                if real.lower().endswith((".html", ".htm", ".json")):
                    self._extra_headers.append(("Cache-Control", "no-cache"))
            else:
                quoted = urllib.parse.quote(dl_name)
                self._extra_headers.append(
                    ("Content-Disposition", f"attachment; filename=\"{quoted}\"; filename*=UTF-8''{quoted}"))
        return super().send_head()

    def guess_type(self, path):
        try:
            root = os.path.realpath(self.directory)
            inline, _ = _download_name(os.path.realpath(path), root)
        except Exception:
            inline = False
        return super().guess_type(path) if inline else "application/octet-stream"

    def list_directory(self, path):
        # 결과 폴더(덤프·보존 악성 파일·로그) 목록을 내보내지 않는다
        self.send_error(404, "Not Found")
        return None

    # ── OPTIONS ───────────────────────────────────────────────────────
    def do_OPTIONS(self) -> None:
        self._extra_headers = []
        # 같은 오리진 요청에는 preflight 가 없다. CORS 허용 헤더는 보내지 않는다.
        if not self._host_ok() or not self._origin_ok():
            self._reject(403, "forbidden")
            return
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.end_headers()

    # ── POST /hunt/relay/<svc> ────────────────────────────────────────
    def do_POST(self) -> None:
        self._extra_headers = []
        if not self._host_ok():
            self._reject(403, "허용되지 않은 Host")
            return
        if not self._origin_ok():
            self._reject(403, "다른 오리진의 요청은 허용하지 않습니다")
            return
        if not self.path.startswith("/hunt/relay/"):
            self._reject(405, "Method Not Allowed")
            return

        svc = self.path[len("/hunt/relay/"):].split("?", 1)[0]
        if svc == "geo":
            if not self.settings.get("geo_lookup"):
                self._reject(403, "IP 국가/ASN 조회가 꺼져 있습니다 (config.json hunt.geo_lookup)")
                return
            upstream = self.settings.get("geo_url") or _GEO_DEFAULT_URL
        else:
            upstream = _ENDPOINTS.get(svc)
        if not upstream:
            self._reject(400, f"알 수 없는 서비스 키: {svc[:40]!r}")
            return

        raw_len = self.headers.get("Content-Length")
        try:
            length = int(raw_len) if raw_len is not None else 0
        except ValueError:
            length = -1
        if length < 0:
            self._reject(400, "잘못된 Content-Length")
            return
        if length > MAX_BODY:
            self._reject(413, "요청 본문이 너무 큽니다")
            return
        body = self.rfile.read(length) if length else b""
        ct = self.headers.get("Content-Type", "application/x-www-form-urlencoded")
        if "\r" in ct or "\n" in ct or len(ct) > 200:
            self._reject(400, "잘못된 Content-Type")
            return

        headers = {"Content-Type": ct, "User-Agent": "dynamic_analyzer/1.5", "Accept": "application/json"}
        host = (urllib.parse.urlparse(upstream).hostname or "").lower()
        key = self.settings.get("auth_key") or ""
        if key and (host.endswith(_ABUSE_HOST_SUFFIX) or host == "abuse.ch"):
            headers["Auth-Key"] = key

        try:
            req = urllib.request.Request(upstream, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read(MAX_UPSTREAM + 1)
                rct = resp.headers.get("Content-Type", "application/json")
            if len(raw) > MAX_UPSTREAM:
                self._relay_error("upstream 응답이 너무 큽니다")
                return
            self.send_response(200)
            self.send_header("Content-Type", rct)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        except urllib.error.HTTPError as exc:
            # 401/403/5xx — 브라우저가 '미등록'으로 오인하지 않도록 상태 코드를 함께 돌려준다
            detail = ""
            try:
                detail = exc.read(2000).decode("utf-8", "replace")
            except Exception:
                pass
            msg = f"upstream HTTP {exc.code}"
            if exc.code in (401, 403):
                msg += " — 인증 키 " + ("거부" if key else "미설정 (config.json hunt.auth_key)")
            self._relay_error(msg, upstream_status=exc.code, detail=detail[:500])
        except urllib.error.URLError as exc:
            self._relay_error(str(exc.reason))
        except Exception as exc:
            self._relay_error(f"{type(exc).__name__}: {exc}")

    def _relay_error(self, msg: str, upstream_status: int = 0, detail: str = "") -> None:
        data = {"relay_error": msg}
        if upstream_status:
            data["upstream_status"] = upstream_status
        if detail:
            data["upstream_body"] = detail
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(502)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── 로그 숨김 ──────────────────────────────────────────────────────
    def log_message(self, fmt, *args) -> None:
        pass


def _make_handler(directory: str, settings: dict | None = None):
    """directory 를 바인딩한 _RelayHandler 클래스를 반환합니다."""
    directory = os.path.realpath(directory)
    cfg = dict(settings) if settings is not None else _load_settings()

    class _H(_RelayHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)
    _H.settings = cfg
    return _H


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """요청마다 스레드 — 느린 upstream·잘못된 요청이 리포트 서빙을 막지 않는다."""
    daemon_threads = True
    allow_reuse_address = True


def make_server(directory: str, port: int, settings: dict | None = None) -> _Server:
    """127.0.0.1:port 에 바인딩된 서버 (테스트에서는 port=0)."""
    return _Server(("127.0.0.1", port), _make_handler(directory, settings))


def main() -> None:
    ap = argparse.ArgumentParser(description="Hunt 탭 릴레이 서버")
    ap.add_argument("--port", type=int, default=18080, help="수신 포트 (기본: 18080)")
    ap.add_argument("--dir",  default=".",             help="HTML 리포트 디렉터리")
    args = ap.parse_args()

    try:
        with make_server(args.dir, args.port) as httpd:
            httpd.serve_forever()
    except OSError:
        # 포트 충돌 등 — 조용히 종료 (caller 가 fallback 처리)
        sys.exit(1)


if __name__ == "__main__":
    main()
