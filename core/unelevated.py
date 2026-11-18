"""
unelevated.py — 관리자 분석기에서 샘플을 일반 사용자 권한(중간 무결성)으로 실행한다.

분석기는 ProcMon·tshark 때문에 관리자로 돈다. 그 상태로 샘플을 띄우면 샘플도 관리자
권한을 물려받아 UAC 우회(T1548.002) 같은 권한 상승 단계를 아예 건너뛴다 — Remcos 는
관리자로 실행되자 CMSTPLUA 우회 없이 곧바로 HKLM 에 설치했다(ANY.RUN 에서는 우회가 보였다).
사용자가 더블클릭한 것처럼 보려면 데스크톱 셸(explorer.exe)의 토큰으로 띄워야 한다.

    needs_unelevation()                 → 분석기가 관리자일 때만 True
    launch_unelevated(argv, cwd, env)   → UnelevatedProcess | None

어느 단계든 실패하면 None 을 돌려준다 — 호출자는 기존 방식으로 실행한다.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes as W

_WIN = sys.platform == "win32"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_ASSIGN_PRIMARY   = 0x0001
TOKEN_DUPLICATE        = 0x0002
TOKEN_QUERY            = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_DEFAULT   = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY          = 1
SE_PRIVILEGE_ENABLED   = 0x2
CREATE_NEW_CONSOLE     = 0x00000010
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STILL_ACTIVE           = 259
WAIT_TIMEOUT           = 0x102
INFINITE               = 0xFFFFFFFF


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR),
                ("lpTitle", W.LPWSTR), ("dwX", W.DWORD), ("dwY", W.DWORD), ("dwXSize", W.DWORD),
                ("dwYSize", W.DWORD), ("dwXCountChars", W.DWORD), ("dwYCountChars", W.DWORD),
                ("dwFillAttribute", W.DWORD), ("dwFlags", W.DWORD), ("wShowWindow", W.WORD),
                ("cbReserved2", W.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", W.HANDLE),
                ("hStdOutput", W.HANDLE), ("hStdError", W.HANDLE)]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE),
                ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", W.DWORD), ("HighPart", W.LONG)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", W.DWORD), ("Luid", _LUID), ("Attributes", W.DWORD)]


def _dlls():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    return k32, adv, u32


class UnelevatedProcess:
    """subprocess.Popen 과 같은 쓰임(pid · poll · wait · terminate · kill)만 제공한다."""

    def __init__(self, pid: int, handle) -> None:
        self.pid = int(pid)
        self._h = handle
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        k32, _, _ = _dlls()
        code = W.DWORD()
        if k32.GetExitCodeProcess(self._h, ctypes.byref(code)) and code.value != STILL_ACTIVE:
            self.returncode = code.value
        return self.returncode

    def wait(self, timeout=None):
        k32, _, _ = _dlls()
        ms = INFINITE if timeout is None else max(0, int(timeout * 1000))
        if k32.WaitForSingleObject(self._h, ms) == WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(f"PID {self.pid}", timeout)
        return self.poll()

    def terminate(self) -> None:
        k32, _, _ = _dlls()
        k32.TerminateProcess(self._h, 1)

    kill = terminate

    def __del__(self):
        try:
            if self._h:
                _dlls()[0].CloseHandle(self._h)
                self._h = None
        except Exception:
            pass


def needs_unelevation() -> bool:
    """분석기가 관리자로 돌 때만 의미가 있다 — 아니면 샘플은 이미 일반 사용자 권한이다."""
    if not _WIN:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _env_block(env: dict):
    """CreateProcess 용 유니코드 환경 블록 — 'K=V\\0…\\0\\0', 이름은 대소문자 무시 정렬."""
    items = sorted(env.items(), key=lambda kv: kv[0].upper())
    text = "".join(f"{k}={v}\0" for k, v in items if k and "=" not in k[1:]) + "\0"
    return ctypes.create_unicode_buffer(text, len(text))


def _enable_privilege(adv, k32, name: str) -> None:
    """현재 프로세스 토큰의 특권을 켠다 (CreateProcessWithTokenW 는 SeImpersonatePrivilege 필요)."""
    tok = W.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(tok)):
        return
    try:
        luid = _LUID()
        if adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            tp = _TOKEN_PRIVILEGES(1, luid, SE_PRIVILEGE_ENABLED)
            adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
    finally:
        k32.CloseHandle(tok)


def launch_unelevated(argv: list, cwd: str | None = None, env: dict | None = None):
    """explorer.exe 토큰으로 argv 를 실행한다. 성공하면 UnelevatedProcess, 아니면 None."""
    if not _WIN:
        return None
    try:
        k32, adv, u32 = _dlls()
        k32.OpenProcess.restype = W.HANDLE
        u32.GetShellWindow.restype = W.HWND

        shell_pid = W.DWORD()
        hwnd = u32.GetShellWindow()
        if not hwnd or not u32.GetWindowThreadProcessId(hwnd, ctypes.byref(shell_pid)) or not shell_pid.value:
            return None   # 대화형 셸이 없다 (서비스 세션 등)

        _enable_privilege(adv, k32, "SeImpersonatePrivilege")

        h_shell = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, shell_pid.value)
        if not h_shell:
            return None
        h_tok, h_dup = W.HANDLE(), W.HANDLE()
        try:
            if not adv.OpenProcessToken(h_shell, TOKEN_DUPLICATE, ctypes.byref(h_tok)):
                return None
            want = (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)
            if not adv.DuplicateTokenEx(h_tok, want, None, SECURITY_IMPERSONATION, TOKEN_PRIMARY,
                                        ctypes.byref(h_dup)):
                return None

            cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(a) for a in argv]))
            block = _env_block(dict(os.environ) if env is None else dict(env))
            si = _STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            pi = _PROCESS_INFORMATION()
            ok = adv.CreateProcessWithTokenW(
                h_dup, 0, None, cmd, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                block, str(cwd) if cwd else None, ctypes.byref(si), ctypes.byref(pi))
            if not ok:
                return None
            k32.CloseHandle(pi.hThread)
            return UnelevatedProcess(pi.dwProcessId, pi.hProcess)
        finally:
            for h in (h_dup, h_tok):
                if h:
                    k32.CloseHandle(h)
            k32.CloseHandle(h_shell)
    except Exception:
        return None
