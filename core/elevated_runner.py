"""관리자 분석 자식 프로세스의 핸들과 로그를 GUI에 연결한다."""
import ctypes
from ctypes import wintypes as W
import codecs
import subprocess
import sys
from pathlib import Path

class ShellExecuteInfo(ctypes.Structure):
    _fields_ = [("cbSize", W.DWORD), ("fMask", W.ULONG), ("hwnd", W.HWND),
                ("lpVerb", W.LPCWSTR), ("lpFile", W.LPCWSTR), ("lpParameters", W.LPCWSTR),
                ("lpDirectory", W.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", W.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", W.LPCWSTR), ("hkeyClass", W.HKEY),
                ("dwHotKey", W.DWORD), ("hIcon", W.HANDLE), ("hProcess", W.HANDLE)]


def run_elevated(command, output, on_line):
    root = Path(__file__).resolve().parents[1]
    log = output / "run.log"
    log.write_bytes(b"")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = W.BOOL
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, ctypes.POINTER(W.DWORD)]
    kernel.GetExitCodeProcess.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x100  # 프로세스 핸들 유지 / 비동기 셸 호출 방지
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = subprocess.list2cmdline([str(root / "analysis_worker.py"), str(log), *command[3:]])
    info.lpDirectory = str(root)
    info.nShow = 0
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        code = ctypes.get_last_error()
        raise OSError("관리자 권한 요청이 취소되었습니다." if code == 1223 else f"분석 실행 실패 (Windows 오류 {code})")
    if not info.hProcess:
        raise OSError("분석 프로세스 핸들을 받지 못했습니다.")
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    pending = ""
    try:
        with log.open("rb") as stream:
            while True:
                status = kernel.WaitForSingleObject(info.hProcess, 150)
                if status not in (0, 258):
                    raise OSError("분석 프로세스 상태 확인 실패")
                pending += decoder.decode(stream.read(), final=status == 0)
                lines = pending.split("\n")
                pending = lines.pop()
                for line in lines:
                    on_line(line.rstrip("\r"))
                if status == 0:
                    if pending:
                        on_line(pending)
                    code = W.DWORD()
                    if not kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
                        raise OSError("분석 종료 코드 확인 실패")
                    return code.value
    finally:
        kernel.CloseHandle(info.hProcess)
