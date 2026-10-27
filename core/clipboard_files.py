"""Windows 탐색기 파일 복사(CF_HDROP)를 경로로 읽는다."""
import ctypes
import os
from ctypes import wintypes


def read_copied_files():
    if os.name != "nt":
        return []
    user = ctypes.WinDLL("user32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    user.OpenClipboard.argtypes = [wintypes.HWND]
    user.OpenClipboard.restype = wintypes.BOOL
    user.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    user.GetClipboardData.argtypes = [wintypes.UINT]
    user.GetClipboardData.restype = wintypes.HANDLE
    user.CloseClipboard.argtypes = []
    shell.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
    shell.DragQueryFileW.restype = wintypes.UINT
    if not user.IsClipboardFormatAvailable(15):
        return []
    if not user.OpenClipboard(None):
        raise OSError("클립보드를 다른 앱이 사용 중입니다. 다시 붙여넣어 주세요.")
    try:
        handle = user.GetClipboardData(15)
        if not handle:
            raise OSError("복사한 파일 정보를 읽지 못했습니다.")
        count = shell.DragQueryFileW(handle, 0xFFFFFFFF, None, 0)
        if count != 1:
            raise ValueError("파일 하나만 복사해 주세요.")
        size = shell.DragQueryFileW(handle, 0, None, 0)
        buf = ctypes.create_unicode_buffer(size + 1)
        shell.DragQueryFileW(handle, 0, buf, size + 1)
        return [buf.value]
    finally:
        user.CloseClipboard()
