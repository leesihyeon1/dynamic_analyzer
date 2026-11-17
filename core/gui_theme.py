"""데스크톱 분석 화면의 색·글꼴·위젯 스타일.

HTML 보고서(exporters/report_theme.py, report_visuals.py)와 같은 색 체계를 쓴다 —
GUI 에서 본 판정 색이 보고서에서도 같은 의미가 되도록.
둥근 카드나 채운 패널 대신 1px 구분선과 여백으로 영역을 나눈다.
"""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# ── 색 ─────────────────────────────────────────────────────────────────────
BG       = "#0c1422"   # 창 배경 (보고서 --bg)
PANEL    = "#0f192a"   # 왼쪽 입력 열 — 배경과 거의 같은 톤, 선으로만 구분
RAISE    = "#132036"   # 선택·호버 행
LINE     = "#24344b"   # 구분선
LINE_HI  = "#33475f"   # 입력 테두리
TEXT     = "#e6edf6"
MUTED    = "#93a4bb"
FAINT    = "#5d6f88"
ACCENT   = "#45d6bf"
ACCENT_D = "#0b3a34"
MAL      = "#ff6b6b"
SUS      = "#f0b429"
INFO     = "#4fb3d9"
OK       = "#3fb98f"

LEVEL_COLOR = {"mal": MAL, "sus": SUS, "info": INFO, "ok": OK, "": MUTED}

# 하위 호환 (기존 코드·테스트가 가져다 쓰던 이름)
SURFACE = PANEL
SIDEBAR = PANEL

UI_FAMILY   = "맑은 고딕"
MONO_FAMILY = "Consolas"
# 한글 글꼴(맑은 고딕)은 백슬래시를 ₩ 로 그린다. 경로가 많은 표는 Segoe UI 로 그리고
# 한글은 Tk 의 글꼴 대체에 맡긴다.
DATA_FAMILY = "Segoe UI"

_scale = 1.0


def enable_dpi_awareness() -> None:
    """고해상도 화면에서 글자가 번지지 않게 프로세스를 DPI 인식으로 표시한다 (Tk 생성 전에 호출)."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def S(px: float) -> int:
    """96 DPI 기준 픽셀 값을 현재 화면 배율로 환산한다."""
    return max(1, int(round(px * _scale)))


def configure_theme(root: tk.Misc) -> None:
    global _scale
    try:
        _scale = max(1.0, float(root.winfo_fpixels("1i")) / 96.0)
    except Exception:
        _scale = 1.0
    root.configure(background=BG)
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(name).configure(family=UI_FAMILY, size=10)
        except tk.TclError:
            pass
    root.option_add("*Font", (UI_FAMILY, 10))
    root.option_add("*TCombobox*Listbox.background", PANEL)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", font=(UI_FAMILY, 10), background=BG, foreground=TEXT,
                    bordercolor=LINE, lightcolor=BG, darkcolor=BG, troughcolor=BG,
                    focuscolor=ACCENT, selectbackground=RAISE, selectforeground=TEXT)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Line.TFrame", background=LINE)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=(UI_FAMILY, 9))
    style.configure("PanelHead.TLabel", background=PANEL, foreground=MUTED, font=(UI_FAMILY, 9, "bold"))
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Faint.TLabel", foreground=FAINT, font=(UI_FAMILY, 9))
    style.configure("Head.TLabel", foreground=MUTED, font=(UI_FAMILY, 9, "bold"))
    style.configure("Title.TLabel", font=(UI_FAMILY, 16, "bold"))
    style.configure("Brand.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 11))
    style.configure("Mono.TLabel", font=(MONO_FAMILY, 9), foreground=MUTED)
    style.configure("Verdict.TLabel", font=(UI_FAMILY, 11, "bold"))

    # 버튼 — 테두리만 있는 평면 버튼. 주 버튼만 채운다.
    style.configure("TButton", background=BG, foreground=TEXT, bordercolor=LINE_HI,
                    lightcolor=BG, darkcolor=BG, relief="solid", borderwidth=1,
                    padding=(S(12), S(5)), focusthickness=0)
    style.map("TButton",
              background=[("disabled", BG), ("pressed", RAISE), ("active", RAISE)],
              foreground=[("disabled", FAINT)],
              bordercolor=[("disabled", LINE), ("active", ACCENT)])
    style.configure("Panel.TButton", background=PANEL, lightcolor=PANEL, darkcolor=PANEL)
    style.map("Panel.TButton", background=[("disabled", PANEL), ("pressed", RAISE), ("active", RAISE)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#05201c", bordercolor=ACCENT,
                    lightcolor=ACCENT, darkcolor=ACCENT, font=(UI_FAMILY, 10, "bold"), padding=(S(12), S(8)))
    style.map("Accent.TButton",
              background=[("disabled", "#1b3a37"), ("pressed", "#2fb8a3"), ("active", "#6fe3d1")],
              foreground=[("disabled", "#5f8a84")],
              bordercolor=[("disabled", "#1b3a37"), ("active", "#6fe3d1")])
    style.configure("Stop.TButton", background=PANEL, foreground=SUS, bordercolor=SUS,
                    lightcolor=PANEL, darkcolor=PANEL, font=(UI_FAMILY, 10, "bold"), padding=(S(12), S(8)))
    style.map("Stop.TButton", background=[("active", "#2a2410"), ("disabled", PANEL)],
              foreground=[("disabled", FAINT)], bordercolor=[("disabled", LINE)])
    style.configure("Link.TButton", background=BG, foreground=ACCENT, borderwidth=0, relief="flat",
                    padding=(S(2), S(1)))
    style.map("Link.TButton", foreground=[("disabled", FAINT), ("active", "#8af0e0")],
              background=[("active", BG)])

    style.configure("TEntry", fieldbackground=BG, foreground=TEXT, bordercolor=LINE_HI,
                    lightcolor=BG, darkcolor=BG, insertcolor=ACCENT, padding=(S(6), S(4)))
    style.map("TEntry", bordercolor=[("focus", ACCENT)], fieldbackground=[("disabled", PANEL)],
              foreground=[("disabled", FAINT)])

    for name, bg in (("TCheckbutton", BG), ("Panel.TCheckbutton", PANEL)):
        style.configure(name, background=bg, foreground=TEXT, padding=(0, S(3)),
                        indicatorbackground=BG, indicatorforeground=ACCENT, indicatorrelief="flat",
                        indicatormargin=(0, 0, S(8), 0), upperbordercolor=LINE_HI, lowerbordercolor=LINE_HI)
        style.map(name, background=[("active", bg)], foreground=[("disabled", FAINT)],
                  indicatorbackground=[("disabled", bg), ("selected", ACCENT)],
                  indicatorforeground=[("selected", "#05201c")])
    # 세그먼트 선택 (모니터링 시간)
    style.configure("Seg.TRadiobutton", background=PANEL, foreground=MUTED, bordercolor=LINE_HI,
                    relief="solid", borderwidth=1, padding=(S(9), S(3)), indicatorsize=0,
                    indicatormargin=0, indicatorrelief="flat")
    style.layout("Seg.TRadiobutton", [("Radiobutton.padding", {"sticky": "nswe", "children": [
        ("Radiobutton.label", {"sticky": "nswe"})]})])
    style.map("Seg.TRadiobutton", foreground=[("disabled", FAINT), ("selected", ACCENT)],
              background=[("selected", ACCENT_D), ("active", RAISE)])

    style.configure("Treeview", background=BG, fieldbackground=BG, foreground=TEXT,
                    bordercolor=LINE, lightcolor=BG, darkcolor=BG, borderwidth=0,
                    rowheight=S(26), font=(DATA_FAMILY, 10))
    style.map("Treeview", background=[("selected", RAISE)], foreground=[("selected", TEXT)])
    style.configure("Treeview.Heading", background=BG, foreground=MUTED, relief="flat",
                    bordercolor=LINE, lightcolor=BG, darkcolor=BG, font=(UI_FAMILY, 9, "bold"),
                    padding=(S(6), S(5)))
    style.map("Treeview.Heading", background=[("active", BG)], foreground=[("active", TEXT)])
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    style.configure("Vertical.TScrollbar", background=LINE, troughcolor=BG, bordercolor=BG,
                    lightcolor=LINE, darkcolor=LINE, arrowcolor=MUTED, gripcount=0, arrowsize=S(11))
    style.configure("Horizontal.TScrollbar", background=LINE, troughcolor=BG, bordercolor=BG,
                    lightcolor=LINE, darkcolor=LINE, arrowcolor=MUTED, gripcount=0, arrowsize=S(11))
    style.map("Vertical.TScrollbar", background=[("active", LINE_HI)])
    style.map("Horizontal.TScrollbar", background=[("active", LINE_HI)])
    style.configure("Thin.Horizontal.TProgressbar", background=ACCENT, troughcolor=LINE,
                    bordercolor=BG, lightcolor=ACCENT, darkcolor=ACCENT, thickness=S(2))
    style.configure("TSeparator", background=LINE)


def hline(parent: tk.Misc, color: str = LINE, **pack) -> tk.Frame:
    """1px 가로 구분선."""
    line = tk.Frame(parent, height=1, bg=color, bd=0, highlightthickness=0)
    line.pack(fill="x", **pack)
    return line


def vline(parent: tk.Misc, color: str = LINE, **pack) -> tk.Frame:
    """1px 세로 구분선."""
    line = tk.Frame(parent, width=1, bg=color, bd=0, highlightthickness=0)
    line.pack(fill="y", **pack)
    return line
