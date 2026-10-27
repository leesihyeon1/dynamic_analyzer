"""데스크톱 분석 화면의 공통 색상과 위젯 스타일."""
from tkinter import ttk

BG = "#0c1422"
SURFACE = "#142136"
SIDEBAR = "#101c2e"
TEXT = "#e9eff8"
MUTED = "#a6b5cb"
ACCENT = "#45d6bf"


def configure_theme(root):
    root.configure(background=BG)
    root.option_add("*Font", ("맑은 고딕", 11))
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", font=("맑은 고딕", 11), background=BG, foreground=TEXT,
                    bordercolor="#2b3b53", lightcolor=BG, darkcolor=BG)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Side.TFrame", background=SIDEBAR)
    style.configure("Side.TLabel", background=SIDEBAR)
    style.configure("SideMuted.TLabel", background=SIDEBAR, foreground=MUTED, font=("맑은 고딕", 10))
    style.configure("Brand.TLabel", background=SIDEBAR, foreground=ACCENT, font=("Segoe UI", 19, "bold"))
    style.configure("TButton", background="#21324a", foreground=TEXT, padding=(14, 10), borderwidth=0, relief="flat")
    style.map("TButton", background=[("disabled", "#182438"), ("active", "#2c4260")],
              foreground=[("disabled", "#6c7f99")])
    style.configure("Accent.TButton", background=ACCENT, foreground="#072b27", font=("맑은 고딕", 11, "bold"))
    style.map("Accent.TButton", background=[("disabled", "#203c3b"), ("active", "#7ae8d7")],
              foreground=[("disabled", "#73918e"), ("!disabled", "#072b27")])
    style.configure("TEntry", fieldbackground="#0b1525", foreground=TEXT, padding=9,
                    insertcolor=ACCENT, borderwidth=1)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])
    style.configure("TCheckbutton", background=SIDEBAR, foreground=TEXT, padding=(0, 4),
                    indicatorbackground="#23354e", indicatorforeground=ACCENT)
    style.map("TCheckbutton", background=[("active", SIDEBAR)], foreground=[("disabled", "#6c7f99")],
              indicatorbackground=[("selected", ACCENT)])
    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 14))
    style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(11, 10), borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", SURFACE)], foreground=[("selected", ACCENT)])
    style.configure("Treeview", font=("맑은 고딕", 11), rowheight=36, background=SURFACE,
                    fieldbackground=SURFACE, foreground=TEXT, borderwidth=0)
    style.map("Treeview", background=[("selected", "#214940")], foreground=[("selected", "#d5fff5")])
    style.configure("Treeview.Heading", background="#1c2c43", foreground=MUTED,
                    font=("맑은 고딕", 10, "bold"), padding=(12, 10), relief="flat")
    style.map("Treeview.Heading", background=[("active", "#263d57")])
    style.configure("Card.TFrame", background=SURFACE)
    style.configure("Card.TLabel", background=SURFACE, foreground=MUTED, font=("맑은 고딕", 10))
    style.configure("Value.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI", 29, "bold"))
    style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor="#203149", borderwidth=0, thickness=4)
    style.configure("TScrollbar", background="#2b405a", troughcolor=BG, borderwidth=0, arrowsize=13)
