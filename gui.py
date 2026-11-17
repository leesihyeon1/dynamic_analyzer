"""격리된 Windows 분석 VM에서 쓰는 동적 분석 실행·결과 화면.

왼쪽 열에서 파일과 수집 항목을 고르고, 오른쪽에서 진행 단계와 결과를 본다.
분석 자체는 analyzer.py 를 자식 프로세스로 실행한다 (관리자 권한이 없으면 UAC 승격).
화면은 HTML 보고서와 같은 색 체계를 쓰고, 영역은 1px 선으로만 나눈다.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core.result_summary import ResultSummary, load_result, list_recent_results, format_size
from core.gui_theme import (configure_theme, enable_dpi_awareness, hline, vline, S,
                            BG, PANEL, RAISE, LINE, LINE_HI, TEXT, MUTED, FAINT, ACCENT,
                            MAL, SUS, INFO, OK, LEVEL_COLOR, UI_FAMILY, MONO_FAMILY, DATA_FAMILY)
from core.sample_types import SAMPLE_SUFFIXES, SHELL_EXEC_SUFFIXES

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
# 결과 폴더에 이 파일이 생기면 분석기가 관찰을 조기 종료한다 (core.orchestrator 와 공유).
# 내용이 "skip" 이면 남은 선택 단계(CAPA·VirusTotal·메모리 포렌식·AI)도 건너뛴다.
STOP_FILE = "STOP"

# (키, 표시 이름, 진입을 알리는 로그 패턴)
STAGES = (
    ("snap",    "사전 스냅샷", r"\[1/6\]"),
    ("collect", "수집 시작",   r"\[2/6\]"),
    ("launch",  "샘플 실행",   r"\[3/6\]"),
    ("observe", "관찰",        r"\[4/6\]"),
    ("scan",    "종료·스캔",   r"\[5/6\]"),
    ("post",    "사후 스냅샷", r"\[6/6\]"),
    ("analyze", "분석",        r"\[분석\] (ProcMon CSV 파싱|PCAP 파싱|행동 분류)"),
    ("report",  "보고서",      r"\[보고서\]|\[\*\] 결과 저장 중"),
    ("ai",      "AI 해석",     r"\[AI 분석\]"),
)
_STAGE_RE = [(key, re.compile(pat)) for key, _label, pat in STAGES]
_PRELIM_RE = re.compile(r"\[보고서\] 1차 보고서 저장")
_OBSERVE_RE = re.compile(r"\[4/6\].*?\((\d+)초\)")
_REMAIN_RE = re.compile(r"(\d+)s 경과 / 잔여 (\d+)s")
_LOG_ERR_RE = re.compile(r"\[오류\]|오류:|실패|Traceback|Error\b|예외")
_LOG_WARN_RE = re.compile(r"\[경고\]|\[주의\]|\[!\]|경고|⚠|\[알림\]")
_LOG_STAGE_RE = re.compile(r"^\s*(\[[1-6]/6\]|\[분석\]|\[AI 분석\]|\[보고서\]|\[완료\]|\[도구 확인\]|\[관련도\]|\[메모리 포렌식\]|\[TLS\]|\[YARA\]|\[FakeNet\]|\[\*\])")

TIMEOUT_PRESETS = ("60", "120", "300", "600")

OPTION_ROWS = (  # (키, 이름, 설명, 도구 점검 키)
    ("procmon",  "ProcMon",          "파일·레지스트리·프로세스 이벤트", "procmon"),
    ("tshark",   "패킷 캡처",         "tshark — DNS·HTTP·TLS·SMTP",     "tshark"),
    ("keylog",   "TLS 키 로그",       "SSLKEYLOGFILE 로 HTTPS 복호화",   None),
    ("fakenet",  "FakeNet-NG",       "가짜 인터넷 응답 (실제 통신 차단)", "fakenet"),
    ("memdump",  "메모리 덤프",        "winpmem + Volatility3 (느림)",    "winpmem"),
    ("ph",       "Process Hacker 창", "분석 중 프로세스 창 띄우기",        "process_hacker"),
    ("ai",       "AI 해석",           "NVIDIA NIM — 요약만 전송",        "ai"),
)


def build_command(path: Path, output: Path, timeout: int, *, procmon: bool,
                  tshark: bool, ph: bool, keylog: bool, ai: bool,
                  memdump: bool, fakenet: bool) -> list[str]:
    """GUI 선택값을 기존 CLI 인자로 변환한다."""
    command = [sys.executable, "-u", str(ROOT / "analyzer.py")]
    if path.suffix.lower() in PCAP_SUFFIXES:
        command += ["--pcap", str(path), "--no-procmon", "--no-tshark", "--no-ph"]
    else:
        command.append(str(path))
        if not procmon:
            command.append("--no-procmon")
        if not tshark:
            command.append("--no-tshark")
        if not ph:
            command.append("--no-ph")
        if not keylog:
            command.append("--no-keylog")
        if memdump:
            command.append("--memdump")
        if fakenet:
            command.append("--fakenet")
    if not ai:
        command.append("--no-ai")
    command += ["--timeout", str(timeout), "--output", str(output), "--no-open"]
    return command


EXIT_MEANING = {
    1: "분석기 오류로 중단되었습니다 — 실행 로그의 마지막 줄을 확인하세요",
    2: "샘플을 실행하지 못했습니다 — 보고서는 수집된 범위로 저장되었습니다",
}


def tail_log(path: Path, poll, on_line, interval: float = 0.15) -> int:
    """자식 프로세스가 쓰는 로그 파일을 줄 단위로 따라 읽고, 끝나면 종료 코드를 돌려준다.

    poll() 은 실행 중이면 None, 끝났으면 종료 코드를 돌려준다 (Popen.poll).
    UTF-8 이 줄 중간에서 잘려도 깨지지 않게 증분 디코더를 쓴다.
    """
    import codecs
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    pending = ""
    with path.open("rb") as stream:
        while True:
            code = poll()
            chunk = stream.read()
            pending += decoder.decode(chunk, final=code is not None and not chunk)
            lines = pending.split("\n")
            pending = lines.pop()
            for line in lines:
                on_line(line.rstrip("\r"))
            if code is not None and not chunk:
                if pending:
                    on_line(pending.rstrip("\r"))
                return code
            if not chunk:
                time.sleep(interval)


def sample_kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in PCAP_SUFFIXES:
        return "PCAP — 실행 없이 네트워크만 분석"
    if ext == ".exe":
        return "실행 파일"
    if ext in {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".psd1"}:
        return "스크립트 — 연결된 호스트 앱으로 실행"
    if ext in {".url", ".lnk"}:
        return "바로가기 — 셸로 실행"
    if ext in SHELL_EXEC_SUFFIXES:
        return "문서 — 연결된 앱으로 열기"
    return "지원하지 않는 형식"


# ════════════════════════════════════════════════════════════════════════════
# 작은 위젯들
# ════════════════════════════════════════════════════════════════════════════

class TabBar(tk.Frame):
    """밑줄 탭 + 페이지 묶음. ttk.Notebook 의 select() 사용법을 그대로 따른다."""

    def __init__(self, master, body: tk.Misc) -> None:
        super().__init__(master, bg=BG)
        self.body = body
        self.pages: list[tuple[tk.Widget, tk.Label, tk.Frame]] = []
        self.current: tk.Widget | None = None

    def add(self, page: tk.Widget, text: str) -> None:
        cell = tk.Frame(self, bg=BG)
        cell.pack(side="left", padx=(0, S(18)))
        label = tk.Label(cell, text=text, bg=BG, fg=MUTED, font=(UI_FAMILY, 10), cursor="hand2",
                         padx=0, pady=S(6))
        label.pack()
        bar = tk.Frame(cell, height=S(2), bg=BG)
        bar.pack(fill="x")
        label.bind("<Button-1>", lambda _e, p=page: self.select(p))
        self.pages.append((page, label, bar))
        page.grid(row=0, column=0, sticky="nsew", in_=self.body)
        page.grid_remove()
        if self.current is None:
            self.select(page)

    def set_text(self, page: tk.Widget, text: str) -> None:
        for p, label, _bar in self.pages:
            if p is page:
                label.configure(text=text)

    def select(self, page: tk.Widget | int | None = None):
        if page is None:
            return str(self.current) if self.current is not None else ""
        if isinstance(page, int):
            page = self.pages[page][0]
        for p, label, bar in self.pages:
            active = p is page
            label.configure(fg=TEXT if active else MUTED,
                            font=(UI_FAMILY, 10, "bold") if active else (UI_FAMILY, 10))
            bar.configure(bg=ACCENT if active else BG)
            if active:
                p.grid()
            else:
                p.grid_remove()
        self.current = page
        return str(page)


class Tooltip:
    """마우스를 올리면 잠깐 뜨는 설명 — 한 줄 설명이 화면 높이를 잡아먹지 않게 한다."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget, self.text, self.tip, self.job = widget, text, None, None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self.job = self.widget.after(450, self._show)

    def _cancel(self) -> None:
        if self.job:
            try:
                self.widget.after_cancel(self.job)
            except tk.TclError:
                pass
            self.job = None

    def _show(self) -> None:
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + S(8)
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + S(4)
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, bg=RAISE, fg=TEXT, font=(UI_FAMILY, 9), justify="left",
                 padx=S(8), pady=S(4), highlightthickness=1, highlightbackground=LINE_HI,
                 wraplength=S(360)).pack()

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self.tip:
            self.tip.destroy()
            self.tip = None


class LinkLabel(tk.Label):
    """테두리 없는 텍스트 버튼 — configure(state=...) 를 버튼처럼 받는다."""

    def __init__(self, master, text: str, command, bg: str = BG) -> None:
        super().__init__(master, text=text, bg=bg, fg=ACCENT, font=(UI_FAMILY, 9), cursor="hand2")
        self._command = command
        self._enabled = True
        self.bind("<Button-1>", lambda _e: self._enabled and self._command())

    def configure(self, cnf=None, **kw):
        if "state" in kw:
            self._enabled = kw.pop("state") != "disabled"
            kw["fg"] = ACCENT if self._enabled else FAINT
            kw["cursor"] = "hand2" if self._enabled else "arrow"
        return super().configure(cnf, **kw)

    config = configure


class ThinBar(tk.Canvas):
    """2px 진행 선 — ttk 진행 막대는 clam 테마에서 두께가 줄지 않는다."""

    def __init__(self, master) -> None:
        super().__init__(master, height=S(2), bg=LINE, highlightthickness=0, bd=0)
        self.value = 0.0
        self.bind("<Configure>", lambda _e: self._draw())

    def configure(self, cnf=None, **kw):
        """Progressbar 와 같은 configure(value=...) 사용법을 받는다."""
        if "value" in kw:
            self.value = max(0.0, min(100.0, float(kw.pop("value"))))
            self._draw()
        if cnf or kw:
            return super().configure(cnf, **kw)
        return None

    config = configure

    def _draw(self) -> None:
        self.delete("all")
        w = self.winfo_width()
        if self.value > 0:
            self.create_rectangle(0, 0, w * self.value / 100, S(2), fill=ACCENT, outline="")


class Stepper(tk.Canvas):
    """분석 단계를 한 줄의 선과 점으로 그린다."""

    def __init__(self, master) -> None:
        super().__init__(master, height=S(46), bg=BG, highlightthickness=0, bd=0)
        self.states = {key: "pending" for key, _l, _p in STAGES}
        self.bind("<Configure>", lambda _e: self.redraw())

    def reset(self, state: str = "pending") -> None:
        self.states = {key: state for key, _l, _p in STAGES}
        self.redraw()

    def set(self, key: str, state: str) -> None:
        self.states[key] = state
        self.redraw()

    def advance_to(self, key: str) -> None:
        """key 단계로 진입 — 앞 단계는 완료(로그에 안 나온 단계는 생략)로 표시한다."""
        seen = True
        for k, _l, _p in STAGES:
            if k == key:
                self.states[k] = "active"
                seen = False
            elif seen:
                if self.states[k] in ("active",):
                    self.states[k] = "done"
                elif self.states[k] == "pending":
                    self.states[k] = "skipped"
        self.redraw()

    def finish(self, failed: bool = False) -> None:
        for k, _l, _p in STAGES:
            if self.states[k] == "active":
                self.states[k] = "failed" if failed else "done"
            elif self.states[k] == "pending":
                self.states[k] = "skipped"
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w = max(self.winfo_width(), S(400))
        n = len(STAGES)
        pad = S(34)
        step = (w - 2 * pad) / (n - 1)
        y = S(12)
        r = S(5)
        colors = {"done": ACCENT, "active": ACCENT, "pending": LINE_HI, "skipped": LINE,
                  "failed": MAL}
        for i in range(n - 1):
            a, b = STAGES[i][0], STAGES[i + 1][0]
            done = self.states[a] in ("done", "skipped") and self.states[b] != "pending"
            self.create_line(pad + i * step + r, y, pad + (i + 1) * step - r, y,
                             fill=ACCENT if done else LINE, width=1)
        for i, (key, label, _p) in enumerate(STAGES):
            x = pad + i * step
            state = self.states[key]
            color = colors[state]
            if state == "done":
                self.create_oval(x - r, y - r, x + r, y + r, fill=color, outline=color)
            elif state == "active":
                self.create_oval(x - r - S(3), y - r - S(3), x + r + S(3), y + r + S(3), outline=ACCENT, width=1)
                self.create_oval(x - r + 1, y - r + 1, x + r - 1, y + r - 1, fill=ACCENT, outline=ACCENT)
            elif state == "failed":
                self.create_line(x - r, y - r, x + r, y + r, fill=MAL, width=2)
                self.create_line(x - r, y + r, x + r, y - r, fill=MAL, width=2)
            elif state == "skipped":
                self.create_line(x - r, y, x + r, y, fill=FAINT, width=2)
            else:
                self.create_oval(x - r, y - r, x + r, y + r, fill=BG, outline=color)
            fg = {"active": TEXT, "done": MUTED, "failed": MAL}.get(state, FAINT)
            self.create_text(x, y + S(20), text=label, fill=fg,
                             font=(UI_FAMILY, 9, "bold" if state == "active" else "normal"))


class RichText(tk.Text):
    """세로로 나열하는 읽기 전용 결과 보기 — 제목, 1px 선, 정렬된 행, 링크."""

    def __init__(self, master, **kw) -> None:
        super().__init__(master, bg=BG, fg=TEXT, relief="flat", bd=0, highlightthickness=0,
                         wrap="word", padx=S(2), pady=S(4), cursor="arrow",
                         font=(UI_FAMILY, 10), spacing1=S(1), spacing3=S(1),
                         insertbackground=BG, selectbackground=RAISE, **kw)
        self._links: dict[str, object] = {}
        col1, col2 = S(22), S(108)
        self.tag_configure("h", font=(UI_FAMILY, 11, "bold"), foreground=TEXT, spacing1=S(16), spacing3=S(4))
        self.tag_configure("count", font=(UI_FAMILY, 9), foreground=MUTED)
        self.tag_configure("rule", font=(UI_FAMILY, -1), background=LINE, spacing1=0, spacing3=0)
        self.tag_configure("gap", font=(UI_FAMILY, -1), spacing1=0, spacing3=S(5))
        self.tag_configure("row", tabs=(col1, col2), lmargin1=0, lmargin2=col2, spacing1=S(3))
        self.tag_configure("sub", font=(MONO_FAMILY, 9), foreground=MUTED, lmargin1=col2, lmargin2=col2,
                           spacing3=S(3))
        self.tag_configure("kv", tabs=(S(118),), lmargin2=S(118), spacing1=S(2))
        self.tag_configure("row2", tabs=(col1, S(170)), lmargin1=0, lmargin2=S(170), spacing1=S(3))
        self.tag_configure("para", lmargin1=0, lmargin2=0, spacing1=S(2), spacing3=S(2))
        self.tag_configure("muted", foreground=MUTED)
        self.tag_configure("faint", foreground=FAINT)
        self.tag_configure("mono", font=(MONO_FAMILY, 9))
        self.tag_configure("bold", font=(UI_FAMILY, 10, "bold"))
        self.tag_configure("tid", foreground=ACCENT, font=(MONO_FAMILY, 9))
        for name, color in (("mal", MAL), ("sus", SUS), ("info", INFO), ("ok", OK), ("accent", ACCENT)):
            self.tag_configure(name, foreground=color)
        self.tag_configure("note", foreground=SUS, lmargin1=0, lmargin2=S(18), spacing1=S(2))
        self.tag_bind("link", "<Enter>", lambda _e: self.configure(cursor="hand2"))
        self.tag_bind("link", "<Leave>", lambda _e: self.configure(cursor="arrow"))
        self.bind("<Key>", self._readonly)
        self.bind("<Control-c>", lambda _e: None)
        self.bind("<Control-a>", self._select_all)
        menu = tk.Menu(self, tearoff=False, bg=PANEL, fg=TEXT, activebackground=RAISE, activeforeground=TEXT)
        menu.add_command(label="복사", command=self._copy)
        menu.add_command(label="전체 선택", command=lambda: self._select_all(None))
        self.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))

    def _readonly(self, event):
        if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
            return None
        if event.keysym in ("Up", "Down", "Left", "Right", "Prior", "Next", "Home", "End"):
            return None
        return "break"

    def _select_all(self, _event):
        self.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _copy(self):
        try:
            text = self.get("sel.first", "sel.last")
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def clear(self) -> None:
        self.delete("1.0", "end")
        self._links.clear()

    def h(self, title: str, count: str = "") -> None:
        if self.index("end-1c") != "1.0":
            self.insert("end", "\n")
        self.insert("end", title, ("h",))
        if count:
            self.insert("end", "   " + count, ("h", "count"))
        self.insert("end", "\n", ("h",))
        self.insert("end", "\n", ("rule",))
        self.insert("end", "\n", ("gap",))

    def put(self, text: str, *tags: str) -> None:
        self.insert("end", text, tags)

    def link(self, text: str, action, *tags: str) -> None:
        name = f"link{len(self._links)}"
        self._links[name] = action
        self.insert("end", text, (*tags, "link", name))
        self.tag_bind(name, "<Button-1>", lambda _e, a=action: a())

    def nl(self, *tags: str) -> None:
        self.insert("end", "\n", tags)


def scrolled(parent: tk.Misc, widget_factory) -> tuple[tk.Frame, tk.Widget]:
    """세로 스크롤바가 붙은 위젯 묶음."""
    frame = tk.Frame(parent, bg=BG)
    widget = widget_factory(frame)
    bar = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
    widget.configure(yscrollcommand=bar.set)
    widget.grid(row=0, column=0, sticky="nsew")
    bar.grid(row=0, column=1, sticky="ns")
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)
    return frame, widget


def make_tree(parent: tk.Misc, columns: tuple, widths: tuple, *, tree_col: str = "",
              tree_width: int = 0, height: int = 8) -> tuple[tk.Frame, ttk.Treeview]:
    frame = tk.Frame(parent, bg=BG)
    show = "tree headings" if tree_col else "headings"
    tree = ttk.Treeview(frame, columns=columns, show=show, height=height, selectmode="browse")
    if tree_col:
        tree.heading("#0", text=tree_col, anchor="w")
        tree.column("#0", width=S(tree_width), minwidth=S(120), stretch=False)
    for column, width in zip(columns, widths):
        tree.heading(column, text=column, anchor="w")
        tree.column(column, width=S(width), minwidth=S(50), stretch=column == columns[-1], anchor="w")
    ybar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    xbar = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
    tree.grid(row=0, column=0, sticky="nsew")
    ybar.grid(row=0, column=1, sticky="ns")
    xbar.grid(row=1, column=0, sticky="ew")
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)
    for name, color in (("mal", MAL), ("sus", SUS), ("info", INFO), ("ok", OK), ("muted", MUTED),
                        ("faint", FAINT), ("accent", ACCENT)):
        tree.tag_configure(name, foreground=color)
    tree.tag_configure("bold", font=(DATA_FAMILY, 10, "bold"))

    def copy_row(_event=None):
        sel = tree.selection()
        if not sel:
            return
        values = [tree.item(sel[0], "text")] + [str(v) for v in tree.item(sel[0], "values")]
        tree.clipboard_clear()
        tree.clipboard_append("\t".join(v for v in values if v))
    tree.bind("<Control-c>", copy_row)
    menu = tk.Menu(tree, tearoff=False, bg=PANEL, fg=TEXT, activebackground=RAISE, activeforeground=TEXT)
    menu.add_command(label="행 복사", command=copy_row)
    tree.bind("<Button-3>", lambda e: (tree.selection_set(tree.identify_row(e.y)) if tree.identify_row(e.y) else None,
                                       menu.tk_popup(e.x_root, e.y_root)))
    return frame, tree


def section_label(parent: tk.Misc, text: str, bg: str = BG, note: str = "") -> tk.Frame:
    row = tk.Frame(parent, bg=bg)
    tk.Label(row, text=text, bg=bg, fg=TEXT, font=(UI_FAMILY, 10, "bold")).pack(side="left")
    if note:
        tk.Label(row, text=note, bg=bg, fg=MUTED, font=(UI_FAMILY, 9)).pack(side="left", padx=(S(10), 0))
    return row


# ════════════════════════════════════════════════════════════════════════════
# 메인 화면
# ════════════════════════════════════════════════════════════════════════════

class AnalyzerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("dynamic_analyzer — 동적 분석")
        configure_theme(root)
        self.root.geometry(f"{S(1360)}x{S(880)}")
        self.root.minsize(S(1120), S(720))
        self.path = tk.StringVar()
        self.timeout = tk.StringVar(value="60")
        self.status = tk.StringVar(value="분석할 파일을 고르세요.")
        self.options = {name: tk.BooleanVar(value=default) for name, default in {
            "procmon": True, "tshark": True, "ph": False, "keylog": True,
            "ai": True, "memdump": False, "fakenet": False,
        }.items()}
        self.log_filter = tk.StringVar(value="all")
        self.autoscroll = tk.BooleanVar(value=True)
        self.proc_scope = tk.StringVar(value="lineage")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.running = False
        self.loading = False
        self.run_failure: str | None = None
        self.summary: ResultSummary | None = None
        self.output: Path | None = None
        self.report: Path | None = None
        self.started_at = 0.0
        self.observe_started = 0.0
        self.observe_total = 0
        self.stage = ""
        self.stop_level = ""
        self.preflight: dict = {}
        self.log_lines: list[tuple[str, str]] = []
        self.prelim_loaded = False
        self._recent: list = []
        self._forced_off: set[str] = set()
        self._reload_pending: tuple | None = None

        self._build_header()
        hline(root)
        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True)
        self._build_left(body)
        vline(body, side="left")
        self._build_main(body)

        self.install_drop()
        self.path.trace_add("write", lambda *_: self.on_path_change())
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        for seq, fn in (("<F5>", lambda _e: self.start()), ("<Control-o>", lambda _e: self.choose_file()),
                        ("<Control-r>", lambda _e: self.refresh_recent()), ("<Escape>", lambda _e: self.request_stop())):
            self.root.bind(seq, fn)
        self.on_path_change()
        self.show_idle()
        self.root.after(100, self.drain_events)
        self.root.after(1000, self.tick)
        self.run_preflight()
        self.refresh_recent()

    # ── 화면 구성 ──────────────────────────────────────────────────────────
    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg=BG, height=S(40))
        bar.pack(fill="x")
        tk.Label(bar, text="dynamic_analyzer", bg=BG, fg=TEXT, font=("Segoe UI Semibold", 11)).pack(
            side="left", padx=(S(16), S(4)), pady=S(8))
        tk.Label(bar, text="동적 분석", bg=BG, fg=MUTED, font=(UI_FAMILY, 9)).pack(side="left", pady=S(8))
        self.ai_settings_button = ttk.Button(bar, text="AI 설정", command=self.ai_settings)
        self.ai_settings_button.pack(side="right", padx=(S(6), S(14)), pady=S(6))
        self.preflight_button = ttk.Button(bar, text="도구 점검", command=self.run_preflight)
        self.preflight_button.pack(side="right", pady=S(6))
        self.env_frame = tk.Frame(bar, bg=BG)
        self.env_frame.pack(side="right", padx=S(14))
        tk.Label(self.env_frame, text="도구 점검 중…", bg=BG, fg=FAINT, font=(UI_FAMILY, 9)).pack(side="left")

    def _build_left(self, body: tk.Frame) -> None:
        left = tk.Frame(body, bg=PANEL, width=S(316))
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        inner = tk.Frame(left, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=S(16), pady=(S(14), S(10)))

        tk.Label(inner, text="새 분석", bg=PANEL, fg=MUTED, font=(UI_FAMILY, 9, "bold")).pack(anchor="w")
        self.drop = tk.Canvas(inner, height=S(78), bg=PANEL, highlightthickness=0, bd=0, cursor="hand2")
        self.drop.pack(fill="x", pady=(S(6), S(6)))
        self.drop.bind("<Configure>", lambda _e: self.draw_drop())
        self.drop.bind("<Button-1>", lambda _e: self.choose_file())
        self.drop_label = self.drop  # 하위 호환 (드롭 대상)
        self.drop_hint = "파일을 끌어다 놓거나 클릭해 고르세요"
        self.path_entry = ttk.Entry(inner, textvariable=self.path, font=(MONO_FAMILY, 9))
        self.path_entry.pack(fill="x")
        for seq in ("<<Paste>>", "<Control-v>", "<Control-V>", "<Shift-Insert>"):
            self.path_entry.bind(seq, self.paste_file)
        menu = tk.Menu(self.path_entry, tearoff=False, bg=PANEL, fg=TEXT, activebackground=RAISE)
        menu.add_command(label="파일 / 경로 붙여넣기", command=self.paste_file)
        self.path_entry.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))
        row = tk.Frame(inner, bg=PANEL)
        row.pack(fill="x", pady=(S(4), 0))
        self.browse = ttk.Button(row, text="찾아보기", command=self.choose_file, style="Panel.TButton")
        self.browse.pack(side="right")
        self.file_meta = tk.Label(row, text="", bg=PANEL, fg=MUTED, font=(UI_FAMILY, 9), anchor="w", justify="left")
        self.file_meta.pack(side="left", fill="x", expand=True)

        hline(inner, pady=(S(12), S(10)))
        tk.Label(inner, text="관찰 시간 (초)", bg=PANEL, fg=MUTED, font=(UI_FAMILY, 9, "bold")).pack(anchor="w")
        seg = tk.Frame(inner, bg=PANEL)
        seg.pack(fill="x", pady=(S(6), 0))
        self.timeout_buttons = []
        for value in TIMEOUT_PRESETS:
            b = ttk.Radiobutton(seg, text=value, value=value, variable=self.timeout, style="Seg.TRadiobutton")
            b.pack(side="left", padx=(0, S(4)))
            self.timeout_buttons.append(b)
        self.timeout_entry = ttk.Entry(seg, textvariable=self.timeout, width=6, font=(MONO_FAMILY, 9))
        self.timeout_entry.pack(side="left", padx=(S(4), 0))

        hline(inner, pady=(S(12), S(8)))
        tk.Label(inner, text="수집 항목", bg=PANEL, fg=MUTED, font=(UI_FAMILY, 9, "bold")).pack(anchor="w")
        self.checks: dict[str, ttk.Checkbutton] = {}
        self.option_notes: dict[str, tk.Label] = {}
        for key, label, desc, _tool in OPTION_ROWS:
            r = tk.Frame(inner, bg=PANEL)
            r.pack(fill="x", pady=(S(1), 0))
            check = ttk.Checkbutton(r, text=label, variable=self.options[key], style="Panel.TCheckbutton")
            check.pack(side="left")
            note = tk.Label(r, text="", bg=PANEL, fg=FAINT, font=(UI_FAMILY, 8))
            note.pack(side="right")
            Tooltip(check, desc)   # 설명은 한 줄을 차지하지 않게 마우스를 올렸을 때만
            self.checks[key] = check
            self.option_notes[key] = note

        hline(inner, pady=(S(12), S(10)))
        self.action_box = tk.Frame(inner, bg=PANEL)
        self.action_box.pack(fill="x")
        self.start_button = ttk.Button(self.action_box, text="분석 시작    F5", command=self.start, style="Accent.TButton")
        self.start_button.pack(fill="x")
        self.stop_button = ttk.Button(self.action_box, text="관찰 조기 종료    Esc", command=self.request_stop, style="Stop.TButton")

        hline(inner, pady=(S(12), S(8)))
        head = tk.Frame(inner, bg=PANEL)
        head.pack(fill="x")
        tk.Label(head, text="최근 결과", bg=PANEL, fg=MUTED, font=(UI_FAMILY, 9, "bold")).pack(side="left")
        self.load_button = LinkLabel(head, "폴더 열기…", self.choose_result, bg=PANEL)
        self.load_button.pack(side="right")
        self.recent_tree = ttk.Treeview(inner, columns=("when",), show="tree", selectmode="browse", height=6)
        self.recent_tree.column("#0", width=S(190), stretch=True)
        self.recent_tree.column("when", width=S(86), stretch=False, anchor="e")
        for name, color in (("mal", MAL), ("sus", SUS), ("ok", OK), ("muted", MUTED)):
            self.recent_tree.tag_configure(name, foreground=color)
        self.recent_tree.pack(fill="both", expand=True, pady=(S(4), 0))
        self.recent_tree.bind("<Double-1>", self.open_recent)
        self.recent_tree.bind("<Return>", self.open_recent)

    def _build_main(self, body: tk.Frame) -> None:
        main = tk.Frame(body, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        pad = S(22)

        top = tk.Frame(main, bg=BG)
        top.pack(fill="x", padx=pad, pady=(S(14), 0))
        actions = tk.Frame(top, bg=BG)
        actions.pack(side="right", anchor="n")
        self.report_button = ttk.Button(actions, text="HTML 보고서 ↗", command=self.open_report, state="disabled")
        self.report_button.pack(side="left")
        self.folder_button = ttk.Button(actions, text="결과 폴더", command=self.open_folder, state="disabled")
        self.folder_button.pack(side="left", padx=(S(6), 0))
        titles = tk.Frame(top, bg=BG)
        titles.pack(side="left", fill="x", expand=True)
        line1 = tk.Frame(titles, bg=BG)
        line1.pack(anchor="w", fill="x")
        self.summary_title = tk.Label(line1, text="", bg=BG, fg=TEXT, font=(UI_FAMILY, 16, "bold"), anchor="w")
        self.summary_title.pack(side="left")
        self.verdict_label = tk.Label(line1, text="", bg=BG, fg=MUTED, font=(UI_FAMILY, 11, "bold"))
        self.verdict_label.pack(side="left", padx=(S(14), 0), pady=(S(4), 0))
        self.summary_detail = tk.Label(titles, text="", bg=BG, fg=MUTED, font=(UI_FAMILY, 9), anchor="w", justify="left")
        self.summary_detail.pack(anchor="w", fill="x", pady=(S(2), 0))
        self.hash_label = tk.Label(titles, text="", bg=BG, fg=FAINT, font=(MONO_FAMILY, 9), anchor="w")
        self.hash_label.pack(anchor="w", fill="x")

        hline(main, padx=pad, pady=(S(10), S(4)))
        self.stepper = Stepper(main)
        self.stepper.pack(fill="x", padx=pad)
        prog = tk.Frame(main, bg=BG)
        prog.pack(fill="x", padx=pad, pady=(0, S(2)))
        self.clock_label = tk.Label(prog, text="", bg=BG, fg=MUTED, font=(MONO_FAMILY, 9))
        self.clock_label.pack(side="right")
        self.status_label = tk.Label(prog, textvariable=self.status, bg=BG, fg=MUTED, font=(UI_FAMILY, 9), anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)
        self.progress = ThinBar(main)
        self.progress.pack(fill="x", padx=pad)
        hline(main, padx=pad, pady=(S(8), 0))

        tabrow = tk.Frame(main, bg=BG)
        tabrow.pack(fill="x", padx=pad, pady=(S(4), 0))
        stack = tk.Frame(main, bg=BG)
        stack.pack(fill="both", expand=True, padx=pad, pady=(S(6), S(4)))
        stack.columnconfigure(0, weight=1)
        stack.rowconfigure(0, weight=1)
        self.tabs = TabBar(tabrow, stack)
        self.tabs.pack(side="left")
        hline(main, padx=pad)

        # 요약
        frame, self.summary_text = scrolled(stack, RichText)
        self.overview = frame
        self.tabs.add(frame, "요약")
        # 프로세스
        proc = tk.Frame(stack, bg=BG)
        bar = tk.Frame(proc, bg=BG)
        bar.pack(fill="x", pady=(0, S(6)))
        for value, text in (("lineage", "샘플 계보"), ("related", "계보 + 의심"), ("all", "전체")):
            ttk.Radiobutton(bar, text=text, value=value, variable=self.proc_scope, style="Seg.TRadiobutton",
                            command=self.fill_processes).pack(side="left", padx=(0, S(4)))
        self.proc_note = tk.Label(bar, text="", bg=BG, fg=MUTED, font=(UI_FAMILY, 9))
        self.proc_note.pack(side="left", padx=(S(10), 0))
        pane = tk.PanedWindow(proc, orient="vertical", bg=LINE, sashwidth=1, bd=0, showhandle=False)
        pane.pack(fill="both", expand=True)
        tf, self.proc_tree = make_tree(pane, ("PID", "등급", "행위", "명령줄"), (70, 70, 190, 520),
                                       tree_col="프로세스", tree_width=230, height=10)
        self.proc_tree.bind("<<TreeviewSelect>>", self.show_process)
        df, self.proc_detail = scrolled(pane, lambda m: RichText(m, height=8))
        pane.add(tf, minsize=S(160), stretch="always")
        pane.add(df, minsize=S(110), stretch="always")
        self.process_tab = proc
        self.tabs.add(proc, "프로세스")
        # 네트워크
        net = tk.Frame(stack, bg=BG)
        section_label(net, "연결", note="프로세스 귀속을 확인한 순서로 정렬").pack(fill="x", pady=(0, S(4)))
        cf, self.connection_tree = make_tree(net, ("귀속", "프로세스", "PID", "원격 주소", "도메인", "이벤트"),
                                             (90, 170, 64, 190, 260, 60), height=8)
        cf.pack(fill="both", expand=True)
        section_label(net, "DNS 질의", note="응답 없는 질의는 접속 시도로만 본다").pack(fill="x", pady=(S(10), S(4)))
        nf, self.dns_tree = make_tree(net, ("도메인", "응답", "프로세스", "상태"), (300, 220, 170, 120), height=6)
        nf.pack(fill="both", expand=True)
        self.network_tab = net
        self.tabs.add(net, "네트워크")
        # 파일·레지스트리
        fr = tk.Frame(stack, bg=BG)
        section_label(fr, "드롭 파일", note="샘플 계보가 쓴 파일 — 증거 폴더 사본 포함").pack(fill="x", pady=(0, S(4)))
        ff, self.file_tree = make_tree(fr, ("경로", "크기", "SHA-256", "등급"), (470, 80, 200, 70), height=8)
        ff.pack(fill="both", expand=True)
        section_label(fr, "레지스트리 변경", note="사전·사후 스냅샷 차이").pack(fill="x", pady=(S(10), S(4)))
        rf, self.registry_tree = make_tree(fr, ("변경", "키", "값", "데이터"), (60, 430, 140, 260), height=6)
        rf.pack(fill="both", expand=True)
        self.files_tab = fr
        self.tabs.add(fr, "파일·레지스트리")
        # 수집 상태
        frame, self.collect_text = scrolled(stack, RichText)
        self.collect_tab = frame
        self.tabs.add(frame, "수집 상태")
        # 실행 로그
        log = tk.Frame(stack, bg=BG)
        lbar = tk.Frame(log, bg=BG)
        lbar.pack(fill="x", pady=(0, S(6)))
        for value, text in (("all", "전체"), ("stage", "단계"), ("issue", "경고·오류")):
            ttk.Radiobutton(lbar, text=text, value=value, variable=self.log_filter, style="Seg.TRadiobutton",
                            command=self.refilter_log).pack(side="left", padx=(0, S(4)))
        ttk.Checkbutton(lbar, text="자동 스크롤", variable=self.autoscroll).pack(side="left", padx=(S(12), 0))
        ttk.Button(lbar, text="로그 복사", command=self.copy_log).pack(side="right")
        lf, self.log = scrolled(log, lambda m: tk.Text(
            m, bg=BG, fg=TEXT, relief="flat", bd=0, highlightthickness=0, wrap="none",
            font=(MONO_FAMILY, 9), padx=S(4), pady=S(4), insertbackground=BG, selectbackground=RAISE,
            state="disabled", spacing3=S(1)))
        lf.pack(fill="both", expand=True)
        for tag, color in (("err", MAL), ("warn", SUS), ("stage", ACCENT), ("muted", MUTED)):
            self.log.tag_configure(tag, foreground=color)
        self.log.tag_configure("stage", font=(MONO_FAMILY, 9, "bold"))
        self.log_tab = log
        self.tabs.add(log, "실행 로그")
        self.tabs.select(self.overview)

        foot = tk.Frame(main, bg=BG)
        foot.pack(fill="x", padx=pad, pady=(S(4), S(8)))
        self.admin_label = tk.Label(foot, text="", bg=BG, fg=FAINT, font=(UI_FAMILY, 8))
        self.admin_label.pack(side="right")
        self.folder_label = tk.Label(foot, text="", bg=BG, fg=FAINT, font=(MONO_FAMILY, 8), anchor="w", cursor="hand2")
        self.folder_label.pack(side="left", fill="x", expand=True)
        self.folder_label.bind("<Button-1>", lambda _e: self.open_folder())

    # ── 드롭 영역 ──────────────────────────────────────────────────────────
    def draw_drop(self) -> None:
        c = self.drop
        c.delete("all")
        w, h = max(c.winfo_width(), S(200)), max(c.winfo_height(), S(60))
        raw = self.path.get().strip().strip('"')
        p = Path(raw) if raw else None
        chosen = bool(p and p.is_file())
        c.create_rectangle(1, 1, w - 2, h - 2, outline=ACCENT if chosen else LINE_HI, dash=() if chosen else (4, 3))
        if chosen:
            c.create_text(S(14), S(22), text=p.name, anchor="w", fill=TEXT, font=(UI_FAMILY, 11, "bold"),
                          width=w - S(28))
            c.create_text(S(14), S(46), text=sample_kind(p), anchor="w", fill=MUTED, font=(UI_FAMILY, 9),
                          width=w - S(28))
            c.create_text(S(14), S(66), text="클릭해 다른 파일 선택", anchor="w", fill=FAINT, font=(UI_FAMILY, 8))
        else:
            c.create_text(w / 2, h / 2 - S(9), text=self.drop_hint, fill=MUTED, font=(UI_FAMILY, 10))
            c.create_text(w / 2, h / 2 + S(13), text="EXE · 스크립트 · 문서 · PCAP   ·   Ctrl+O · Ctrl+V",
                          fill=FAINT, font=(UI_FAMILY, 8))

    def on_path_change(self) -> None:
        self.draw_drop()
        self.update_options()
        raw = self.path.get().strip().strip('"')
        p = Path(raw) if raw else None
        if not p or not p.is_file():
            self.file_meta.configure(text="" if not raw else "파일을 찾을 수 없음", fg=SUS if raw else MUTED)
            return
        try:
            size = format_size(p.stat().st_size)
        except OSError:
            size = "?"
        self.file_meta.configure(text=f"{size} · SHA-256 계산 중…", fg=MUTED)

        def digest(target=p):
            h = hashlib.sha256()
            try:
                with target.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                self.events.put(("hash", (str(target), size, h.hexdigest())))
            except OSError as exc:
                self.events.put(("hash", (str(target), size, f"읽기 실패: {exc.strerror or exc}")))
        threading.Thread(target=digest, daemon=True).start()

    # ── 상태 표시 ──────────────────────────────────────────────────────────
    def show_idle(self) -> None:
        self.summary_title.configure(text="분석 대기")
        self.verdict_label.configure(text="")
        self.summary_detail.configure(text="왼쪽에서 파일을 고르고 분석을 시작하거나, 최근 결과를 두 번 눌러 여세요.")
        self.hash_label.configure(text="")
        self.stepper.reset()
        self.progress.configure(value=0)
        t = self.summary_text
        t.clear()
        t.h("사용 순서")
        for n, line in enumerate((
            "분석할 파일을 왼쪽 상자에 끌어다 놓거나 클릭해 고릅니다. 탐색기에서 복사한 파일은 Ctrl+V 로 붙여넣습니다.",
            "관찰 시간과 수집 항목을 고릅니다. 회색 항목은 도구가 설치되지 않아 쓸 수 없는 것입니다.",
            "분석 시작(F5)을 누르면 이 VM 에서 샘플이 실제로 실행됩니다. 관리자 권한 요청을 승인하세요.",
            "관찰 중에는 Esc 로 조기 종료할 수 있습니다. 수집한 데이터로 분석을 마무리합니다.",
            "보고서가 먼저 만들어지고, AI 해석은 끝나는 대로 같은 보고서에 반영됩니다.",
        ), 1):
            t.put(f"{n}\t", "row", "accent")
            t.put(line, "row")
            t.nl("row")
        t.h("주의")
        t.put("분석 전용 VM 에서만 실행하세요. 스냅샷을 먼저 만들어 두고, 분석 후에는 되돌리는 것을 권장합니다.", "para", "muted")
        t.nl("para")

    def tick(self) -> None:
        """1초마다 경과 시간·관찰 잔여 시간을 갱신한다."""
        if self.running and self.started_at:
            elapsed = int(time.monotonic() - self.started_at)
            text = f"경과 {elapsed // 60:02d}:{elapsed % 60:02d}"
            if self.stage == "observe" and self.observe_total:
                done = min(self.observe_total, time.monotonic() - self.observe_started)
                left = max(0, int(self.observe_total - done))
                text = f"관찰 잔여 {left}초   ·   " + text
                self.progress.configure(value=100 * done / self.observe_total)
            self.clock_label.configure(text=text)
        self.root.after(1000, self.tick)

    # ── 도구 점검 ──────────────────────────────────────────────────────────
    def run_preflight(self) -> None:
        self.preflight_button.configure(state="disabled")

        def work():
            info: dict = {}
            try:
                info["admin"] = bool(sys.platform == "win32" and ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                info["admin"] = False
            checks = (
                ("procmon", "core.procmon", "find_procmon"),
                ("tshark", "core.tshark_capture", "find_tshark"),
                ("pe_sieve", "core.pesieve_scanner", "find_pesieve"),
                ("hollows_hunter", "core.hollows_hunter", "find_hollows_hunter"),
                ("capa", "analysis.capa_analyzer", "find_capa"),
                ("fakenet", "core.fakenet_integrator", "find_fakenet"),
                ("winpmem", "core.memory_forensics", "find_winpmem"),
                ("process_hacker", "core.process_tracker", "find_process_hacker"),
            )
            for key, module, func in checks:
                try:
                    mod = __import__(module, fromlist=[func])
                    info[key] = getattr(mod, func)()
                except Exception:
                    info[key] = None
            try:
                from core.config_loader import get_ai_cfg
                cfg = get_ai_cfg()
                info["ai"] = cfg.get("model", "") if cfg.get("api_key") else None
                info["ai_model"] = cfg.get("model", "")
            except Exception:
                info["ai"] = None
            self.events.put(("preflight", info))
        threading.Thread(target=work, daemon=True).start()

    def show_preflight(self, info: dict) -> None:
        self.preflight = info
        self.preflight_button.configure(state="normal")
        for child in self.env_frame.winfo_children():
            child.destroy()
        items = [("관리자", info.get("admin"), "")]
        items += [(name, info.get(key), "") for key, name in (
            ("procmon", "ProcMon"), ("tshark", "tshark"), ("pe_sieve", "pe-sieve"),
            ("hollows_hunter", "hollows-hunter"), ("capa", "CAPA"))]
        items.append(("AI", info.get("ai"), ""))
        for i, (name, found, _extra) in enumerate(items):
            if i:
                tk.Label(self.env_frame, text="·", bg=BG, fg=FAINT, font=(UI_FAMILY, 9)).pack(side="left", padx=S(4))
            label = tk.Label(self.env_frame, text=name, bg=BG, fg=MUTED, font=(UI_FAMILY, 9))
            label.pack(side="left")
            mark, color = ("✔", OK) if found else ("✕", MAL if name in ("관리자", "ProcMon", "tshark") else FAINT)
            tk.Label(self.env_frame, text=f" {mark}", bg=BG, fg=color, font=(UI_FAMILY, 9)).pack(side="left")
            where = info.get("ai_model") if name == "AI" else found
            Tooltip(label, str(where) if found and where else
                    {"관리자": "관리자 권한 아님 — 분석을 시작하면 UAC 승인을 요청합니다",
                     "AI": "API 키 없음 — AI 설정에서 입력하세요"}.get(name, "설치되지 않았거나 경로를 찾지 못했습니다"))
        self.admin_label.configure(
            text="관리자 권한으로 실행 중" if info.get("admin") else "분석을 시작하면 관리자 권한을 요청합니다")
        self.update_options()

    # ── 최근 결과 ──────────────────────────────────────────────────────────
    def refresh_recent(self) -> None:
        def work():
            try:
                self.events.put(("recent", list_recent_results(RESULTS_DIR)))
            except Exception:
                self.events.put(("recent", []))
        threading.Thread(target=work, daemon=True).start()

    def show_recent(self, items: list) -> None:
        self._recent = items
        tree = self.recent_tree
        tree.delete(*tree.get_children())
        if not items:
            tree.insert("", "end", iid="none", text="저장된 결과 없음", values=("",), tags=("muted",))
            return
        for i, item in enumerate(items):
            mark = {"mal": "● ", "sus": "● ", "ok": "● "}.get(item.level, "○ ")
            tree.insert("", "end", iid=str(i), text=mark + item.sample, values=(item.when,),
                        tags=(item.level or "muted",))

    def open_recent(self, _event=None) -> None:
        sel = self.recent_tree.selection()
        if sel and sel[0] != "none" and not self.running:
            item = self._recent[int(sel[0])]
            self.run_failure = None
            self.request_result(item.folder)

    # ── 결과 읽기·표시 ──────────────────────────────────────────────────────
    def choose_result(self) -> None:
        selected = filedialog.askdirectory(title="분석 결과 폴더 선택", initialdir=str(RESULTS_DIR))
        if selected:
            self.run_failure = None
            self.request_result(Path(selected))

    def request_result(self, folder: Path, *, quiet: bool = False) -> None:
        if self.loading:
            # 1차 보고서를 읽는 중에 분석이 끝나면 최종 결과를 다시 읽어야 한다 — 끝난 뒤 이어서 읽는다
            self._reload_pending = (folder, quiet)
            return
        self.loading = True
        if not self.running:
            self.load_button.configure(state="disabled")
            self.start_button.configure(state="disabled")
            self.status.set("저장 결과 읽는 중…")

        def read():
            try:
                self.events.put(("loaded", load_result(folder)))
            except Exception as exc:
                self.events.put(("load_error", f"{type(exc).__name__}: {exc}" if not quiet else ""))
        threading.Thread(target=read, daemon=True).start()

    def display_result(self, result: ResultSummary) -> None:
        self.summary = result
        self.output = result.folder
        self.report = result.html_path
        self.summary_title.configure(text=result.sample)
        color = LEVEL_COLOR.get(result.verdict_level, MUTED)
        verdict = result.verdict_label or "판정 정보 없음"
        if result.score is not None:
            verdict += f"   {result.score}/100"
        self.verdict_label.configure(text=verdict, fg=color)
        self.summary_detail.configure(text=result.subtitle)
        self.hash_label.configure(text=f"SHA-256  {result.sha256}" if result.sha256 else "")
        self.folder_label.configure(text=f"결과 폴더  {result.folder.name}")
        if not self.running:
            self.status.set(f"실행 실패: {self.run_failure} — 저장된 결과 표시" if self.run_failure else result.title)
        self.report_button.configure(state="normal" if self.report else "disabled")
        self.folder_button.configure(state="normal")
        self.fill_summary(result)
        self.fill_processes()
        self.fill_network(result)
        self.fill_files(result)
        self.fill_collection(result)
        if not self.running and result.log_text:
            self.set_log(result.log_text)
        if not self.running:
            self.stepper.reset("done" if result.report_stage == "final" else "pending")
            if result.ai_state == "off":
                self.stepper.set("ai", "skipped")
            elif result.ai_state == "pending":
                self.stepper.set("ai", "active")
            elif result.ai_state == "error":
                self.stepper.set("ai", "failed")
            self.progress.configure(value=100)
            self.clock_label.configure(text="")
        self.tabs.set_text(self.overview, f"요약  {len(result.indicators)}" if result.indicators else "요약")
        self.tabs.set_text(self.network_tab, f"네트워크  {len(result.connections)}" if result.connections else "네트워크")
        self.tabs.set_text(self.files_tab, f"파일·레지스트리  {len(result.dropped) + len(result.registry)}"
                           if (result.dropped or result.registry) else "파일·레지스트리")
        bad = sum(1 for row in result.collection if row[1] in ("fail", "partial"))
        self.tabs.set_text(self.collect_tab, f"수집 상태  ⚠{bad}" if bad else "수집 상태")

    def fill_summary(self, r: ResultSummary) -> None:
        t = self.summary_text
        t.clear()
        if r.report_stage == "preliminary" and r.ai_state == "pending":
            t.put("AI 해석이 진행 중입니다. 끝나면 이 화면과 HTML 보고서가 자동으로 갱신됩니다.", "note")
            t.nl("note")
        if r.sample_active is False:
            t.put("유의미한 행위가 관찰되지 않았습니다 — " + " / ".join(r.inactivity[:4]), "note")
            t.nl("note")

        groups = (("mal", "악성"), ("sus", "의심"), ("info", "정보"))
        t.h("판정 근거", f"악성 {sum(1 for i in r.indicators if i['level'] == 'mal')} · "
                     f"의심 {sum(1 for i in r.indicators if i['level'] == 'sus')} · "
                     f"정보 {sum(1 for i in r.indicators if i['level'] == 'info')}")
        if not r.indicators:
            t.put("판정 근거가 기록되지 않았습니다." if r.verdict_level else
                  "이 결과의 JSON 에는 판정 근거가 없습니다 (이전 버전 보고서). HTML 보고서를 확인하세요.", "para", "muted")
            t.nl("para")
        for level, name in groups:
            for ind in [i for i in r.indicators if i["level"] == level]:
                t.put("●\t", "row", level)
                t.put(f"{ind['cat']}\t", "row", "muted")
                t.put(ind["title"], "row")
                if ind.get("tid"):
                    t.put("   ", "row")
                    tid = ind["tid"]
                    t.link(tid, lambda x=tid: webbrowser.open(
                        "https://attack.mitre.org/techniques/" + x.replace(".", "/") + "/"), "row", "tid")
                t.nl("row")
                if ind.get("ev"):
                    t.put(str(ind["ev"])[:400], "sub")
                    t.nl("sub")

        t.h("AI 해석", {"done": r.ai_model, "pending": "진행 중", "error": "실패", "off": "사용 안 함"}.get(r.ai_state, ""))
        if r.ai_state == "done" and r.ai_summary:
            for title, body in r.ai_summary:
                t.put(title, "bold")
                t.nl()
                t.put(body.strip(), "para")
                t.nl("para")
        elif r.ai_state == "pending":
            t.put("응답을 기다리는 중입니다. 대형 모델은 수 분이 걸릴 수 있습니다 — 아래 근거는 AI 와 무관하게 확정된 관측입니다.",
                  "para", "muted")
            t.nl("para")
        elif r.ai_state == "error":
            t.put(r.ai_note or "AI 해석 실패", "para", "sus")
            t.nl("para")
        else:
            t.put("이번 분석에서는 AI 해석을 사용하지 않았습니다.", "para", "muted")
            t.nl("para")

        t.h("샘플 귀속 IOC", "계보 프로세스가 직접 만든 지표만")
        any_ioc = False
        for label, key in (("도메인", "domains"), ("IP", "ip_addresses"), ("URL", "urls"),
                           ("드롭 파일", "dropped_files"), ("레지스트리", "registry_keys"), ("뮤텍스", "mutexes")):
            values = r.iocs.get(key) or []
            for v in values[:12]:
                any_ioc = True
                t.put(f"{label}\t", "kv", "muted")
                t.put(str(v), "kv", "mono")
                t.nl("kv")
            if len(values) > 12:
                t.put(f"\t… 외 {len(values) - 12}개 — HTML 보고서 IOC 섹션", "kv", "faint")
                t.nl("kv")
        if not any_ioc:
            t.put("샘플에 귀속된 IOC 가 없습니다.", "para", "muted")
            t.nl("para")

        if r.techniques:
            t.h("관측 기법과 근거", f"{len(r.techniques)}건")
            for tech in r.techniques[:40]:
                tid, name, tactic, sources, evidence, tier = tech
                t.link(tid, lambda x=tid: webbrowser.open(
                    "https://attack.mitre.org/techniques/" + x.replace(".", "/") + "/"), "row", "tid")
                t.put(f"\t{name}", "row", "faint" if tier == 3 else "")
                t.put(f"   {tactic}" if tactic else "", "row", "muted")
                t.put(f"   · {sources}" if sources else "", "row", "faint")
                t.nl("row")
                if evidence:
                    t.put(evidence.splitlines()[0][:300], "sub")
                    t.nl("sub")

        if r.warnings:
            t.h("확인할 점", f"{len(r.warnings)}건")
            for w in r.warnings:
                t.put("⚠  " + w, "note")
                t.nl("note")

    def fill_processes(self) -> None:
        tree = self.proc_tree
        tree.delete(*tree.get_children())
        self.proc_detail.clear()
        r = self.summary
        if not r:
            return
        scope = self.proc_scope.get()
        keep = {1} if scope == "lineage" else ({1, 2} if scope == "related" else {0, 1, 2, 3})
        rows = [p for p in r.processes if (p.tier in keep) or (p.tier == 0 and scope != "lineage") or p.is_sample]
        if scope == "lineage" and not any(p.tier == 1 for p in r.processes):
            rows = [p for p in r.processes if p.tier in (0, 1, 2) or p.is_sample]
        pids = {p.pid for p in rows}
        hidden = len(r.processes) - len(rows)
        self.proc_note.configure(text=f"{len(rows)}개 표시 · {hidden}개 숨김" if hidden else f"{len(rows)}개")
        by_parent: dict[int, list] = {}
        for p in rows:
            parent = p.ppid if p.ppid in pids and p.ppid != p.pid else 0
            by_parent.setdefault(parent, []).append(p)

        def add(parent_iid: str, parent_pid: int, depth: int) -> None:
            for p in sorted(by_parent.get(parent_pid, []), key=lambda x: x.pid):
                tier_text = {1: "계보", 2: "의심", 3: "배경"}.get(p.tier, "—")
                tags = ("mal" if p.injected else ("accent" if p.is_sample else
                        {1: "", 2: "sus", 3: "faint"}.get(p.tier, "muted")),)
                if p.is_sample:
                    tags += ("bold",)
                acts = []
                for n, label in ((p.files, "파일"), (p.regs, "레지"), (p.nets, "통신"), (p.dns, "DNS")):
                    if n:
                        acts.append(f"{label} {n}")
                if p.injected:
                    acts.insert(0, "주입 탐지")
                name = p.name + ("  ← 샘플" if p.is_sample else "")
                iid = tree.insert(parent_iid, "end", iid=f"p{p.pid}", text=name, open=depth < 6,
                                  values=(p.pid, tier_text, " · ".join(acts), p.cmdline), tags=tags)
                if depth < 30:
                    add(iid, p.pid, depth + 1)
        add("", 0, 0)
        first = tree.get_children()
        if first:
            tree.selection_set(first[0])

    def show_process(self, _event=None) -> None:
        sel = self.proc_tree.selection()
        r = self.summary
        t = self.proc_detail
        t.clear()
        if not sel or not r:
            return
        pid = int(sel[0][1:])
        p = next((x for x in r.processes if x.pid == pid), None)
        if not p:
            return
        t.put(f"{p.name}", "bold")
        t.put(f"   PID {p.pid} · 부모 {p.ppid}", "muted")
        t.nl()
        if p.exe:
            t.put(p.exe, "mono", "muted")
            t.nl()
        if p.cmdline:
            t.put(p.cmdline, "mono")
            t.nl()
        for title, values in (("파일 쓰기", p.detail.get("files_written")), ("파일 삭제", p.detail.get("files_deleted")),
                              ("레지스트리 쓰기", p.detail.get("reg_written")), ("레지스트리 삭제", p.detail.get("reg_deleted")),
                              ("통신", p.detail.get("tcp_conns")), ("DNS", p.detail.get("dns_queries")),
                              ("자식 프로세스", p.detail.get("children"))):
            if not values:
                continue
            t.h(title, f"{len(values)}건")
            for v in values[:60]:
                t.put(str(v), "mono")
                t.nl()
            if len(values) > 60:
                t.put(f"… 외 {len(values) - 60}건", "faint")
                t.nl()

    def fill_network(self, r: ResultSummary) -> None:
        tree = self.connection_tree
        tree.delete(*tree.get_children())
        for i, row in enumerate(r.connections):
            attribution, process, pid, remote, domain, events, level = row
            tree.insert("", "end", iid=str(i), values=(attribution, process, pid, remote, domain, events),
                        tags=(level,))
        if not r.connections:
            tree.insert("", "end", iid="none", values=("", "관측된 외부 연결 없음", "", "", "", ""), tags=("muted",))
        tree = self.dns_tree
        tree.delete(*tree.get_children())
        for i, row in enumerate(r.dns):
            name, answers, process, state, level = row
            tree.insert("", "end", iid=str(i), values=(name, answers, process, state), tags=(level,))
        if not r.dns:
            tree.insert("", "end", iid="none", values=("관측된 DNS 질의 없음", "", "", ""), tags=("muted",))

    def fill_files(self, r: ResultSummary) -> None:
        tree = self.file_tree
        tree.delete(*tree.get_children())
        for i, (path, size, sha, tier) in enumerate(r.dropped):
            level = {1: "mal", 2: "sus", 3: "faint"}.get(tier, "")
            tree.insert("", "end", iid=str(i), values=(path, size, sha, {1: "계보", 2: "의심", 3: "배경"}.get(tier, "—")),
                        tags=(level,))
        if not r.dropped:
            tree.insert("", "end", iid="none", values=("샘플이 쓴 파일 없음", "", "", ""), tags=("muted",))
        tree = self.registry_tree
        tree.delete(*tree.get_children())
        for i, (op, key, name, value, level) in enumerate(r.registry):
            tree.insert("", "end", iid=str(i), values=(op, key, name, value), tags=(level,))
        if not r.registry:
            tree.insert("", "end", iid="none", values=("", "레지스트리 변경 없음", "", ""), tags=("muted",))

    def fill_collection(self, r: ResultSummary) -> None:
        t = self.collect_text
        t.clear()
        t.h("수집 도구", "각 도구가 실제로 데이터를 남겼는지 기준")
        marks = {"ok": ("●", "ok"), "partial": ("◐", "sus"), "fail": ("✕", "mal"), "off": ("–", "faint")}
        for tool, state, detail in r.collection:
            mark, tag = marks.get(state, ("·", "muted"))
            t.put(f"{mark}\t", "row2", tag)
            t.put(f"{tool}\t", "row2", "bold" if state in ("fail", "partial") else "")
            t.put(detail, "row2", "muted" if state in ("ok", "off") else tag)
            t.nl("row2")
        if r.errors:
            t.h("실행 중 오류", f"{len(r.errors)}건")
            for e in r.errors:
                t.put("✕\t", "row", "mal")
                t.put(e, "row")
                t.nl("row")
        t.h("산출물", str(len(r.artifacts)))
        for name, size, purpose in r.artifacts:
            t.put(f"{purpose}\t", "kv", "muted")
            t.put(name, "kv", "mono")
            t.put(f"   {size}", "kv", "faint")
            t.nl("kv")

    # ── 로그 ───────────────────────────────────────────────────────────────
    @staticmethod
    def classify(line: str) -> str:
        if _LOG_ERR_RE.search(line):
            return "err"
        if _LOG_WARN_RE.search(line):
            return "warn"
        if _LOG_STAGE_RE.search(line):
            return "stage"
        return "muted" if line.startswith("      ") else ""

    def _log_visible(self, kind: str) -> bool:
        mode = self.log_filter.get()
        return mode == "all" or (mode == "stage" and kind in ("stage", "err", "warn")) or (
            mode == "issue" and kind in ("err", "warn"))

    def append_log(self, line: str) -> None:
        kind = self.classify(line)
        self.log_lines.append((line, kind))
        if not self._log_visible(kind):
            return
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n", (kind,) if kind else ())
        if self.autoscroll.get():
            self.log.see("end")
        self.log.configure(state="disabled")

    def set_log(self, text: str) -> None:
        self.log_lines = [(line, self.classify(line)) for line in text.splitlines()]
        self.refilter_log()

    def refilter_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        for line, kind in self.log_lines:
            if self._log_visible(kind):
                self.log.insert("end", line + "\n", (kind,) if kind else ())
        self.log.see("end")
        self.log.configure(state="disabled")

    def copy_log(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(line for line, _k in self.log_lines))
        self.status.set("실행 로그를 클립보드에 복사했습니다.")

    @staticmethod
    def set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ── 입력 ───────────────────────────────────────────────────────────────
    def close(self) -> None:
        if self.running:
            answer = messagebox.askyesnocancel(
                "분석 실행 중",
                "분석이 아직 진행 중입니다.\n\n예: 조기 종료를 요청하고 창을 닫습니다 (분석기는 수집한 데이터로 보고서를 마저 만듭니다).\n"
                "아니요: 창만 닫습니다 (분석은 백그라운드에서 계속됩니다).\n취소: 창을 닫지 않습니다.")
            if answer is None:
                return
            if answer:
                self.write_stop("skip")
        self.root.destroy()

    def install_drop(self) -> None:
        try:
            from tkinterdnd2 import DND_FILES
        except ImportError:
            self.drop_hint = "클릭해 파일을 고르세요"
            self.draw_drop()
            return
        for widget in (self.root, self.drop, self.path_entry):
            try:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self.on_drop)
            except Exception:
                pass

    def on_drop(self, event: tk.Event) -> None:
        if self.running or self.loading:
            return
        paths = self.root.tk.splitlist(event.data)
        if len(paths) != 1:
            messagebox.showerror("파일 선택", "파일 하나만 선택해 주세요.")
            return
        if Path(paths[0]).is_dir():
            self.run_failure = None
            self.request_result(Path(paths[0]))
        else:
            self.path.set(paths[0])

    def paste_file(self, event=None):
        if self.running or self.loading:
            return "break"
        from core.clipboard_files import read_copied_files
        try:
            paths = read_copied_files()
            if not paths:
                text = self.root.clipboard_get().strip()
                paths = [line.strip().strip('"') for line in text.splitlines() if line.strip()]
            if len(paths) != 1:
                raise ValueError("파일 경로 하나만 붙여넣어 주세요.")
            path = Path(paths[0])
            if not path.is_file():
                raise ValueError("복사한 파일을 찾을 수 없습니다. 파일 또는 전체 경로를 복사해 주세요.")
            self.path.set(str(path))
        except (OSError, ValueError, tk.TclError) as exc:
            messagebox.showerror("파일 붙여넣기", str(exc) if not isinstance(exc, tk.TclError) else "탐색기 파일 또는 파일 경로를 복사해 주세요.")
        return "break"

    def choose_file(self) -> None:
        if self.running:
            return
        selected = filedialog.askopenfilename(
            title="분석할 파일 선택",
            filetypes=[("지원하는 분석 파일", " ".join("*" + ext for ext in sorted(SAMPLE_SUFFIXES | PCAP_SUFFIXES))), ("모든 파일", "*.*")],
        )
        if selected:
            self.path.set(selected)

    def update_options(self) -> None:
        is_pcap = Path(self.path.get().strip().strip('"')).suffix.lower() in PCAP_SUFFIXES
        info = self.preflight
        for key, _label, _desc, tool in OPTION_ROWS:
            check = self.checks[key]
            note = self.option_notes[key]
            missing = bool(info) and tool is not None and not info.get(tool)
            if tool == "ai":
                note.configure(text=(info.get("ai_model") or "").split("/")[-1][:20] if info.get("ai") else
                               ("키 없음 — AI 설정" if info else ""), fg=FAINT if info.get("ai") else SUS)
            elif info and tool:
                note.configure(text="설치됨" if info.get(tool) else "없음", fg=FAINT if info.get(tool) else MAL)
            disabled = self.running or (is_pcap and key != "ai") or (missing and key != "ai")
            if missing and key != "ai" and self.options[key].get():
                self._forced_off.add(key)
                self.options[key].set(False)
            elif not missing and key in self._forced_off:
                self._forced_off.discard(key)
                self.options[key].set(True)
            check.configure(state="disabled" if disabled else "normal")
        for b in self.timeout_buttons:
            b.configure(state="disabled" if self.running or is_pcap else "normal")
        self.timeout_entry.configure(state="disabled" if self.running or is_pcap else "normal")

    # ── 실행 ───────────────────────────────────────────────────────────────
    def start(self) -> None:
        if self.running or self.loading:
            return
        path = Path(self.path.get().strip().strip('"')).expanduser()
        if not path.is_file():
            messagebox.showerror("입력 오류", "존재하는 파일을 선택해 주세요.")
            return
        if path.suffix.lower() not in PCAP_SUFFIXES | SAMPLE_SUFFIXES:
            messagebox.showerror("입력 오류", "지원하는 실행 파일·문서(DOC, DOCX, XLS, PDF 등)·스크립트 또는 PCAP을 선택해 주세요.")
            return
        try:
            timeout = int(self.timeout.get())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("입력 오류", "관찰 시간은 양의 정수(초)여야 합니다.")
            return
        is_pcap = path.suffix.lower() in PCAP_SUFFIXES
        missing = [name for key, name in (("procmon", "ProcMon"), ("tshark", "tshark"))
                   if self.preflight and not is_pcap and self.options[key].get() and not self.preflight.get(key)]
        if not is_pcap and not messagebox.askyesno(
            "실행 확인",
            f"선택한 파일을 이 VM 에서 실제로 실행하거나 연결된 앱으로 엽니다.\n\n{path}\n\n"
            + (f"설치되지 않은 도구: {', '.join(missing)} — 해당 수집은 빠집니다.\n\n" if missing else "")
            + "분석을 시작할까요?"
        ):
            return

        self.output = RESULTS_DIR / f"{path.stem}_{datetime.now():%Y%m%d_%H%M%S_%f}"
        self.report = None
        self.summary = None
        self.run_failure = None
        self.stop_level = ""
        self.prelim_loaded = False
        self.stage = ""
        self.observe_total = 0
        self.started_at = time.monotonic()
        self.summary_title.configure(text=path.name)
        self.verdict_label.configure(text="분석 중", fg=ACCENT)
        self.summary_detail.configure(text=f"{sample_kind(path)} · 관찰 {timeout}초")
        self.hash_label.configure(text="")
        self.folder_label.configure(text=f"결과 폴더  {self.output.name}")
        self.stepper.reset()
        self.progress.configure(value=0)
        for tree in (self.proc_tree, self.connection_tree, self.dns_tree, self.file_tree, self.registry_tree):
            tree.delete(*tree.get_children())
        self.summary_text.clear()
        self.summary_text.put("분석이 진행 중입니다. 1차 보고서가 만들어지면 결과가 여기에 표시됩니다.", "para", "muted")
        self.collect_text.clear()
        self.proc_detail.clear()
        self.log_lines = []
        self.refilter_log()
        command = build_command(path, self.output, timeout, **{k: v.get() for k, v in self.options.items()})
        self.running = True
        self.start_button.pack_forget()
        self.stop_button.configure(text="관찰 조기 종료    Esc", state="normal")
        self.stop_button.pack(fill="x")
        for widget in (self.browse, self.load_button, self.report_button, self.ai_settings_button, self.folder_button):
            widget.configure(state="disabled")
        self.update_options()
        self.status.set("분석 프로세스 시작 중…")
        self.tabs.select(self.log_tab)
        self.append_log(f"분석 대상: {path}")
        self.append_log(f"결과 폴더: {self.output}")
        threading.Thread(target=self.run_command, args=(command,), daemon=True).start()

    def write_stop(self, level: str) -> bool:
        if not self.output:
            return False
        try:
            self.output.mkdir(parents=True, exist_ok=True)
            (self.output / STOP_FILE).write_text(level, encoding="utf-8")
            return True
        except OSError:
            return False

    def request_stop(self) -> None:
        if not self.running:
            return
        level = "skip" if self.stop_level or self.stage not in ("", "snap", "collect", "launch", "observe") else "monitor"
        if level == "skip" and not messagebox.askyesno(
                "선택 단계 건너뛰기", "남은 선택 단계(CAPA · VirusTotal · 메모리 포렌식 · AI 해석)를 건너뛰고 보고서를 마무리할까요?"):
            return
        if self.write_stop(level):
            self.stop_level = level
            if level == "monitor":
                self.append_log("[GUI] 관찰 조기 종료 요청 — 수집한 데이터로 분석을 마무리합니다")
                self.stop_button.configure(text="선택 단계 건너뛰기    Esc")
            else:
                self.append_log("[GUI] 선택 단계 건너뛰기 요청")
                self.stop_button.configure(text="종료 요청됨", state="disabled")
        else:
            messagebox.showerror("조기 종료", "결과 폴더에 종료 요청 파일을 쓰지 못했습니다.")

    def run_command(self, command: list[str]) -> None:
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["NO_COLOR"] = "1"
            env["COLUMNS"] = "200"
            assert self.output is not None
            self.output.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
                from core.elevated_runner import run_elevated
                self.events.put(("line", "분석 프로세스의 관리자 권한 요청을 확인해 주세요."))
                code = run_elevated(command, self.output, lambda line: self.events.put(("line", line)))
                self.events.put(("done", code))
                return
            # 출력은 파이프가 아니라 run.log 로 직접 쓴다 — GUI 창을 닫아도 분석기가 끊긴 파이프에
            # 쓰다 죽지 않고 끝까지 보고서를 만든다. GUI 는 승격 실행과 같은 방식으로 파일을 따라 읽는다.
            log_path = self.output / "run.log"
            with log_path.open("wb") as log_file:
                process = subprocess.Popen(command, cwd=ROOT, stdout=log_file, stderr=subprocess.STDOUT, env=env,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.events.put(("line", f"분석 프로세스 PID {process.pid}"))
            code = tail_log(log_path, process.poll, lambda line: self.events.put(("line", line)))
            self.events.put(("done", code))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def on_line(self, line: str) -> None:
        self.append_log(line)
        for key, pattern in _STAGE_RE:
            if pattern.search(line):
                if key != self.stage:
                    self.stage = key
                    self.stepper.advance_to(key)
                    if key != "observe":
                        self.progress.configure(value=0)
                    if key not in ("snap", "collect", "launch", "observe") and self.stop_level == "monitor":
                        pass
                    elif key not in ("snap", "collect", "launch", "observe") and not self.stop_level:
                        self.stop_button.configure(text="선택 단계 건너뛰기    Esc")
                self.status.set(line.strip())
                break
        m = _OBSERVE_RE.search(line)
        if m:
            self.observe_total = int(m.group(1))
            self.observe_started = time.monotonic()
        m = _REMAIN_RE.search(line)
        if m and self.observe_total:
            self.observe_started = time.monotonic() - int(m.group(1))
        if _PRELIM_RE.search(line) and self.output and not self.prelim_loaded:
            self.prelim_loaded = True
            self.request_result(self.output, quiet=True)

    def drain_events(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "line":
                    self.on_line(str(value))
                elif kind == "hash":
                    target, size, digest = value
                    if Path(self.path.get().strip().strip('"')) == Path(target):
                        self.file_meta.configure(text=f"{size} · SHA-256 {digest[:10]}…", fg=MUTED)
                elif kind == "preflight":
                    self.show_preflight(value)
                elif kind == "recent":
                    self.show_recent(value)
                elif kind in ("loaded", "load_error"):
                    self.loading = False
                    if not self.running:
                        self.load_button.configure(state="normal")
                        self.start_button.configure(state="normal")
                    if kind == "loaded":
                        self.display_result(value)
                        if self.running:
                            self.tabs.select(self.overview)
                            self.report_button.configure(state="normal" if self.report else "disabled")
                    elif value:
                        self.status.set(f"결과 읽기 실패: {value}")
                        messagebox.showerror("결과 읽기 실패", str(value))
                    if self._reload_pending:
                        folder, quiet = self._reload_pending
                        self._reload_pending = None
                        self.request_result(folder, quiet=quiet)
                else:
                    self.finish_run(kind, value)
        except queue.Empty:
            pass
        self.root.after(100, self.drain_events)

    def finish_run(self, kind: str, value) -> None:
        self.running = False
        failed = kind != "done" or value != 0
        self.stepper.finish(failed=failed)
        self.progress.configure(value=100)
        self.stop_button.pack_forget()
        self.start_button.pack(fill="x")
        for widget in (self.browse, self.ai_settings_button, self.load_button, self.start_button):
            widget.configure(state="normal")
        self.update_options()
        if self.output and self.output.is_dir():
            self.folder_button.configure(state="normal")
            try:
                (self.output / STOP_FILE).unlink(missing_ok=True)
            except OSError:
                pass
        elapsed = int(time.monotonic() - self.started_at) if self.started_at else 0
        self.clock_label.configure(text=f"총 {elapsed // 60}분 {elapsed % 60}초")
        if failed:
            meaning = EXIT_MEANING.get(value, f"종료 코드 {value}") if kind == "done" else str(value)
            self.run_failure = meaning
            self.status.set(f"분석 실패: {meaning}")
            self.append_log(f"[GUI] 분석 실패: {meaning}")
            self.verdict_label.configure(text="샘플 실행 실패" if value == 2 else "분석 실패", fg=MAL)
        else:
            self.status.set("분석 완료" + (" — 조기 종료 요청 반영" if self.stop_level else ""))
        if self.output and self.output.is_dir():
            self.request_result(self.output)
        self.refresh_recent()

    def open_report(self) -> None:
        if self.report and self.report.is_file():
            try:
                from analyzer import _open_report
                from rich.console import Console
                _open_report(self.report, Console())
            except Exception as exc:
                messagebox.showerror("리포트 열기 실패", str(exc))

    def open_folder(self) -> None:
        if self.output and self.output.is_dir():
            os.startfile(str(self.output))

    # ── AI 설정 ────────────────────────────────────────────────────────────
    def ai_settings(self) -> None:
        from core.config_loader import get_ai_cfg, save_ai_settings
        cfg = get_ai_cfg()
        dialog = tk.Toplevel(self.root)
        dialog.title("AI 해석 설정")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        frame = tk.Frame(dialog, bg=BG)
        frame.pack(fill="both", expand=True, padx=S(20), pady=S(16))
        tk.Label(frame, text="NVIDIA NIM", bg=BG, fg=TEXT, font=(UI_FAMILY, 13, "bold")).pack(anchor="w")
        tk.Label(frame, text="AI 를 켜면 분석 요약(프로세스·파일·네트워크 근거)을 integrate.api.nvidia.com 으로 보냅니다.\n"
                             "샘플·PCAP·메모리 덤프 원본은 보내지 않습니다.",
                 bg=BG, fg=MUTED, font=(UI_FAMILY, 9), justify="left").pack(anchor="w", pady=(S(4), S(10)))
        hline(frame, pady=(0, S(10)))
        tk.Label(frame, text="모델", bg=BG, fg=MUTED, font=(UI_FAMILY, 9, "bold")).pack(anchor="w")
        model = tk.StringVar(value=cfg.get("model", ""))
        model_box = ttk.Combobox(frame, textvariable=model, width=56, font=(MONO_FAMILY, 9))
        model_box.pack(fill="x", pady=(S(3), S(10)))
        tk.Label(frame, text="API 키 — 새 키를 넣으면 저장, 비워 두면 기존 키 유지", bg=BG, fg=MUTED,
                 font=(UI_FAMILY, 9, "bold")).pack(anchor="w")
        key = tk.StringVar()
        ttk.Entry(frame, textvariable=key, show="•", width=58).pack(fill="x", pady=(S(3), S(6)))
        tk.Label(frame, text="저장된 키 있음" if cfg.get("api_key") else "저장된 키 없음", bg=BG,
                 fg=OK if cfg.get("api_key") else SUS, font=(UI_FAMILY, 9)).pack(anchor="w")
        result = tk.Label(frame, text="", bg=BG, fg=MUTED, font=(UI_FAMILY, 9), justify="left", wraplength=S(480))
        result.pack(anchor="w", fill="x", pady=(S(10), 0))
        hline(frame, pady=(S(10), S(10)))
        buttons = tk.Frame(frame, bg=BG)
        buttons.pack(fill="x")

        def test():
            api_key = key.get().strip() or cfg.get("api_key", "")
            wanted = model.get().strip()
            result.configure(text="연결 확인 중… (모델 목록 조회 + 짧은 응답 1회)", fg=MUTED)
            test_button.configure(state="disabled")

            def work():
                from core.ai_analyzer import probe_nvidia
                outcome = probe_nvidia(api_key, wanted)
                dialog.after(0, lambda: show(outcome))
            threading.Thread(target=work, daemon=True).start()

        def show(outcome: dict):
            if not dialog.winfo_exists():
                return
            test_button.configure(state="normal")
            models = outcome.get("models") or []
            if models:
                model_box.configure(values=models)
            result.configure(text=outcome.get("message", ""), fg=OK if outcome.get("ok") else SUS)

        def save():
            if not model.get().strip():
                messagebox.showerror("AI 설정", "모델 이름을 입력해 주세요.", parent=dialog)
                return
            try:
                save_ai_settings(model.get(), key.get() or None)
            except (OSError, ValueError):
                messagebox.showerror("AI 설정", "config.json을 저장할 수 없습니다. 파일 권한과 JSON 형식을 확인하세요.", parent=dialog)
                return
            key.set("")
            dialog.destroy()
            self.status.set("AI 설정 저장 완료 — 다음 분석부터 적용됩니다.")
            self.run_preflight()

        ttk.Button(buttons, text="저장", command=save, style="Accent.TButton").pack(side="right")
        test_button = ttk.Button(buttons, text="연결 확인", command=test)
        test_button.pack(side="right", padx=(0, S(6)))
        dialog.grab_set()


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("GUI는 Windows 분석 VM에서 실행하세요.")
    import argparse
    parser = argparse.ArgumentParser(description="동적 분석 GUI")
    parser.add_argument("--results", type=Path, help="실행 없이 불러올 결과 폴더")
    parser.add_argument("--uac-relaunch", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    enable_dpi_awareness()
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except ImportError:
        root = tk.Tk()
    app = AnalyzerGUI(root)
    if args.results:
        app.request_result(args.results)
    root.mainloop()


if __name__ == "__main__":
    main()
