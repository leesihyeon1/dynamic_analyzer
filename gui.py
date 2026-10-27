"""격리된 Windows 분석 VM에서 사용하는 로컬 실행 화면."""
from __future__ import annotations

import os
import ctypes
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core.result_summary import ResultSummary, load_result
from core.gui_theme import configure_theme, BG, SURFACE, SIDEBAR, TEXT, MUTED


ROOT = Path(__file__).resolve().parent
from core.sample_types import SAMPLE_SUFFIXES

PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}


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


class AnalyzerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("dynamic_analyzer")
        self.root.geometry("1280x820")
        self.root.minsize(1060, 700)
        configure_theme(root)
        self.path = tk.StringVar()
        self.timeout = tk.StringVar(value="60")
        self.status = tk.StringVar(value="파일을 선택한 뒤 분석 시작을 누르세요.")
        self.options = {name: tk.BooleanVar(value=default) for name, default in {
            "procmon": True, "tshark": True, "ph": True, "keylog": True,
            "ai": True, "memdump": False, "fakenet": False,
        }.items()}
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.running = False
        self.loading = False
        self.run_failure: str | None = None
        self.summary: ResultSummary | None = None
        self.output: Path | None = None
        self.report: Path | None = None

        sidebar = ttk.Frame(root, padding=22, width=286, style="Side.TFrame")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="DA / ANALYZER", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(sidebar, text="동적 분석 작업공간", style="SideMuted.TLabel").pack(anchor="w", pady=(3, 18))
        ttk.Label(sidebar, text="분석할 파일", style="Side.TLabel", font=("맑은 고딕", 12, "bold")).pack(anchor="w")
        self.path_entry = ttk.Entry(sidebar, textvariable=self.path)
        self.path_entry.pack(fill="x", pady=(10, 8))
        self.path_entry.bind("<<Paste>>", self.paste_file)
        self.path_entry.bind("<Control-v>", self.paste_file)
        self.path_entry.bind("<Control-V>", self.paste_file)
        self.path_entry.bind("<Shift-Insert>", self.paste_file)
        menu = tk.Menu(self.path_entry, tearoff=False)
        menu.add_command(label="파일 / 경로 붙여넣기", command=self.paste_file)
        self.path_entry.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))
        self.browse = ttk.Button(sidebar, text="파일 찾아보기", command=self.choose_file)
        self.browse.pack(fill="x")
        self.drop_label = ttk.Label(sidebar, text="EXE · 문서 · 스크립트 · PCAP", style="SideMuted.TLabel", wraplength=235)
        self.drop_label.pack(anchor="w", pady=(6, 12))
        ttk.Label(sidebar, text="모니터링 시간 · 초", style="SideMuted.TLabel").pack(anchor="w")
        ttk.Entry(sidebar, textvariable=self.timeout, width=8).pack(fill="x", pady=(4, 12))
        ttk.Label(sidebar, text="수집 옵션", style="Side.TLabel", font=("맑은 고딕", 12, "bold")).pack(anchor="w", pady=(0, 6))
        settings = ttk.Frame(sidebar, style="Side.TFrame")
        settings.pack(fill="x")
        labels = [("procmon", "ProcMon"), ("tshark", "tshark"), ("ph", "프로세스 창"),
                  ("keylog", "TLS 키 로그"), ("memdump", "메모리 덤프"), ("fakenet", "FakeNet-NG"), ("ai", "NVIDIA AI")]
        self.checks = {}
        for index, (name, label) in enumerate(labels):
            check = ttk.Checkbutton(settings, text=label, variable=self.options[name])
            check.grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 10))
            self.checks[name] = check
        self.start_button = ttk.Button(sidebar, text="분석 시작  →", command=self.start, style="Accent.TButton")
        self.start_button.pack(fill="x", pady=(12, 10))
        self.load_button = ttk.Button(sidebar, text="저장 결과 불러오기", command=self.choose_result)
        self.load_button.pack(fill="x")
        self.ai_settings_button = ttk.Button(sidebar, text="AI 연결 설정", command=self.ai_settings)
        self.ai_settings_button.pack(fill="x", pady=(10, 0))
        ttk.Label(sidebar, text="분석 전용 VM에서 실행하세요.", style="SideMuted.TLabel").pack(side="bottom", anchor="w", pady=(12, 0))

        outer = ttk.Frame(root, padding=(28, 24))
        outer.pack(side="left", fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 20))
        ttk.Label(header, text="분석 결과", font=("맑은 고딕", 22, "bold")).pack(side="left")
        self.report_button = ttk.Button(header, text="HTML 보고서 ↗", command=self.open_report, state="disabled")
        self.report_button.pack(side="right")
        self.folder_button = ttk.Button(header, text="결과 폴더", command=self.open_folder, state="disabled")
        self.folder_button.pack(side="right", padx=8)
        actions = ttk.Frame(outer, padding=(0, 0, 0, 18))
        actions.pack(fill="x")
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=140)
        self.progress.pack(side="right")
        ttk.Label(actions, textvariable=self.status, style="Muted.TLabel", wraplength=510).pack(side="left", anchor="w")
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.overview = ttk.Frame(self.tabs, padding=(0, 12))
        self.tabs.add(self.overview, text="결과 요약")
        self.summary_title = ttk.Label(self.overview, text="분석 결과가 여기에 표시됩니다.", font=("맑은 고딕", 17, "bold"), wraplength=700)
        self.summary_title.pack(anchor="w")
        self.summary_detail = ttk.Label(self.overview, text="새 분석을 시작하거나, 왼쪽에서 저장 결과를 불러오세요.", style="Muted.TLabel")
        self.summary_detail.pack(anchor="w", pady=(8, 24))
        self.overview.bind("<Configure>", lambda e: (self.summary_title.configure(wraplength=max(350, e.width-20)), self.summary_detail.configure(wraplength=max(350, e.width-20))))
        cards = ttk.Frame(self.overview)
        cards.pack(fill="x")
        self.metric_labels = {}
        for index, name in enumerate(("ATT&CK 후보", "ProcMon 이벤트", "네트워크 패킷", "관찰 IP")):
            cards.columnconfigure(index, weight=1, uniform="metric")
            card = ttk.Frame(cards, style="Card.TFrame", padding=(16, 18))
            card.grid(row=0, column=index, sticky="ew", padx=(0, 8 if index < 3 else 0))
            ttk.Label(card, text=name, style="Card.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="—", style="Value.TLabel")
            value.pack(anchor="w")
            self.metric_labels[name] = value
        ttk.Label(self.overview, text="수집 상태와 기법별 근거를 함께 확인하세요.", style="Muted.TLabel").pack(anchor="w", pady=(12, 24))
        ttk.Label(self.overview, text="확인할 내용", font=("맑은 고딕", 12, "bold")).pack(anchor="w", pady=(0, 10))
        self.notices = scrolledtext.ScrolledText(self.overview, height=7, wrap="word", state="disabled",
                                               bg="#26271f", fg="#eed9a4", relief="flat", padx=18, pady=16,
                                               font=("맑은 고딕", 11), spacing1=3, spacing3=6)
        self.notices.pack(fill="both", expand=True)
        self.collection_tree = self.make_table("수집 상태", ("도구", "상태", "확인된 내용"), (180, 160, 600))
        self.technique_tree = self.make_table("기법 근거", ("ID", "기법 후보", "근거 출처"), (120, 440, 360), detail=True)
        self.technique_tree.bind("<<TreeviewSelect>>", self.show_evidence)
        self.connection_tree = self.make_table("프로세스 연결", ("프로세스", "PID", "원격 주소", "샘플과의 관계"), (260, 100, 340, 200))
        self.artifact_tree = self.make_table("산출물", ("파일", "크기", "용도"), (510, 150, 250))
        self.log_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.log_tab, text="실행 로그")
        self.log = scrolledtext.ScrolledText(self.log_tab, height=12, state="disabled", wrap="word",
                                             bg=SURFACE, fg=TEXT, insertbackground="white", relief="flat",
                                             font=("Consolas", 11), padx=18, pady=16, spacing3=3)
        self.log.pack(fill="both", expand=True)

        self.install_drop()
        self.path.trace_add("write", lambda *_: self.update_options())
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self.drain_events)

    def ai_settings(self) -> None:
        from core.config_loader import get_ai_cfg, save_ai_settings
        cfg = get_ai_cfg()
        dialog = tk.Toplevel(self.root)
        dialog.title("NVIDIA AI 설정")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="NVIDIA NIM API", font=("맑은 고딕", 14, "bold")).pack(anchor="w")
        ttk.Label(frame, text="AI를 켜면 분석 요약을 integrate.api.nvidia.com으로 전송합니다.\nEXE·PCAP·메모리 덤프 원본은 전송하지 않습니다.").pack(anchor="w", pady=10)
        ttk.Label(frame, text="모델").pack(anchor="w")
        model = tk.StringVar(value=cfg.get("model", ""))
        ttk.Entry(frame, textvariable=model, width=58).pack(fill="x", pady=(3, 12))
        ttk.Label(frame, text="API 키 (새 키를 입력하면 저장, 비워두면 기존 키 유지)").pack(anchor="w")
        key = tk.StringVar()
        ttk.Entry(frame, textvariable=key, show="•", width=58).pack(fill="x", pady=(3, 8))
        state = "사용할 API 키 있음" if cfg.get("api_key") else "API 키 미설정"
        ttk.Label(frame, text=state).pack(anchor="w")
        ttk.Label(frame, text="입력한 키와 모델은 config.json의 ai 항목에 저장됩니다.\nconfig.json의 값을 우선 사용하고, 빈 값만 NVIDIA 환경변수로 보완합니다.").pack(anchor="w", pady=10)
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
            self.status.set("NVIDIA AI 설정 저장 완료 — 다음 분석부터 적용됩니다.")
        ttk.Button(frame, text="저장", command=save, style="Accent.TButton").pack(side="right")
        dialog.grab_set()

    def make_table(self, title: str, columns: tuple, widths: tuple, detail: bool = False) -> ttk.Treeview:
        frame = ttk.Frame(self.tabs, padding=(0, 10))
        self.tabs.add(frame, text=title)
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=7, selectmode="browse")
        for column, width in zip(columns, widths):
            tree.heading(column, text=column)
            tree.column(column, width=width, minwidth=70)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.tag_configure("alternate", background="#18283f")
        if detail:
            ttk.Label(frame, text="항목을 선택하면 아래에서 원문 근거를 확인할 수 있습니다.", style="Muted.TLabel").pack(anchor="w", pady=(18, 8))
            self.evidence = scrolledtext.ScrolledText(frame, height=6, state="disabled", wrap="word", font=("맑은 고딕", 11), bg=SURFACE, fg=TEXT, relief="flat", padx=16, pady=12, spacing3=4)
            self.evidence.pack(fill="x")
        return tree

    @staticmethod
    def set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def show_evidence(self, _event=None) -> None:
        selection = self.technique_tree.selection()
        if selection and self.summary:
            self.set_text(self.evidence, self.summary.techniques[int(selection[0])][3] or "저장된 근거 없음")

    def choose_result(self) -> None:
        selected = filedialog.askdirectory(title="분석 결과 폴더 선택")
        if selected:
            self.run_failure = None
            self.request_result(Path(selected))

    def request_result(self, folder: Path) -> None:
        if self.running or self.loading:
            return
        self.loading = True
        self.load_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.status.set("저장 결과 읽는 중...")
        self.progress.start(12)
        def read():
            try:
                self.events.put(("loaded", load_result(folder)))
            except Exception as exc:
                self.events.put(("load_error", str(exc)))
        threading.Thread(target=read, daemon=True).start()

    def display_result(self, result: ResultSummary) -> None:
        self.summary = result
        self.output = result.folder
        self.report = result.html_path
        self.summary_title.configure(text=f"{result.sample}  ·  {result.title}")
        self.summary_detail.configure(text=result.subtitle)
        self.status.set(f"실행 실패: {self.run_failure} · 저장된 결과 표시" if self.run_failure else result.title)
        for name, label in self.metric_labels.items():
            label.configure(text=result.metrics.get(name, "—"))
        self.notices.configure(bg="#26271f" if result.warnings else SURFACE,
                               fg="#eed9a4" if result.warnings else TEXT)
        self.set_text(self.notices, "\n\n".join(f"• {w}" for w in result.warnings) or "수집 경고가 기록되지 않았습니다. 상세 근거를 검토하세요.")
        for tree, rows in ((self.collection_tree, result.collection), (self.technique_tree, [row[:3] for row in result.techniques]),
                           (self.connection_tree, result.connections), (self.artifact_tree, result.artifacts)):
            tree.delete(*tree.get_children())
            for index, row in enumerate(rows):
                tree.insert("", "end", iid=str(index), values=row, tags=("alternate",) if index % 2 else ())
        self.set_text(self.evidence, "기법 후보를 선택하세요.")
        self.set_text(self.log, result.log_text)
        self.report_button.configure(state="normal" if self.report else "disabled")
        self.folder_button.configure(state="normal")
        self.tabs.select(self.overview)

    def close(self) -> None:
        if self.running:
            messagebox.showinfo("분석 실행 중", "분석이 끝난 뒤 창을 닫아 주세요.")
            return
        self.root.destroy()

    def install_drop(self) -> None:
        try:
            from tkinterdnd2 import DND_FILES
        except ImportError:
            self.drop_label.configure(text="드롭 기능 설치 필요: pip install tkinterdnd2\n파일 찾아보기 / Ctrl+V 사용 가능")
            return
        for widget in (self.root, self.drop_label, self.path_entry):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self.on_drop)
        self.drop_label.configure(text="실행 파일, 문서, 스크립트 또는 PCAP을 선택하거나 끌어다 놓으세요.")

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
        selected = filedialog.askopenfilename(
            title="분석할 파일 선택",
            filetypes=[("지원하는 분석 파일", " ".join("*" + ext for ext in sorted(SAMPLE_SUFFIXES | PCAP_SUFFIXES))), ("모든 파일", "*.*")],
        )
        if selected:
            self.path.set(selected)

    def update_options(self) -> None:
        is_pcap = Path(self.path.get()).suffix.lower() in PCAP_SUFFIXES
        for name, check in self.checks.items():
            check.configure(state="disabled" if self.running or (is_pcap and name != "ai") else "normal")

    def append_log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

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
            messagebox.showerror("입력 오류", "모니터링 시간은 양의 정수여야 합니다.")
            return
        if path.suffix.lower() not in PCAP_SUFFIXES and not messagebox.askyesno(
            "실행 확인", f"선택한 파일을 현재 VM에서 실제로 실행하거나 연결된 앱으로 엽니다.\n\n{path}\n\n분석을 시작할까요?"
        ):
            return

        self.output = ROOT / "results" / f"{path.stem}_{datetime.now():%Y%m%d_%H%M%S_%f}"
        self.report = None
        self.summary = None
        self.run_failure = None
        self.summary_title.configure(text=f"{path.name} · 분석 진행 중")
        self.summary_detail.configure(text="분석이 끝나면 수집 상태와 결과가 표시됩니다.")
        for label in self.metric_labels.values():
            label.configure(text="—")
        for tree in (self.collection_tree, self.technique_tree, self.connection_tree, self.artifact_tree):
            tree.delete(*tree.get_children())
        self.set_text(self.notices, "분석 진행 중입니다. 실행 로그에서 현재 단계를 확인하세요.")
        self.notices.configure(bg=SURFACE, fg=MUTED)
        self.set_text(self.evidence, "")
        self.set_text(self.log, "")
        command = build_command(path, self.output, timeout, **{k: v.get() for k, v in self.options.items()})
        self.running = True
        self.start_button.configure(state="disabled")
        self.browse.configure(state="disabled")
        self.load_button.configure(state="disabled")
        self.report_button.configure(state="disabled")
        self.ai_settings_button.configure(state="disabled")
        self.folder_button.configure(state="disabled")
        self.update_options()
        self.status.set("분석 실행 중...")
        self.progress.start(12)
        self.tabs.select(self.log_tab)
        self.append_log(f"분석 대상: {path}")
        self.append_log(f"결과 폴더: {self.output}")
        threading.Thread(target=self.run_command, args=(command,), daemon=True).start()

    def run_command(self, command: list[str]) -> None:
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["NO_COLOR"] = "1"
            assert self.output is not None
            self.output.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
                from core.elevated_runner import run_elevated
                self.events.put(("line", "분석 프로세스의 관리자 권한 요청을 확인해 주세요."))
                code = run_elevated(command, self.output, lambda line: self.events.put(("line", line)))
                self.events.put(("done", code))
                return
            with (self.output / "run.log").open("w", encoding="utf-8") as log_file, subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                  errors="replace", bufsize=1, env=env) as process:
                assert process.stdout is not None
                for line in process.stdout:
                    log_file.write(line)
                    log_file.flush()
                    self.events.put(("line", line.rstrip("\r\n")))
                code = process.wait()
            self.events.put(("done", code))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def drain_events(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "line":
                    self.append_log(str(value))
                    if re.search(r"\[[1-6]/6\]|\[분석\]|결과 저장 중", str(value)):
                        self.status.set(str(value).strip())
                elif kind in ("loaded", "load_error"):
                    self.loading = False
                    self.progress.stop()
                    self.load_button.configure(state="normal")
                    self.start_button.configure(state="normal")
                    if kind == "loaded":
                        self.display_result(value)
                    else:
                        self.status.set(f"결과 읽기 실패: {value}")
                        messagebox.showerror("결과 읽기 실패", str(value))
                else:
                    self.running = False
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    self.browse.configure(state="normal")
                    self.ai_settings_button.configure(state="normal")
                    self.load_button.configure(state="normal")
                    self.update_options()
                    if self.output and self.output.is_dir():
                        self.folder_button.configure(state="normal")
                    if kind != "done" or value != 0:
                        self.run_failure = str(value)
                        self.status.set(f"분석 실패: {value}")
                        self.append_log(f"분석 실패: {value}")
                    if self.output and self.output.is_dir():
                        self.request_result(self.output)
        except queue.Empty:
            pass
        self.root.after(100, self.drain_events)

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


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("GUI는 Windows 분석 VM에서 실행하세요.")
    import argparse
    parser = argparse.ArgumentParser(description="동적 분석 GUI")
    parser.add_argument("--results", type=Path, help="실행 없이 불러올 결과 폴더")
    parser.add_argument("--uac-relaunch", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
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
