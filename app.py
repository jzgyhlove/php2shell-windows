#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP2Shell 批量检测工具 — 图形界面（仅被动指纹检测）。"""

from __future__ import annotations

import csv
import json
import os
import queue
import re
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

import exploit_check
import scan_core

APP_NAME = "PHP2Shell 批量检测工具"
APP_VERSION = "1.5.0"
PROJECT_URL = "https://github.com/jzgyhlove/php2shell-windows"
RELEASES_URL = PROJECT_URL + "/releases/latest"
LATEST_RELEASE_API = (
    "https://api.github.com/repos/jzgyhlove/php2shell-windows/releases/latest"
)
SUSPICIOUS = set(scan_core.SUSPICIOUS_STATUSES)


def version_tuple(text: str) -> tuple[int, int, int]:
    numbers = [int(part) for part in re.findall(r"\d+", text or "")[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    return numbers[0], numbers[1], numbers[2]

COLUMNS = (
    ("idx", "#", 54, "center", False),
    ("input", "目标", 310, "w", True),
    ("status", "判定", 110, "w", False),
    ("php_version", "PHP 版本", 100, "w", False),
    ("php_detected", "PHP识别", 92, "w", False),
    ("exploit", "利用确认", 130, "w", False),
    ("http_status", "HTTP", 64, "center", False),
    ("server", "服务器", 130, "w", True),
    ("x_powered_by", "X-Powered-By", 160, "w", True),
    ("elapsed_ms", "耗时(ms)", 84, "e", False),
)

FILTERS: dict[str, set[str] | None] = {
    "全部": None,
    "可疑 (需复核)": {"likely_vulnerable", "branch_only", "php_no_version"},
    "疑似漏洞": {"likely_vulnerable"},
    "分支未知": {"branch_only"},
    "PHP版本未知": {"php_no_version"},
    "已修复": {"patched"},
    "EOL/未知": {"eol_or_unknown"},
    "未发现PHP": {"no_php_version"},
    "无法访问/错误": {"unreachable", "error"},
}

TAG_STYLES: dict[str, tuple[str, str]] = {
    "likely_vulnerable": ("#fee4e2", "#912018"),
    "branch_only": ("#fef0c7", "#93370d"),
    "patched": ("#d1fadf", "#05603a"),
    "eol_or_unknown": ("#e4e7ec", "#344054"),
    "no_php_version": ("#f2f4f7", "#475467"),
    "unreachable": ("#f9fafb", "#98a2b3"),
    "error": ("#fce7f6", "#9e165f"),
}

BG = "#f4f6f9"
FG = "#101828"
MUTED = "#667085"


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def settings_path() -> Path:
    root = os.environ.get("APPDATA") or tempfile.gettempdir()
    return Path(root) / "php2shell-checker" / "settings.json"


def enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            import ctypes

            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def pick_font_family(root: tk.Misc) -> str:
    try:
        families = set(tkfont.families(root))
    except Exception:
        families = set()
    for name in ("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Arial"):
        if name in families:
            return name
    return "TkDefaultFont"


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.family = pick_font_family(root)
        self._queue: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self._stop_event = threading.Event()
        self._rows: list[dict[str, Any]] = []
        self._counts: dict[str, int] = {}
        self._iid_rows: dict[str, dict[str, Any]] = {}
        self._iid = 0
        self._running = False
        self._run_id = 0
        self._total = 0
        self._completed = 0
        self._sort_col: str | None = None
        self._sort_rev = False
        self._poll_job: str | None = None
        self._last_dir = str(Path.home())

        self._build_style()
        self._build_ui()
        self._load_settings()
        self._set_running(False)
        self._update_summary("就绪：粘贴或导入目标后点击“开始检测”")
        self._update_display_count()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<F5>", lambda _e: self._start_scan())
        self.root.bind("<Escape>", lambda _e: self._stop_scan())
        self.root.bind("<Control-o>", lambda _e: self._import_file())
        self.root.bind("<Control-s>", lambda _e: self._export_all())

        self._center_window()

    def _build_style(self) -> None:
        family = self.family
        for name in (
            "TkDefaultFont",
            "TkTextFont",
            "TkMenuFont",
            "TkHeadingFont",
            "TkTooltipFont",
        ):
            try:
                tkfont.nametofont(name).configure(family=family, size=10)
            except Exception:
                pass

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG, foreground=FG, font=(family, 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TLabelframe", background=BG, bordercolor="#d0d5dd", relief="solid")
        style.configure(
            "TLabelframe.Label",
            background=BG,
            foreground="#344054",
            font=(family, 10, "bold"),
        )
        style.configure(
            "Title.TLabel",
            background=BG,
            foreground="#0f172a",
            font=(family, 18, "bold"),
        )
        style.configure(
            "Sub.TLabel",
            background=BG,
            foreground=MUTED,
            font=(family, 9),
        )
        style.configure(
            "Hint.TLabel",
            background=BG,
            foreground=MUTED,
            font=(family, 9),
        )
        style.configure(
            "Count.TLabel",
            background=BG,
            foreground="#344054",
            font=(family, 10, "bold"),
        )
        style.configure(
            "Link.TLabel",
            background=BG,
            foreground="#1570ef",
            font=(family, 9, "underline"),
        )
        style.configure("TButton", padding=(10, 6), font=(family, 10))
        style.configure(
            "Accent.TButton",
            background="#1570ef",
            foreground="#ffffff",
            borderwidth=0,
            focusthickness=0,
            padding=(18, 8),
            font=(family, 10, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#175cd3"), ("disabled", "#b2ccf5")],
            foreground=[("disabled", "#ffffff")],
        )
        style.configure(
            "Stop.TButton",
            background="#f04438",
            foreground="#ffffff",
            borderwidth=0,
            focusthickness=0,
            padding=(14, 8),
            font=(family, 10, "bold"),
        )
        style.map(
            "Stop.TButton",
            background=[("active", "#d92d20"), ("disabled", "#f7b7b2")],
            foreground=[("disabled", "#ffffff")],
        )
        style.configure(
            "Scan.Horizontal.TProgressbar",
            troughcolor="#e4e7ec",
            background="#1570ef",
            bordercolor="#e4e7ec",
            lightcolor="#1570ef",
            darkcolor="#1570ef",
            thickness=10,
        )
        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground=FG,
            rowheight=27,
            borderwidth=0,
            font=(family, 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#eef2f7",
            foreground="#344054",
            font=(family, 10, "bold"),
            padding=(6, 7),
            relief="flat",
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#e2e8f0")],
        )
        style.map(
            "Treeview",
            background=[("selected", "#dbeafe")],
            foreground=[("selected", "#0f172a")],
        )
        style.configure("TCombobox", padding=(6, 5))
        style.configure("TSpinbox", padding=(6, 5))
        style.configure(
            "TCheckbutton",
            background=BG,
            foreground=FG,
            font=(family, 10),
        )
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure(
            "Status.TLabel",
            background=BG,
            foreground=MUTED,
            font=(family, 9),
        )

    def _build_ui(self) -> None:
        self.root.title(f"{APP_NAME} v{APP_VERSION} · CVE-2026-109618 / 109619")
        self.root.configure(background=BG)
        self.root.minsize(1000, 660)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=(16, 14, 16, 10))
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="PHP2Shell 批量检测", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="被动指纹检测 · 仅发送 GET 请求 · 不发送利用流量",
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))
        ttk.Label(
            header,
            text="仅限获得授权的安全测试",
            style="Hint.TLabel",
        ).grid(row=0, column=1, rowspan=2, sticky="e")

        input_box = ttk.LabelFrame(main, text=" 目标列表 ", padding=(10, 8))
        input_box.grid(row=1, column=0, sticky="ew")
        input_box.columnconfigure(0, weight=1)
        self.input_text = tk.Text(
            input_box,
            height=7,
            wrap="none",
            undo=True,
            font=(self.family, 10),
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            padx=8,
            pady=6,
        )
        self.input_text.grid(row=0, column=0, sticky="nsew")
        input_scroll = ttk.Scrollbar(
            input_box, orient="vertical", command=self.input_text.yview
        )
        input_scroll.grid(row=0, column=1, sticky="ns")
        self.input_text.configure(yscrollcommand=input_scroll.set)

        input_buttons = ttk.Frame(input_box)
        input_buttons.grid(row=0, column=2, sticky="n", padx=(10, 0))
        ttk.Button(input_buttons, text="导入文件", command=self._import_file).pack(
            fill="x", pady=(0, 6)
        )
        ttk.Button(input_buttons, text="去重 / 规整", command=self._dedupe_input).pack(
            fill="x", pady=(0, 6)
        )
        ttk.Button(input_buttons, text="清空", command=self._clear_input).pack(fill="x")

        options = ttk.Frame(main)
        options.grid(row=2, column=0, sticky="ew", pady=(10, 6))
        ttk.Label(options, text="并发数").pack(side="left")
        self.workers_var = tk.StringVar(value="30")
        ttk.Spinbox(
            options,
            from_=1,
            to=200,
            width=6,
            textvariable=self.workers_var,
            font=(self.family, 10),
        ).pack(side="left", padx=(6, 18))
        ttk.Label(options, text="超时(秒)").pack(side="left")
        self.timeout_var = tk.StringVar(value="10")
        ttk.Spinbox(
            options,
            from_=1,
            to=120,
            width=6,
            textvariable=self.timeout_var,
            font=(self.family, 10),
        ).pack(side="left", padx=(6, 18))
        ttk.Label(options, text="重试").pack(side="left")
        self.retries_var = tk.StringVar(value="1")
        ttk.Spinbox(
            options,
            from_=0,
            to=5,
            width=5,
            textvariable=self.retries_var,
            font=(self.family, 10),
        ).pack(side="left", padx=(6, 18))
        self.enhanced_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options,
            text="增强识别 PHP (+3请求/站)",
            variable=self.enhanced_var,
        ).pack(side="left")
        self.deep_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options,
            text="深度确认疑似 (+2请求/站)",
            variable=self.deep_var,
        ).pack(side="left", padx=(10, 0))

        self.stop_button = ttk.Button(
            options, text="停止 (Esc)", style="Stop.TButton", command=self._stop_scan
        )
        self.stop_button.pack(side="right")
        self.start_button = ttk.Button(
            options, text="开始检测 (F5)", style="Accent.TButton", command=self._start_scan
        )
        self.start_button.pack(side="right", padx=(0, 8))

        progress_frame = ttk.Frame(main)
        progress_frame.grid(row=3, column=0, sticky="ew", pady=(2, 6))
        progress_frame.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            style="Scan.Horizontal.TProgressbar",
        )
        self.progress.grid(row=0, column=0, sticky="ew")
        self.count_label = ttk.Label(progress_frame, text="0/0", style="Hint.TLabel")
        self.count_label.grid(row=0, column=1, padx=(12, 0))
        self.summary_label = ttk.Label(
            progress_frame, text="就绪", style="Status.TLabel"
        )
        self.summary_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        filter_bar = ttk.Frame(main)
        filter_bar.grid(row=4, column=0, sticky="ew", pady=(4, 6))
        ttk.Label(filter_bar, text="状态筛选").pack(side="left")
        self.filter_var = tk.StringVar(value="全部")
        self.filter_box = ttk.Combobox(
            filter_bar,
            textvariable=self.filter_var,
            values=list(FILTERS.keys()),
            state="readonly",
            width=20,
            font=(self.family, 10),
        )
        self.filter_box.pack(side="left", padx=(6, 16))
        self.filter_box.bind("<<ComboboxSelected>>", lambda _e: self._render_rows())
        self.display_label = ttk.Label(filter_bar, text="", style="Hint.TLabel")
        self.display_label.pack(side="left")
        self.copy_button = ttk.Button(
            filter_bar, text="复制可疑地址", command=self._copy_suspicious
        )
        self.copy_button.pack(side="right")

        tree_box = ttk.Frame(main)
        tree_box.grid(row=5, column=0, sticky="nsew")
        tree_box.columnconfigure(0, weight=1)
        tree_box.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            tree_box,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for key, title, width, anchor, stretch in COLUMNS:
            self.tree.heading(
                key,
                text=title,
                command=lambda c=key: self._sort_by(c),
            )
            self.tree.column(key, width=width, anchor=anchor, stretch=stretch)
        for status, (bg, fg) in TAG_STYLES.items():
            self.tree.tag_configure(status, background=bg, foreground=fg)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_y = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        tree_y.grid(row=0, column=1, sticky="ns")
        tree_x = ttk.Scrollbar(tree_box, orient="horizontal", command=self.tree.xview)
        tree_x.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=tree_y.set, xscrollcommand=tree_x.set)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        self.menu = tk.Menu(self.root, tearoff=0, font=(self.family, 10))
        self.menu.add_command(label="查看详情", command=self._menu_details)
        self.menu.add_command(label="复制地址", command=self._menu_copy)
        self.menu.add_separator()
        self.menu.add_command(
            label="利用确认（当前目标）", command=self._exploit_selected
        )
        self.menu.add_command(label="在浏览器中打开", command=self._menu_open)

        footer = ttk.Frame(main)
        footer.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(footer, text="导出可疑/待复核 (CSV)", command=self._export_suspicious).pack(
            side="left"
        )
        ttk.Button(footer, text="导出全部 (CSV)", command=self._export_all).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(footer, text="导出 JSONL", command=self._export_jsonl).pack(
            side="left", padx=(8, 0)
        )
        self.exploit_button = ttk.Button(
            footer, text="利用确认（全部）", command=self._exploit_all
        )
        self.exploit_button.pack(side="left", padx=(16, 0))
        ttk.Label(
            footer,
            text="判定仅供参考：版本被隐藏时用“增强识别”判断是否为 PHP，仍无法确定补丁版本。",
            style="Hint.TLabel",
        ).pack(side="right")
        ttk.Button(footer, text="检查更新", command=self._check_update).pack(
            side="right", padx=(8, 0)
        )
        link = ttk.Label(footer, text="项目主页", style="Link.TLabel", cursor="hand2")
        link.pack(side="right", padx=(14, 0))
        link.bind("<Button-1>", lambda _event: self._open_url(PROJECT_URL))

    def _center_window(self) -> None:
        self.root.update_idletasks()
        width = max(1240, self.root.winfo_reqwidth() + 30)
        height = max(800, self.root.winfo_reqheight() + 30)
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2 - 20)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        try:
            icon = resource_path("app.ico")
            if os.path.exists(icon):
                self.root.iconbitmap(icon)
        except Exception:
            pass

    def _load_settings(self) -> None:
        try:
            data = json.loads(settings_path().read_text(encoding="utf-8"))
        except Exception:
            return
        self.workers_var.set(str(data.get("workers", 30)))
        self.timeout_var.set(str(data.get("timeout", 10)))
        self.retries_var.set(str(data.get("retries", 1)))
        self.enhanced_var.set(bool(data.get("enhanced", True)))
        self.deep_var.set(bool(data.get("deep", False)))
        last_dir = data.get("last_dir")
        if isinstance(last_dir, str) and os.path.isdir(last_dir):
            self._last_dir = last_dir

    def _save_settings(self) -> None:
        try:
            path = settings_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "workers": self._safe_int(self.workers_var.get(), 30, 1, 200),
                        "timeout": self._safe_int(self.timeout_var.get(), 10, 1, 120),
                        "retries": self._safe_int(self.retries_var.get(), 1, 0, 5),
                        "enhanced": bool(self.enhanced_var.get()),
                        "deep": bool(self.deep_var.get()),
                        "last_dir": self._last_dir,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    @staticmethod
    def _safe_int(value: str, default: int, low: int, high: int) -> int:
        try:
            number = int(str(value).strip())
        except Exception:
            number = default
        return max(low, min(high, number))

    def _center_dialog(self, win: tk.Toplevel) -> None:
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _import_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择目标列表",
            initialdir=self._last_dir,
            filetypes=[
                ("文本 / CSV", "*.txt *.csv *.lst *.list"),
                ("所有文件", "*.*"),
            ],
        )
        if not path:
            return
        text = self._read_text_file(path)
        if text is None:
            return
        self._last_dir = os.path.dirname(path)
        current = self.input_text.get("1.0", "end").strip()
        if current:
            self.input_text.insert("end", "\n" + text)
        else:
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", text)
        count = len(scan_core.normalize_targets(self.input_text.get("1.0", "end")))
        self._update_summary(f"已导入 {os.path.basename(path)}，当前共 {count} 个目标")

    def _read_text_file(self, path: str) -> str | None:
        for encoding in ("utf-8-sig", "gbk", "utf-16", "latin-1"):
            try:
                return Path(path).read_text(encoding=encoding)
            except (UnicodeDecodeError, UnicodeError):
                continue
            except OSError as exc:
                messagebox.showerror("读取失败", f"无法读取文件：\n{exc}")
                return None
        messagebox.showerror("读取失败", "无法识别文件编码，请另存为 UTF-8 后重试。")
        return None

    def _dedupe_input(self) -> None:
        targets = scan_core.normalize_targets(self.input_text.get("1.0", "end"))
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", "\n".join(targets))
        self._update_summary(f"已去重并规整，共 {len(targets)} 个目标")

    def _clear_input(self) -> None:
        self.input_text.delete("1.0", "end")
        self._update_summary("输入已清空")

    def _set_running(self, running: bool) -> None:
        self._running = running
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.copy_button.configure(state="disabled" if running else "normal")

    def _start_scan(self) -> None:
        if self._running:
            return
        targets = scan_core.normalize_targets(self.input_text.get("1.0", "end"))
        if not targets:
            messagebox.showwarning("没有目标", "请先粘贴或导入目标地址（每行一个）。")
            return
        workers = self._safe_int(self.workers_var.get(), 30, 1, 200)
        timeout = self._safe_int(self.timeout_var.get(), 10, 1, 120)
        retries = self._safe_int(self.retries_var.get(), 1, 0, 5)
        enhanced = bool(self.enhanced_var.get())
        deep = bool(self.deep_var.get())
        self.workers_var.set(str(workers))
        self.timeout_var.set(str(timeout))
        self.retries_var.set(str(retries))
        self._save_settings()

        self._rows.clear()
        self._counts.clear()
        self._iid_rows.clear()
        self.tree.delete(*self.tree.get_children())
        self._sort_col = None
        self._sort_rev = False
        self._total = len(targets)
        self._completed = 0
        self._run_id += 1
        run_id = self._run_id
        self._stop_event.clear()
        self.progress.configure(maximum=len(targets), value=0)
        self.count_label.configure(text=f"0/{len(targets)}")
        self._update_summary(f"正在检测 {len(targets)} 个目标…")
        self._update_display_count()
        self._set_running(True)

        thread = threading.Thread(
            target=self._scan_worker,
            args=(run_id, targets, workers, timeout, retries, enhanced, deep),
            daemon=True,
        )
        thread.start()
        self._poll()

    def _scan_worker(
        self,
        run_id: int,
        targets: list[str],
        workers: int,
        timeout: int,
        retries: int,
        enhanced: bool,
        deep: bool,
    ) -> None:
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {}
        try:
            for index, target in enumerate(targets, 1):
                if self._stop_event.is_set():
                    break
                future = executor.submit(
                    scan_core.check_target,
                    target,
                    timeout=timeout,
                    retries=retries,
                    enhanced=enhanced,
                    deep=deep,
                )
                futures[future] = index
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for pending in futures:
                        pending.cancel()
                    break
                row = future.result()
                row["_idx"] = futures[future]
                self._queue.put(("row", run_id, row))
        except Exception as exc:
            self._queue.put(("error", run_id, f"{type(exc).__name__}: {exc}"))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
            self._queue.put(("done", run_id, self._stop_event.is_set()))

    def _poll(self) -> None:
        processed = 0
        while processed < 400:
            try:
                message = self._queue.get_nowait()
            except queue.Empty:
                break
            processed += 1
            kind = message[0]
            if len(message) > 1 and message[1] != self._run_id:
                continue
            if kind == "row":
                self._on_row(message[2])
            elif kind == "done":
                self._on_done(bool(message[2]))
            elif kind == "error":
                self._update_summary(f"检测线程异常：{message[2]}")
        if self._running:
            self._poll_job = self.root.after(120, self._poll)

    def _on_row(self, row: dict[str, Any]) -> None:
        self._rows.append(row)
        self._completed += 1
        status = row.get("status") or "error"
        self._counts[status] = self._counts.get(status, 0) + 1
        self.progress.configure(value=self._completed)
        self.count_label.configure(text=f"{self._completed}/{self._total}")
        self._update_summary()
        if self._match_filter(row):
            self._insert_row(row)
        self._update_display_count()

    def _on_done(self, stopped: bool) -> None:
        self._set_running(False)
        self.progress.configure(value=self._completed)
        if not stopped and self._sort_col is None:
            self._sort_col = "idx"
            self._sort_rev = False
            self._render_rows()
        self._update_summary("已停止（结果已保留）" if stopped else "检测完成")
        self._update_display_count()
        hits = self._counts.get("likely_vulnerable", 0)
        branch = self._counts.get("branch_only", 0)
        php_unknown = self._counts.get("php_no_version", 0)
        if not self._rows:
            return
        if stopped:
            messagebox.showinfo(
                "已停止",
                f"已完成 {self._completed}/{self._total} 个目标。\n\n"
                f"疑似漏洞：{hits}\n分支未知：{branch}\nPHP版本未知：{php_unknown}",
            )
            return
        messagebox.showinfo(
            "检测完成",
            f"共检测 {self._completed} 个目标。\n\n"
            f"疑似漏洞：{hits}\n分支未知：{branch}\nPHP版本未知：{php_unknown}\n\n"
            "可点击“导出可疑 (CSV)”保存以上需复核的目标。",
        )

    def _match_filter(self, row: dict[str, Any]) -> bool:
        wanted = FILTERS.get(self.filter_var.get(), None)
        if wanted is None:
            return True
        return (row.get("status") or "error") in wanted

    def _insert_row(self, row: dict[str, Any]) -> None:
        if self._sort_col is not None:
            return
        self._iid += 1
        iid = f"row{self._iid}"
        status = row.get("status") or "error"
        self._iid_rows[iid] = row
        self.tree.insert(
            "",
            "end",
            iid=iid,
            values=self._row_values(row),
            tags=(status,),
        )

    def _row_values(self, row: dict[str, Any]) -> tuple[Any, ...]:
        detected = row.get("php_detected", "unknown")
        return (
            row.get("_idx", ""),
            row.get("input", ""),
            scan_core.STATUS_LABELS.get(row.get("status", ""), row.get("status", "")),
            row.get("php_version") or "-",
            scan_core.PHP_CONFIDENCE_LABELS.get(detected, detected or "-"),
            row.get("exploit_label") or "未检测",
            row.get("http_status") or "-",
            row.get("server") or "-",
            row.get("x_powered_by") or "-",
            row.get("elapsed_ms") or 0,
        )

    def _sorted_rows(self) -> list[dict[str, Any]]:
        rows = [row for row in self._rows if self._match_filter(row)]
        col = self._sort_col
        if not col:
            return rows

        def key(row: dict[str, Any]) -> Any:
            if col == "idx":
                return int(row.get("_idx") or 0)
            if col == "status":
                return scan_core.STATUS_SEVERITY.get(row.get("status"), 99)
            if col == "http_status":
                return int(row.get("http_status") or 0)
            if col == "elapsed_ms":
                return int(row.get("elapsed_ms") or 0)
            if col == "php_version":
                return scan_core.version_sort_key(row.get("php_version"))
            if col == "exploit":
                return str(row.get("exploit_label") or "未检测")
            return str(row.get(col) or "").lower()

        rows.sort(key=key, reverse=self._sort_rev)
        return rows

    def _render_rows(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._iid_rows.clear()
        for row in self._sorted_rows():
            status = row.get("status") or "error"
            self._iid += 1
            iid = f"row{self._iid}"
            self._iid_rows[iid] = row
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=self._row_values(row),
                tags=(status,),
            )
        self._update_display_count()

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False
        self._render_rows()

    def _update_summary(self, prefix: str | None = None) -> None:
        parts = [prefix] if prefix else []
        if prefix is None:
            parts.append(f"已检测 {self._completed}/{self._total}")
            for key in (
                "likely_vulnerable",
                "branch_only",
                "php_no_version",
                "patched",
                "no_php_version",
                "eol_or_unknown",
                "unreachable",
                "error",
            ):
                count = self._counts.get(key, 0)
                if count:
                    parts.append(f"{scan_core.STATUS_LABELS[key]} {count}")
            if self._total and not self._counts:
                parts.append("等待结果…")
        self.summary_label.configure(text=" · ".join(parts) if parts else "就绪")

    def _update_display_count(self) -> None:
        shown = len(self.tree.get_children())
        self.display_label.configure(text=f"显示 {shown} / {len(self._rows)} 条")

    def _on_tree_double_click(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid and iid in self._iid_rows:
            self._show_details(self._iid_rows[iid])

    def _on_tree_right_click(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _selected_row(self) -> dict[str, Any] | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self._iid_rows.get(selection[0])

    def _menu_details(self) -> None:
        row = self._selected_row()
        if row:
            self._show_details(row)

    def _menu_copy(self) -> None:
        row = self._selected_row()
        if row:
            self._copy_text(row.get("input", ""))
            self._update_summary("地址已复制到剪贴板")

    def _menu_open(self) -> None:
        row = self._selected_row()
        if row and row.get("input"):
            webbrowser.open(row["input"])

    @staticmethod
    def _row_url(row: dict[str, Any]) -> str:
        return str(row.get("target") or row.get("final_url") or row.get("input") or "")

    @staticmethod
    def _is_php_row(row: dict[str, Any]) -> bool:
        return row.get("status") in SUSPICIOUS or row.get("php_detected") in (
            "confirmed",
            "likely",
        )

    def _exploit_selected(self) -> None:
        row = self._selected_row()
        if row is None:
            messagebox.showinfo("利用确认", "请先在列表中选中一个目标。")
            return
        if not self._is_php_row(row):
            messagebox.showinfo(
                "利用确认",
                "只对“疑似/确认 PHP”的目标执行利用确认。",
            )
            return
        self._run_exploit([row])

    def _exploit_all(self) -> None:
        rows = [row for row in self._rows if self._is_php_row(row)]
        if not rows:
            messagebox.showinfo(
                "利用确认",
                "当前结果中没有“疑似/确认 PHP”的目标。",
            )
            return
        self._run_exploit(rows)

    def _run_exploit(self, rows: list[dict[str, Any]]) -> None:
        if self._running:
            messagebox.showinfo("利用确认", "请等待当前检测完成后再进行利用确认。")
            return
        if getattr(self, "_exploit_running", False):
            messagebox.showinfo("利用确认", "已有利用确认任务在运行，请等待完成。")
            return
        targets: list[dict[str, Any]] = []
        for row in rows:
            if not self._is_php_row(row):
                continue
            if not self._row_url(row):
                continue
            targets.append(row)
        if not targets:
            messagebox.showinfo("利用确认", "没有可执行利用确认的目标。")
            return
        if len(targets) == 1:
            prompt = (
                f"即将对以下目标发送 multipart POST 探测：\n\n{self._row_url(targets[0])}\n\n"
            )
        else:
            prompt = f"即将对 {len(targets)} 个疑似/确认 PHP 目标发送 multipart POST 探测。\n\n"
        if not messagebox.askyesno(
            "利用确认",
            prompt
            + "可能造成服务负载、连接中断或被安全设备记录。\n"
            "仅限已获得授权的测试目标。\n\n确定继续？",
            icon="warning",
        ):
            return

        timeout = self._safe_int(self.timeout_var.get(), 10, 1, 120)
        self._exploit_rows = targets
        self._exploit_total = len(targets)
        self._exploit_done = 0
        self._exploit_counts: dict[str, int] = {}
        self._exploit_running = True
        self._exploit_queue: queue.Queue = queue.Queue()
        self.exploit_button.configure(state="disabled")
        self._update_summary(f"正在进行利用确认 0/{self._exploit_total}…")
        threading.Thread(
            target=self._exploit_worker,
            args=(targets, timeout),
            daemon=True,
        ).start()
        self.root.after(200, self._poll_exploit)

    def _exploit_worker(
        self, rows: list[dict[str, Any]], timeout: int
    ) -> None:
        try:
            workers = min(3, len(rows))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(
                        exploit_check.verify_target,
                        self._row_url(row),
                        timeout=float(timeout),
                        stall=1.0,
                    ): row
                    for row in rows
                }
                for future in as_completed(futures):
                    row = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "exploit_status": "error",
                            "exploit_label": "错误",
                            "exploit_detail": f"{type(exc).__name__}: {exc}",
                            "exploit_success": False,
                        }
                    self._exploit_queue.put((row, result))
        finally:
            self._exploit_queue.put(None)

    def _poll_exploit(self) -> None:
        finished = False
        while True:
            try:
                item = self._exploit_queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                finished = True
                break
            row, result = item
            row.update(result)
            label = str(row.get("exploit_label") or "未确认")
            self._exploit_counts[label] = self._exploit_counts.get(label, 0) + 1
            self._exploit_done += 1
            self._refresh_row(row)
            self._update_summary(
                f"利用确认 {self._exploit_done}/{self._exploit_total}…"
            )
        if finished:
            self._exploit_running = False
            self.exploit_button.configure(state="normal")
            self._update_summary()
            self._show_exploit_summary()
            return
        self.root.after(200, self._poll_exploit)

    def _show_exploit_summary(self) -> None:
        if self._exploit_total <= 1:
            row = self._exploit_rows[0]
            messagebox.showinfo(
                "利用确认完成",
                f"{row.get('exploit_label') or '未确认'}\n\n"
                f"{row.get('exploit_detail') or ''}",
            )
            return
        parts = [
            f"{label}：{count}" for label, count in sorted(self._exploit_counts.items())
        ]
        lines = [f"共检测 {self._exploit_total} 个目标。", "", "\n".join(parts)]
        confirmed = [
            self._row_url(row)
            for row in self._exploit_rows
            if row.get("exploit_success")
        ]
        if confirmed:
            lines.extend(
                ["", f"原语确认（{len(confirmed)}）："]
                + [f"  {url}" for url in confirmed[:10]]
            )
            if len(confirmed) > 10:
                lines.append(f"  … 其余 {len(confirmed) - 10} 个见列表")
        messagebox.showinfo("利用确认完成", "\n".join(lines))

    def _refresh_row(self, row: dict[str, Any]) -> None:
        for iid, existing in self._iid_rows.items():
            if existing is row:
                self.tree.item(iid, values=self._row_values(row))
                return

    def _open_url(self, url: str) -> None:
        try:
            webbrowser.open(url)
        except Exception:
            self._copy_text(url)
            messagebox.showinfo("项目主页", f"已复制地址，请手动打开：\n{url}")

    def _check_update(self) -> None:
        self._update_checked: Any = None
        self._update_summary("正在检查最新版本…")
        threading.Thread(target=self._check_update_worker, daemon=True).start()
        self.root.after(200, self._poll_update_check)

    def _check_update_worker(self) -> None:
        try:
            request = urllib.request.Request(
                LATEST_RELEASE_API,
                headers={
                    "User-Agent": f"php2shell-checker/{APP_VERSION}",
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                data = json.loads(response.read().decode("utf-8"))
            tag = str(data.get("tag_name") or "").strip().lstrip("vV")
            url = str(data.get("html_url") or "")
            self._update_checked = (tag, url, None)
        except Exception as exc:
            self._update_checked = ("", "", exc)

    def _poll_update_check(self) -> None:
        result = getattr(self, "_update_checked", None)
        if result is None:
            self.root.after(200, self._poll_update_check)
            return
        self._update_checked = None
        self._on_update_checked(*result)

    def _on_update_checked(
        self, tag: str, url: str, error: Exception | None
    ) -> None:
        if error is not None:
            self._update_summary("检查更新失败，可点击“项目主页”手动查看")
            if messagebox.askyesno(
                "检查更新",
                f"无法获取最新版本：{error}\n\n是否打开项目主页？",
            ):
                self._open_url(PROJECT_URL)
            return
        if not tag:
            self._update_summary("未找到发行版本，可点击“项目主页”查看")
            if messagebox.askyesno(
                "检查更新",
                f"仓库还没有发行版本。\n\n是否打开项目主页？",
            ):
                self._open_url(PROJECT_URL)
            return
        if version_tuple(tag) > version_tuple(APP_VERSION):
            self._update_summary(f"发现新版本 v{tag}")
            if messagebox.askyesno(
                "发现新版本",
                f"当前版本 v{APP_VERSION}，最新版本 v{tag}。\n\n是否打开发行页面下载？",
            ):
                self._open_url(url or RELEASES_URL)
        else:
            self._update_summary(f"已是最新版本 v{APP_VERSION}")
            messagebox.showinfo(
                "检查更新",
                f"当前已是最新版本 v{APP_VERSION}。\n\n项目主页：{PROJECT_URL}",
            )

    def _copy_text(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:
            pass

    def _show_details(self, row: dict[str, Any]) -> None:
        win = tk.Toplevel(self.root)
        win.title("检测详情")
        win.configure(background=BG)
        win.minsize(620, 430)
        win.transient(self.root)

        status = row.get("status", "")
        label = scan_core.STATUS_LABELS.get(status, status)
        detected = row.get("php_detected", "unknown")
        detected_label = scan_core.PHP_CONFIDENCE_LABELS.get(detected, detected)
        lines = [
            f"输入地址：{row.get('input', '')}",
            f"最终地址：{row.get('final_url') or row.get('target', '')}",
            f"判定结果：{label}（{status}）",
            "",
            f"PHP 版本：{row.get('php_version') or '未知'}",
            f"版本来源：{row.get('php_version_source') or '未知'}",
            f"PHP 识别：{detected_label}",
            f"增强探测：{row.get('php_probes', 0)} 个附加请求",
            f"利用确认：{row.get('exploit_label') or '未检测'}",
            f"利用确认详情：{row.get('exploit_detail') or '-'}",
            f"HTTP 状态：{row.get('http_status') or '无响应'}",
            f"耗时：{row.get('elapsed_ms', 0)} ms",
            f"检测时间：{row.get('checked_at', '')}",
            "",
            f"Server：{row.get('server') or '-'}",
            f"X-Powered-By：{row.get('x_powered_by') or '-'}",
        ]
        evidence = row.get("php_evidence") or []
        if evidence:
            lines.append("")
            lines.append("PHP 识别依据：")
            lines.extend(f"  - {item}" for item in evidence)
        redirects = row.get("redirects") or []
        if redirects:
            lines.append("")
            lines.append("重定向：")
            lines.extend(f"  {url}" for url in redirects)
        if row.get("error"):
            lines.append("")
            lines.append(f"错误：{row['error']}")
        lines.append("")
        lines.append("说明：")
        lines.append("  疑似漏洞 = 版本低于该分支的官方修复版本。")
        lines.append("  分支未知 = 仅识别到 PHP 8.4 这类主次版本，补丁级别未知。")
        lines.append("  PHP版本未知 = 确认/疑似为 PHP，但未暴露版本，无法判断补丁级别。")
        lines.append("  未发现PHP = 未发现 PHP 特征（CDN / expose_php=Off 可能漏判）。")
        lines.append("  EOL/未知 = 已停止维护分支或无法映射到修复版本。")
        lines.append("  利用确认 = 发送 php2shell 618 multipart 探测；“原语确认”不等于完整 RCE。")

        text = tk.Text(
            win,
            wrap="word",
            font=(self.family, 10),
            relief="flat",
            padx=14,
            pady=12,
            background="#ffffff",
            foreground=FG,
        )
        text.pack(fill="both", expand=True, padx=(14, 0), pady=(14, 0))
        scroll = ttk.Scrollbar(win, orient="vertical", command=text.yview)
        scroll.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
        text.configure(yscrollcommand=scroll.set)
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

        buttons = ttk.Frame(win, padding=(14, 10))
        buttons.pack(fill="x")
        ttk.Button(
            buttons,
            text="复制地址",
            command=lambda: self._copy_text(row.get("input", "")),
        ).pack(side="left")
        ttk.Button(buttons, text="关闭", command=win.destroy).pack(side="right")

        win.after(10, lambda: self._center_dialog(win))

    def _copy_suspicious(self) -> None:
        rows = sorted(
            [row for row in self._rows if row.get("status") in SUSPICIOUS],
            key=lambda row: int(row.get("_idx") or 0),
        )
        if not rows:
            messagebox.showinfo(
                "没有可疑目标",
                "当前结果中没有“疑似漏洞”“分支未知”或“PHP版本未知”的目标。",
            )
            return
        text = "\n".join(str(row.get("input", "")) for row in rows)
        self._copy_text(text)
        self._update_summary(f"已复制 {len(rows)} 个需复核地址到剪贴板")

    def _default_filename(self, tag: str, suffix: str) -> str:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        return f"php2shell_{tag}_{stamp}.{suffix}"

    def _export_suspicious(self) -> None:
        self._export(SUSPICIOUS, "csv", "可疑", "导出可疑结果")

    def _export_all(self) -> None:
        self._export(None, "csv", "全部", "导出全部结果")

    def _export_jsonl(self) -> None:
        self._export(None, "jsonl", "全部", "导出 JSONL")

    def _export(
        self,
        statuses: set[str] | None,
        fmt: str,
        tag: str,
        title: str,
    ) -> None:
        rows = sorted(self._rows, key=lambda row: int(row.get("_idx") or 0))
        if statuses is not None:
            rows = [row for row in rows if row.get("status") in statuses]
        if not rows:
            messagebox.showinfo("没有数据", "当前没有可导出的结果。")
            return

        path = filedialog.asksaveasfilename(
            title=title,
            initialdir=self._last_dir,
            initialfile=self._default_filename(tag, fmt),
            defaultextension=f".{fmt}",
            filetypes=[("CSV 文件", "*.csv")] if fmt == "csv" else [("JSONL 文件", "*.jsonl")],
        )
        if not path:
            return
        self._last_dir = os.path.dirname(path)

        try:
            if fmt == "csv":
                self._write_csv(path, rows)
            else:
                self._write_jsonl(path, rows)
        except OSError as exc:
            messagebox.showerror("导出失败", f"无法写入文件：\n{exc}")
            return

        self._update_summary(f"已导出 {len(rows)} 条到 {os.path.basename(path)}")
        if messagebox.askyesno(
            "导出成功",
            f"已导出 {len(rows)} 条结果到：\n{path}\n\n是否打开所在文件夹？",
        ):
            try:
                os.startfile(os.path.dirname(path))  # type: ignore[attr-defined]
            except Exception:
                pass

    @staticmethod
    def _write_csv(path: str, rows: list[dict[str, Any]]) -> None:
        headers = [
            "序号",
            "输入地址",
            "最终地址",
            "判定",
            "状态代码",
            "PHP版本",
            "PHP识别",
            "PHP识别依据",
            "利用确认",
            "利用确认详情",
            "版本来源",
            "HTTP状态",
            "服务器",
            "X-Powered-By",
            "重定向",
            "错误",
            "耗时(ms)",
            "检测时间",
        ]
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            for row in rows:
                status = row.get("status", "")
                detected = row.get("php_detected", "unknown")
                writer.writerow(
                    [
                        row.get("_idx", ""),
                        row.get("input", ""),
                        row.get("final_url") or row.get("target", ""),
                        scan_core.STATUS_LABELS.get(status, status),
                        status,
                        row.get("php_version") or "",
                        scan_core.PHP_CONFIDENCE_LABELS.get(detected, detected),
                        "; ".join(row.get("php_evidence") or []),
                        row.get("exploit_label") or "未检测",
                        row.get("exploit_detail") or "",
                        row.get("php_version_source") or "",
                        row.get("http_status") or "",
                        row.get("server") or "",
                        row.get("x_powered_by") or "",
                        " -> ".join(row.get("redirects") or []),
                        row.get("error") or "",
                        row.get("elapsed_ms") or 0,
                        row.get("checked_at") or "",
                    ]
                )

    @staticmethod
    def _write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            for row in rows:
                payload = dict(row)
                payload["status_label"] = scan_core.STATUS_LABELS.get(
                    row.get("status", ""), row.get("status", "")
                )
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _stop_scan(self) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self.stop_button.configure(state="disabled")
        self._update_summary("正在停止，等待进行中的请求超时…")

    def _on_close(self) -> None:
        if self._running:
            if not messagebox.askyesno("正在检测", "检测尚未完成，确定要退出吗？"):
                return
            self._stop_event.set()
        self._save_settings()
        try:
            self.root.destroy()
        except Exception:
            pass


def run_selftest() -> int:
    import http.server

    routes = {
        "/vuln": (200, {"X-Powered-By": "PHP/8.4.20"}, "<html>ok</html>"),
        "/patched": (200, {"X-Powered-By": "PHP/8.4.27"}, "ok"),
        "/branch": (200, {"X-Powered-By": "PHP/8.4"}, "ok"),
        "/none": (200, {"Server": "nginx"}, "hello"),
        "/body": (200, {}, "<meta name='generator' content='PHP/8.3.10'>"),
        "/redirect": (302, {"Location": "/vuln"}, ""),
        "/cookie": (200, {"Set-Cookie": "PHPSESSID=abc123; path=/"}, "hello"),
        "/wp": (200, {}, '<link rel="stylesheet" href="/wp-content/themes/x/a.css">'),
        "/app/": (200, {}, "plain app page"),
        "/app/index.php": (200, {"X-Powered-By": "PHP/8.3.20"}, "app"),
        "/fpm/": (200, {}, "plain fpm page"),
        "/sess": (200, {"Expires": "Thu, 19 Nov 1981 08:52:00 GMT"}, "hello"),
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, status: int, headers: dict[str, str], body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path.startswith("/soft/"):
                self._send(200, {}, "soft 404 page")
                return
            if self.path in ("/d1", "/d1/"):
                self._send(200, {}, "plain d1 page")
                return
            if self.path.startswith("/d1/"):
                if ".php/" in self.path:
                    self._send(200, {"Content-Type": "text/html"}, "d1 app page")
                elif self.path.endswith(".php"):
                    self._send(404, {"Content-Type": "text/html"}, "php route missing")
                elif ".html/" in self.path:
                    self._send(404, {"Content-Type": "text/html"}, "static not found")
                else:
                    self._send(404, {"Content-Type": "text/html"}, "static not found")
                return
            if self.path.startswith("/fpm/"):
                if self.path.endswith(".php"):
                    self._send(404, {"Content-Type": "text/html"}, "File not found.")
                else:
                    self._send(404, {"Content-Type": "text/html"}, "<html>404</html>")
                return
            route = routes.get(self.path)
            if route is None:
                self._send(404, {}, "")
                return
            status, headers, body = route
            self._send(status, headers, body)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length) if length else b""
            match = re.search(rb'name="PHPSESSID"\r\n\r\n([^\r\n]+)', payload)
            self.send_response(200)
            if match:
                session_id = match.group(1).decode("latin-1")
                self.send_header("Set-Cookie", f"PHPSESSID={session_id}; path=/")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    cases = [
        {"path": "/vuln", "status": "likely_vulnerable", "php": "confirmed"},
        {"path": "/patched", "status": "patched", "php": "confirmed"},
        {"path": "/branch", "status": "branch_only", "php": "confirmed"},
        {"path": "/none", "status": "no_php_version", "php": "unlikely"},
        {"path": "/body", "status": "likely_vulnerable", "php": "confirmed"},
        {"path": "/redirect", "status": "likely_vulnerable", "php": "confirmed"},
        {"path": "/cookie", "status": "php_no_version", "php": "confirmed"},
        {"path": "/wp", "status": "php_no_version", "php": "confirmed"},
        {"path": "/app/", "status": "likely_vulnerable", "php": "confirmed"},
        {"path": "/fpm/", "status": "php_no_version", "php": "confirmed"},
        {"path": "/soft/anything", "status": "no_php_version", "php": "unlikely"},
        {"path": "/sess", "status": "php_no_version", "php": "confirmed"},
        {"path": "/d1/", "status": "php_no_version", "php": "likely"},
        {
            "path": "/d1/",
            "status": "php_no_version",
            "php": "confirmed",
            "deep": True,
            "probes": 5,
        },
    ]
    rows = []
    ok = True
    normalized: list[str] = []
    norm_ok = False
    try:
        for case in cases:
            row = scan_core.check_target(
                f"http://127.0.0.1:{port}{case['path']}",
                timeout=5,
                retries=0,
                enhanced=case.get("enhanced", True),
                deep=case.get("deep", False),
            )
            passed = (
                row.get("status") == case["status"]
                and row.get("php_detected") == case["php"]
            )
            if "probes" in case:
                passed = passed and row.get("php_probes") == case["probes"]
            ok = ok and passed
            rows.append(
                {
                    "path": case["path"],
                    "expected": case["status"],
                    "expected_php": case["php"],
                    "pass": passed,
                    "row": row,
                }
            )
        no_enh = scan_core.check_target(
            f"http://127.0.0.1:{port}/app/", timeout=5, retries=0, enhanced=False
        )
        no_enh_ok = (
            no_enh.get("status") == "no_php_version"
            and no_enh.get("php_detected") == "unknown"
        )
        ok = ok and no_enh_ok
        rows.append(
            {
                "path": "/app/ (enhanced=off)",
                "expected": "no_php_version",
                "expected_php": "unknown",
                "pass": no_enh_ok,
                "row": no_enh,
            }
        )
        dead = scan_core.check_target("http://127.0.0.1:1/", timeout=2, retries=0)
        dead_ok = dead.get("status") == "unreachable"
        ok = ok and dead_ok
        rows.append(
            {
                "path": "http://127.0.0.1:1/",
                "expected": "unreachable",
                "pass": dead_ok,
                "row": dead,
            }
        )
        by_path = {r["path"]: r["row"] for r in rows}
        extra = [
            (
                "cookie_evidence",
                any("PHPSESSID" in item for item in by_path["/cookie"]["php_evidence"]),
            ),
            (
                "fpm_evidence",
                any("File not found" in item for item in by_path["/fpm/"]["php_evidence"]),
            ),
            (
                "index_probe_version",
                str(by_path["/app/"]["php_version_source"]).startswith("index.php"),
            ),
            (
                "wp_evidence",
                any("wp-content" in item for item in by_path["/wp"]["php_evidence"]),
            ),
        ]
        for name, passed in extra:
            ok = ok and passed
        rows.append({"path": "extra", "checks": [{"name": n, "pass": p} for n, p in extra]})
        exploit_res = exploit_check.verify_target(
            f"http://127.0.0.1:{port}/", timeout=5, stall=0.2
        )
        exploit_ok = (
            exploit_res.get("exploit_status") == "session_fixation"
            and exploit_res.get("exploit_success") is True
        )
        ok = ok and exploit_ok
        rows.append(
            {
                "path": "exploit",
                "expected": "session_fixation",
                "pass": exploit_ok,
                "row": exploit_res,
            }
        )
        normalized = scan_core.normalize_targets(
            "# comment\nexample.com\nhttps://example.com\nDOMAIN\nb.com,1.2.3.4\n"
        )
        norm_ok = normalized == ["https://example.com", "https://b.com"]
        ok = ok and norm_ok
    finally:
        server.shutdown()
        server.server_close()

    out = os.path.join(tempfile.gettempdir(), "php2shell_selftest.json")
    Path(out).write_text(
        json.dumps(
            {"ok": ok, "normalized": normalized, "norm_ok": norm_ok, "cases": rows},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return run_selftest()
    enable_dpi_awareness()
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
