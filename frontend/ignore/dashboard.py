import threading
import queue
import datetime
import collections
import tkinter as tk
import requests
import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import styles
from components import MetricCard, PerformanceInfo, MitigationTable, QuarantinePanel

API       = "http://127.0.0.1:5000"
POLL_MS   = 2000
DRAIN_MS  = 500
GRAPH_PTS = 30


def _get_scroll_canvas(scroll_frame):
    """Robustly find the internal tk.Canvas inside a CTkScrollableFrame."""
    # Try known attribute names across CTk versions
    for attr in ("_parent_canvas", "_canvas", "canvas"):
        c = getattr(scroll_frame, attr, None)
        if c is not None:
            return c
    # Fallback: walk children for the first tk.Canvas
    for child in scroll_frame.winfo_children():
        if isinstance(child, tk.Canvas):
            return child
    return None


class _CalendarPicker(ctk.CTkFrame):
    """Minimal month-grid calendar built from pure tkinter — no extra deps."""

    DAYS   = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"]
    MONTHS = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]

    def __init__(self, parent, initial: datetime.date, mode: str, command):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, fg_color=theme["card"], corner_radius=8)
        self._command = command
        self._mode    = mode
        self._theme   = theme
        self._viewing = datetime.date(initial.year, initial.month, 1)
        self._selected: datetime.date | None = initial
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self._theme
        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", padx=6, pady=(6, 2))
        ctk.CTkButton(nav, text="‹", width=28, height=24, font=("Arial", 14),
                      fg_color="transparent", text_color=theme["text"],
                      hover_color=theme["border"],
                      command=self._prev_month).pack(side="left")
        lbl = f"{self.MONTHS[self._viewing.month-1]} {self._viewing.year}"
        ctk.CTkLabel(nav, text=lbl, font=("Arial", 12, "bold"),
                     text_color=theme["text"]).pack(side="left", expand=True)
        ctk.CTkButton(nav, text="›", width=28, height=24, font=("Arial", 14),
                      fg_color="transparent", text_color=theme["text"],
                      hover_color=theme["border"],
                      command=self._next_month).pack(side="right")

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(padx=6, pady=(0, 6))
        for col, d in enumerate(self.DAYS):
            ctk.CTkLabel(grid, text=d, width=32, font=("Arial", 10, "bold"),
                         text_color=theme["subtext"]).grid(row=0, column=col, pady=(0, 2))

        import calendar
        cal   = calendar.monthcalendar(self._viewing.year, self._viewing.month)
        today = datetime.date.today()
        for row_i, week in enumerate(cal):
            for col_i, day in enumerate(week):
                if day == 0:
                    ctk.CTkFrame(grid, width=32, height=28,
                                 fg_color="transparent").grid(row=row_i+1, column=col_i)
                    continue
                d = datetime.date(self._viewing.year, self._viewing.month, day)
                is_sel   = (d == self._selected)
                is_today = (d == today)
                is_fut   = (d > today)
                if is_sel:
                    bg, fg = "#2563eb", "#ffffff"
                elif is_today:
                    bg, fg = theme["border"], theme["text"]
                elif is_fut:
                    bg, fg = "transparent", theme["subtext"]
                else:
                    bg, fg = "transparent", theme["text"]
                btn = ctk.CTkButton(
                    grid, text=str(day), width=32, height=28,
                    font=("Arial", 11), fg_color=bg, text_color=fg,
                    hover_color=theme["border"], corner_radius=6,
                    state="disabled" if is_fut else "normal",
                    command=(lambda _d=d: self._pick(_d)) if not is_fut else None)
                btn.grid(row=row_i+1, column=col_i, padx=1, pady=1)

    def _prev_month(self):
        y, m = self._viewing.year, self._viewing.month
        m -= 1
        if m == 0: y, m = y-1, 12
        self._viewing = datetime.date(y, m, 1)
        self._build()

    def _next_month(self):
        y, m = self._viewing.year, self._viewing.month
        m += 1
        if m == 13: y, m = y+1, 1
        nxt = datetime.date(y, m, 1)
        if nxt <= datetime.date.today():
            self._viewing = nxt
            self._build()

    def _pick(self, d: datetime.date):
        self._selected = d
        self._build()
        self._command(d)

    def get(self) -> datetime.date | None:
        return self._selected


class ReportDialog(ctk.CTkToplevel):
    def __init__(self, parent, mode="Dark"):
        super().__init__(parent)
        self.title("Generate Report")
        self.geometry("560x420")
        self.resizable(False, False)
        theme = styles.THEME_CONFIG[mode]
        self.configure(fg_color=theme["bg"])
        self._result = None

        today    = datetime.date.today()
        week_ago = today - datetime.timedelta(days=7)

        ctk.CTkLabel(self, text="Generate Report", font=("Arial", 15, "bold"),
                     text_color=theme["text"]).pack(pady=(16, 8))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20)
        body.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(body, text="Start Date", font=("Arial", 11, "bold"),
                     text_color=theme["subtext"]).grid(row=0, column=0, pady=(0, 4))
        ctk.CTkLabel(body, text="End Date", font=("Arial", 11, "bold"),
                     text_color=theme["subtext"]).grid(row=0, column=1, pady=(0, 4))

        self._start_var = tk.StringVar(value=str(week_ago))
        self._end_var   = tk.StringVar(value=str(today))

        # Display labels showing current selection
        self._start_disp = ctk.CTkLabel(body, textvariable=self._start_var,
                                        font=("Arial", 13, "bold"),
                                        text_color=theme["text"])
        self._start_disp.grid(row=1, column=0, pady=(0, 6))
        self._end_disp = ctk.CTkLabel(body, textvariable=self._end_var,
                                      font=("Arial", 13, "bold"),
                                      text_color=theme["text"])
        self._end_disp.grid(row=1, column=1, pady=(0, 6))

        self._cal_start = _CalendarPicker(body, week_ago, mode,
                                          command=lambda d: self._start_var.set(str(d)))
        self._cal_start.grid(row=2, column=0, padx=8, sticky="n")

        self._cal_end = _CalendarPicker(body, today, mode,
                                        command=lambda d: self._end_var.set(str(d)))
        self._cal_end.grid(row=2, column=1, padx=8, sticky="n")

        self._err = ctk.CTkLabel(self, text="", text_color="#ef4444",
                                 font=("Arial", 10))
        self._err.pack()
        ctk.CTkButton(self, text="Generate", width=120, command=self._submit).pack(pady=(6, 16))

    def _submit(self):
        today = datetime.date.today()
        try:
            sd = datetime.date.fromisoformat(self._start_var.get())
            ed = datetime.date.fromisoformat(self._end_var.get())
        except ValueError:
            self._err.configure(text="Invalid date selection.")
            return
        if ed < sd:
            self._err.configure(text="End date must be on or after start date.")
            return
        if ed > today:
            self._err.configure(text="End date cannot be in the future.")
            return
        self._result = (str(sd), str(ed))
        self.destroy()

    def get_result(self):
        self.wait_window()
        return self._result


class DDoSDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DDoS Mitigation System Dashboard")
        # Start maximised but still resizable
        self.state("zoomed") if self._is_windows() else self.attributes("-zoomed", True)
        self.minsize(1100, 700)
        self.current_mode = "Dark"
        ctk.set_appearance_mode(self.current_mode)

        self._prev_total   = 0
        self._prev_mal     = 0
        self._prev_normal  = 0

        self._live_times   = collections.deque(maxlen=GRAPH_PTS)
        self._live_in      = collections.deque(maxlen=GRAPH_PTS)
        self._live_blocked = collections.deque(maxlen=GRAPH_PTS)
        self._live_fwd     = collections.deque(maxlen=GRAPH_PTS)
        self._graph_range  = "Live"

        self._ui_queue: queue.Queue = queue.Queue()
        self._if_threshold = 0.0
        self._scroll_canvas = None   # resolved after UI build

        self.setup_ui()
        self._start_pollers()
        self._schedule_drain()

    def _is_windows(self):
        return self.tk.call("tk", "windowingsystem") == "win32"

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def setup_ui(self):
        for w in self.winfo_children():
            w.destroy()

        theme    = styles.THEME_CONFIG[self.current_mode]
        mode_idx = 0 if self.current_mode == "Light" else 1
        self.configure(fg_color=theme["bg"])

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(20, 10))

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="A-DDoS", font=("Arial", 26, "bold"),
                     text_color=theme["text"]).pack(anchor="w")
        ctk.CTkLabel(title_box, text="Threat detection & mitigation System",
                     font=("Arial", 12),
                     text_color=theme["subtext"]).pack(anchor="w")

        self._report_btn = ctk.CTkButton(
            header, text="Generate Report", width=130,
            command=self._on_generate_report,
            fg_color=theme["card"], text_color=theme["text"],
            border_width=1, border_color=theme["border"])
        self._report_btn.pack(side="right", padx=(6, 0))

        self._mode_btn = ctk.CTkButton(
            header,
            text="Light Mode" if self.current_mode == "Dark" else "Dark Mode",
            width=120, command=self._toggle_mode,
            fg_color=theme["card"], text_color=theme["text"],
            border_width=1, border_color=theme["border"])
        self._mode_btn.pack(side="right", padx=10)

        active_bg = "#1b3a2a" if self.current_mode == "Dark" else "#ecfdf5"
        ctk.CTkButton(header, text="● System Active", fg_color=active_bg,
                      text_color=styles.SUCCESS_GREEN[mode_idx],
                      corner_radius=20, hover=False).pack(side="right")

        # Scrollable area
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True, padx=20)

        # Row 1 — Metric cards
        m_frame = ctk.CTkFrame(self._scroll, fg_color="transparent")
        m_frame.pack(fill="x", pady=10)
        m_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._card_total = MetricCard(
            m_frame, "Total Packets Detected", styles.ACCENT_BLUE, self.current_mode)
        self._card_total.grid(row=0, column=0, padx=8, sticky="nsew")

        self._card_mal = MetricCard(
            m_frame, "Malicious Packets Dropped", styles.DANGER_RED, self.current_mode)
        self._card_mal.grid(row=0, column=1, padx=8, sticky="nsew")

        self._card_norm = MetricCard(
            m_frame, "Normal Traffic", styles.SUCCESS_GREEN, self.current_mode)
        self._card_norm.grid(row=0, column=2, padx=8, sticky="nsew")

        self._card_threats = MetricCard(
            m_frame, "Active Threats", styles.WARNING_ORANGE, self.current_mode)
        self._card_threats.grid(row=0, column=3, padx=8, sticky="nsew")

        # Row 2 — Graph
        self._setup_graph(self._scroll, theme, mode_idx)

        # Row 3 — Performance
        p_frame = ctk.CTkFrame(self._scroll, fg_color="transparent")
        p_frame.pack(fill="x", pady=(10, 20))
        p_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._perf_if = PerformanceInfo(
            p_frame, "Detection Model", "Isolation Forest", self.current_mode)
        self._perf_if.grid(row=0, column=0, padx=8, sticky="nsew")

        self._perf_rf = PerformanceInfo(
            p_frame, "Classification Model", "Random Forest", self.current_mode)
        self._perf_rf.grid(row=0, column=1, padx=8, sticky="nsew")

        self._perf_rt = PerformanceInfo(
            p_frame, "Response Time", "—ms", self.current_mode)
        self._perf_rt.grid(row=0, column=2, padx=8, sticky="nsew")

        self._perf_fp = PerformanceInfo(
            p_frame, "False Positive Rate", "—%", self.current_mode)
        self._perf_fp.grid(row=0, column=3, padx=8, sticky="nsew")

        # Row 4 — Audit log
        self._table = MitigationTable(self._scroll, self.current_mode)
        self._table.pack(fill="x", padx=8, pady=(0, 10))

        # Row 5 — Quarantine panel
        self._qpanel = QuarantinePanel(
            self._scroll, self.current_mode,
            on_release=self._on_release,
            on_block=self._on_block)
        self._qpanel.pack(fill="x", padx=8, pady=(0, 20))
        self._qpanel.set_threshold(self._if_threshold)

        # Resolve internal canvas AFTER all widgets are packed, then bind scroll
        self.after(150, self._init_scroll_binding)

    def _setup_graph(self, parent, theme, mode_idx):
        self._graph_card = ctk.CTkFrame(
            parent, corner_radius=12, border_width=1,
            fg_color=theme["card"], border_color=theme["border"])
        self._graph_card.pack(fill="x", padx=8, pady=10)

        hdr = ctk.CTkFrame(self._graph_card, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(15, 0))
        ctk.CTkLabel(hdr, text="Live Traffic Monitor", font=("Arial", 14, "bold"),
                     text_color=theme["text"]).pack(side="left")
        ctk.CTkLabel(hdr, text=" ● Real-time", font=("Arial", 11, "bold"),
                     text_color=styles.SUCCESS_GREEN[mode_idx]).pack(side="left", padx=5)

        self._range_var = ctk.StringVar(value=self._graph_range)
        seg = ctk.CTkSegmentedButton(
            hdr, values=["Live", "1 hr", "12 hr", "24 hr", "Session"],
            variable=self._range_var, command=self._on_range_change,
            font=("Arial", 11))
        seg.pack(side="right")

        fig_bg = theme["card"]
        self._fig, self._ax = plt.subplots(figsize=(10, 2.5), facecolor=fig_bg)
        self._ax.set_facecolor(fig_bg)
        self._ax.spines["top"].set_visible(False)
        self._ax.spines["right"].set_visible(False)
        self._ax.spines["bottom"].set_color(theme["border"])
        self._ax.spines["left"].set_color(theme["border"])
        self._ax.tick_params(colors=theme["subtext"], labelsize=9)
        self._ax.grid(True, axis="y", linestyle="--",
                      color=theme["border"], alpha=0.7)

        # Initialise with flat zero line so graph shows clean on startup
        now  = datetime.datetime.now()
        xs   = [now - datetime.timedelta(seconds=(GRAPH_PTS - i) * 2)
                for i in range(GRAPH_PTS)]
        ys   = [0] * GRAPH_PTS

        lb = styles.ACCENT_BLUE[mode_idx]
        lr = styles.DANGER_RED[mode_idx]
        lg = styles.SUCCESS_GREEN[mode_idx]

        self._line_in,  = self._ax.plot(xs, ys, color=lb, label="Incoming Traffic")
        self._line_blk, = self._ax.plot(xs, ys, color=lr, label="Blocked Traffic")
        self._line_fwd, = self._ax.plot(xs, ys, color=lg, label="Forwarded Traffic")

        self._ax.set_ylim(0, 10)
        self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
        self._ax.xaxis.set_major_locator(mdates.SecondLocator(bysecond=range(0, 60, 5)))
        self._fig.autofmt_xdate(rotation=0, ha="center")

        legend = self._ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.35),
                                 ncol=3, frameon=False)
        for t in legend.get_texts():
            t.set_color(theme["subtext"])
        plt.tight_layout()

        self._canvas = FigureCanvasTkAgg(self._fig, master=self._graph_card)
        self._canvas.draw()
        self._canvas_widget = self._canvas.get_tk_widget()
        self._canvas_widget.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    # ------------------------------------------------------------------
    # Scroll binding — robust Linux fix
    # ------------------------------------------------------------------

    def _init_scroll_binding(self):
        self._scroll_canvas = _get_scroll_canvas(self._scroll)
        if self._scroll_canvas:
            self._apply_scroll_bindings()
        else:
            # Retry once more if CTk hasn't finished rendering
            self.after(200, self._init_scroll_binding)

    def _apply_scroll_bindings(self):
        c = self._scroll_canvas

        def _scroll_up(event=None):
            c.yview_scroll(-1, "units")

        def _scroll_down(event=None):
            c.yview_scroll(1, "units")

        def _scroll_wheel(event):
            # Windows/macOS: event.delta is ±120 multiples
            if event.delta:
                c.yview_scroll(int(-1 * (event.delta / 120)), "units")

        # Linux uses Button-4 (scroll up) and Button-5 (scroll down)
        # Windows/macOS uses MouseWheel with delta
        self.bind_all("<Button-4>",    lambda e: _scroll_up())
        self.bind_all("<Button-5>",    lambda e: _scroll_down())
        self.bind_all("<MouseWheel>",  _scroll_wheel)

        # Also bind the matplotlib canvas widget so scrolling over graph works
        if hasattr(self, "_canvas_widget"):
            self._canvas_widget.bind("<Button-4>",   lambda e: _scroll_up())
            self._canvas_widget.bind("<Button-5>",   lambda e: _scroll_down())
            self._canvas_widget.bind("<MouseWheel>", _scroll_wheel)
            # Prevent matplotlib from consuming scroll events
            self._canvas_widget.bind("<Button-4>",   lambda e: (_scroll_up(), "break"))
            self._canvas_widget.bind("<Button-5>",   lambda e: (_scroll_down(), "break"))

    # ------------------------------------------------------------------
    # Background pollers
    # ------------------------------------------------------------------

    def _start_pollers(self):
        threading.Thread(target=self._stats_poller,
                         daemon=True, name="stats-poller").start()
        threading.Thread(target=self._model_info_poller,
                         daemon=True, name="model-poller").start()
        threading.Thread(target=self._quarantine_poller,
                         daemon=True, name="quarantine-poller").start()
        threading.Thread(target=self._sse_listener,
                         daemon=True, name="sse-listener").start()

    def _stats_poller(self):
        import time
        while True:
            try:
                r = requests.get(f"{API}/api/stats", timeout=2)
                if r.ok:
                    self._ui_queue.put(("stats", r.json()))
            except Exception:
                pass
            time.sleep(POLL_MS / 1000)

    def _model_info_poller(self):
        import time
        while True:
            try:
                r = requests.get(f"{API}/api/model_info", timeout=2)
                if r.ok:
                    self._ui_queue.put(("model_info", r.json()))
            except Exception:
                pass
            time.sleep(POLL_MS / 1000)

    def _quarantine_poller(self):
        import time
        while True:
            try:
                r = requests.get(f"{API}/api/quarantine_list", timeout=2)
                if r.ok:
                    self._ui_queue.put(("quarantine", r.json()))
            except Exception:
                pass
            time.sleep(POLL_MS / 1000)

    def _sse_listener(self):
        import time, json
        while True:
            try:
                with requests.get(f"{API}/api/events",
                                  stream=True, timeout=None) as resp:
                    for line in resp.iter_lines():
                        if line and line.startswith(b"data:"):
                            data = json.loads(line[5:].strip())
                            self._ui_queue.put(("event", data))
            except Exception:
                pass
            time.sleep(2)

    def _fetch_graph_history(self, range_key: str):
        try:
            key_map = {"1 hr": "1hr", "12 hr": "12hr",
                       "24 hr": "24hr", "Session": "session"}
            k = key_map.get(range_key, "1hr")
            r = requests.get(f"{API}/api/graph_history?range={k}", timeout=3)
            if r.ok:
                self._ui_queue.put(("graph_history", r.json()))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Drain loop
    # ------------------------------------------------------------------

    def _schedule_drain(self):
        self._drain_loop()

    def _drain_loop(self):
        try:
            processed = 0
            while not self._ui_queue.empty() and processed < 50:
                msg_type, data = self._ui_queue.get_nowait()
                self._handle_message(msg_type, data)
                processed += 1
        except Exception:
            pass
        self.after(DRAIN_MS, self._drain_loop)

    def _handle_message(self, msg_type: str, data):
        if msg_type == "stats":
            self._apply_stats(data)
        elif msg_type == "model_info":
            self._apply_model_info(data)
        elif msg_type == "event":
            self._table.add_event(data)
        elif msg_type == "quarantine":
            self._qpanel.refresh(data)
        elif msg_type == "graph_history":
            self._apply_graph_history(data)
        elif msg_type == "popup":
            self._show_popup(data)

    # ------------------------------------------------------------------
    # Stats update
    # ------------------------------------------------------------------

    def _apply_stats(self, s: dict):
        cur_total = s.get("total_packets", 0)
        cur_mal   = s.get("malicious_dropped", 0)
        cur_norm  = s.get("normal_packets", 0)

        def pct_change(cur, prev):
            delta = ((cur - prev) / max(prev, 1)) * 100
            return f"+{delta:.1f}%" if delta >= 0 else f"{delta:.1f}%"

        def pct_of(part, total):
            return (part / max(total, 1)) * 100

        self._card_total.update(f"{cur_total:,}",
                                pct_change(cur_total, self._prev_total))
        self._card_mal.update(f"{cur_mal:,}",
                              f"-{pct_of(cur_mal, cur_total):.1f}%")
        self._card_norm.update(f"{cur_norm:,}",
                               f"+{pct_of(cur_norm, cur_total):.1f}%")
        self._card_threats.update(str(s.get("active_threats", 0)),
                                  "Currently being mitigated")

        self._perf_rt._main_lbl.configure(
            text=f"{s.get('avg_latency_ms', 0)}ms")
        self._perf_rt.update_detail("Average mitigation latency")

        self._perf_fp._main_lbl.configure(
            text=f"{s.get('fp_rate', 0.0):.1f}%")
        self._perf_fp.update_detail("Legitimate traffic blocked")

        if self._graph_range == "Live":
            now       = datetime.datetime.now()
            delta_in  = max(cur_total - self._prev_total, 0)
            delta_blk = max(cur_mal   - self._prev_mal,   0)
            delta_fwd = max(cur_norm  - self._prev_normal, 0)
            self._live_times.append(now)
            self._live_in.append(delta_in)
            self._live_blocked.append(delta_blk)
            self._live_fwd.append(delta_fwd)
            self._redraw_live_graph()

        self._prev_total  = cur_total
        self._prev_mal    = cur_mal
        self._prev_normal = cur_norm

    def _apply_model_info(self, info: dict):
        if_acc = info.get("if_accuracy")
        rf_acc = info.get("rf_accuracy")
        thr    = info.get("if_threshold", 0.0)

        self._perf_if.update_detail(
            f"Anomaly detection accuracy: {if_acc:.1f}%"
            if if_acc is not None else "Anomaly detection accuracy: —")
        self._perf_rf.update_detail(
            f"Classification accuracy: {rf_acc:.1f}%"
            if rf_acc is not None else "Classification accuracy: —")

        if thr:
            self._if_threshold = thr
            self._qpanel.set_threshold(thr)

    # ------------------------------------------------------------------
    # Graph
    # ------------------------------------------------------------------

    def _redraw_live_graph(self):
        if not self._live_times:
            return
        xs = list(self._live_times)
        self._line_in.set_data(xs,  list(self._live_in))
        self._line_blk.set_data(xs, list(self._live_blocked))
        self._line_fwd.set_data(xs, list(self._live_fwd))
        self._ax.set_ylim(0, max(max(self._live_in, default=1),
                                 max(self._live_blocked, default=1),
                                 max(self._live_fwd, default=1), 1) * 1.2)
        self._ax.set_xlim(xs[0], xs[-1])
        self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
        self._ax.xaxis.set_major_locator(
            mdates.SecondLocator(bysecond=range(0, 60, 5)))
        self._fig.autofmt_xdate(rotation=0, ha="center")
        self._canvas.draw_idle()

    def _apply_graph_history(self, buckets: list):
        xs, y_in, y_blk, y_fwd = [], [], [], []
        for b in buckets:
            try:
                xs.append(datetime.datetime.strptime(
                    b["timestamp"], "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
            y_in.append(b.get("incoming",  0))
            y_blk.append(b.get("blocked",  0))
            y_fwd.append(b.get("forwarded", 0))

        if not xs:
            return

        self._line_in.set_data(xs,  y_in)
        self._line_blk.set_data(xs, y_blk)
        self._line_fwd.set_data(xs, y_fwd)
        self._ax.relim()
        self._ax.autoscale_view()

        rng = {"1 hr": "1hr", "12 hr": "12hr",
               "24 hr": "24hr", "Session": "session"}.get(self._graph_range, "1hr")
        if rng == "1hr":
            self._ax.xaxis.set_major_locator(
                mdates.MinuteLocator(byminute=range(0, 60, 10)))
            self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        elif rng == "12hr":
            self._ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
            self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        elif rng == "24hr":
            self._ax.xaxis.set_major_locator(mdates.HourLocator(interval=2))
            self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        else:
            self._ax.xaxis.set_major_locator(mdates.AutoDateLocator())
            self._ax.xaxis.set_major_formatter(
                mdates.AutoDateFormatter(self._ax.xaxis.get_major_locator()))

        self._fig.autofmt_xdate(rotation=0, ha="center")
        self._canvas.draw_idle()

    def _on_range_change(self, value: str):
        self._graph_range = value
        if value != "Live":
            threading.Thread(target=self._fetch_graph_history,
                             args=(value,), daemon=True).start()

    # ------------------------------------------------------------------
    # Quarantine actions
    # ------------------------------------------------------------------

    def _on_release(self, src_ip: str):
        try:
            requests.post(f"{API}/api/quarantine/release",
                          json={"src_ip": src_ip}, timeout=2)
        except Exception:
            pass

    def _on_block(self, src_ip: str):
        try:
            requests.post(f"{API}/api/quarantine/block",
                          json={"src_ip": src_ip}, timeout=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _on_generate_report(self):
        dlg    = ReportDialog(self, self.current_mode)
        result = dlg.get_result()
        if not result:
            return
        start_date, end_date = result

        def _download():
            try:
                resp = requests.post(
                    f"{API}/api/report",
                    json={"start_date": start_date, "end_date": end_date},
                    timeout=30)
                if resp.status_code == 404:
                    self._ui_queue.put(("popup",
                        resp.json().get("error", "No data found.")))
                    return
                if not resp.ok:
                    self._ui_queue.put(("popup", f"Error: {resp.status_code}"))
                    return
                filename = f"ddos_report_{start_date}_to_{end_date}.pdf"
                with open(filename, "wb") as f:
                    f.write(resp.content)
                self._ui_queue.put(("popup", f"Report saved to: {filename}"))
            except Exception as e:
                self._ui_queue.put(("popup", f"Report failed: {e}"))

        threading.Thread(target=_download, daemon=True).start()

    # ------------------------------------------------------------------
    # Theme toggle
    # ------------------------------------------------------------------

    def _toggle_mode(self):
        self.current_mode = "Light" if self.current_mode == "Dark" else "Dark"
        ctk.set_appearance_mode(self.current_mode)
        plt.close("all")
        self.setup_ui()
        self.after(DRAIN_MS, self._drain_loop)

    # ------------------------------------------------------------------
    # Popup
    # ------------------------------------------------------------------

    def _show_popup(self, message: str):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Info")
        dlg.geometry("420x120")
        theme = styles.THEME_CONFIG[self.current_mode]
        dlg.configure(fg_color=theme["bg"])
        ctk.CTkLabel(dlg, text=message, font=("Arial", 11),
                     text_color=theme["text"], wraplength=380).pack(pady=20)
        ctk.CTkButton(dlg, text="OK", width=80, command=dlg.destroy).pack()