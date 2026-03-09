import tkinter as tk
import customtkinter as ctk
import styles


class _VarLabel(ctk.CTkLabel):
    """CTkLabel that routes configure(text=...) through its StringVar.
    This prevents CustomTkinter from destroying/recreating the underlying
    tk.Label on every text update, which causes a one-frame blank flash
    (visible flicker) on Linux/TkAgg backends."""
    def configure(self, **kw):
        if "text" in kw:
            var = self.cget("textvariable")
            if isinstance(var, tk.StringVar):
                var.set(kw.pop("text"))
        if kw:
            super().configure(**kw)


class MetricCard(ctk.CTkFrame):
    def __init__(self, parent, title, color, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1,
                         fg_color=theme["card"], border_color=theme["border"])
        self.mode  = mode
        self.color = color

        self._value_var = tk.StringVar(value="\u2014")
        self._sub_var   = tk.StringVar(value="\u2014")

        ctk.CTkLabel(self, text=title, font=("Arial", 12),
                     text_color=theme["subtext"]).pack(anchor="w", padx=20, pady=(20, 0))
        ctk.CTkLabel(self, textvariable=self._value_var, font=("Arial", 28, "bold"),
                     text_color=theme["text"]).pack(anchor="w", padx=20, pady=(5, 0))
        ctk.CTkLabel(self, textvariable=self._sub_var, font=("Arial", 11, "bold"),
                     text_color=color).pack(anchor="w", padx=20, pady=(0, 20))

    def update(self, value: str, subtext: str) -> None:
        self._value_var.set(value)
        self._sub_var.set(subtext)


class PerformanceInfo(ctk.CTkFrame):
    def __init__(self, parent, title, main, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1,
                         fg_color=theme["card"], border_color=theme["border"])

        self._main_var   = tk.StringVar(value=main)
        self._detail_var = tk.StringVar(value="\u2014")

        ctk.CTkLabel(self, text=title, font=("Arial", 11),
                     text_color=theme["subtext"]).pack(anchor="w", padx=15, pady=(15, 0))
        self._main_lbl = _VarLabel(self, textvariable=self._main_var,
                                   font=("Arial", 16, "bold"),
                                   text_color=theme["text"])
        self._main_lbl.pack(anchor="w", padx=15, pady=(5, 0))
        ctk.CTkLabel(self, textvariable=self._detail_var, font=("Arial", 10),
                     text_color=theme["subtext"]).pack(anchor="w", padx=15, pady=(0, 15))

    def update_detail(self, detail: str) -> None:
        self._detail_var.set(detail)


class MitigationTable(ctk.CTkFrame):
    def __init__(self, parent, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1,
                         fg_color=theme["card"], border_color=theme["border"])
        self.mode = mode
        self._rows: list = []

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(15, 10))
        ctk.CTkLabel(top, text="Mitigation Audit Log", font=("Arial", 14, "bold"),
                     text_color=theme["text"]).pack(side="left")
        ctk.CTkLabel(top, text="ML Model: Isolation Forest + Random Forest",
                     font=("Arial", 11), text_color=theme["subtext"]).pack(side="right")

        header_row = ctk.CTkFrame(self, fg_color="transparent", height=30)
        header_row.pack(fill="x", padx=(15, 32))
        header_row.pack_propagate(False)

        self.grid_weights = [3, 3, 2, 2, 1, 1, 2]
        cols = ["Timestamp", "Source IP", "Predicted Class",
                "Attack Vector", "Confidence", "Priority", "Action Taken"]
        for i, w in enumerate(self.grid_weights):
            header_row.grid_columnconfigure(i, weight=w, uniform="col")
            ctk.CTkLabel(header_row, text=cols[i], anchor="w",
                         text_color=theme["subtext"],
                         font=("Arial", 11, "bold")).grid(row=0, column=i,
                                                          sticky="w", padx=5)

        ctk.CTkFrame(self, height=1, fg_color=theme["border"]).pack(fill="x", padx=15, pady=(5, 0))

        self.rows_container = ctk.CTkScrollableFrame(self, fg_color="transparent", height=280)
        self.rows_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def add_event(self, event: dict) -> None:
        theme    = styles.THEME_CONFIG[self.mode]
        mode_idx = 0 if self.mode == "Light" else 1

        # Enforce 100-event cap — remove oldest widget row
        if len(self._rows) >= 100:
            oldest = self._rows.pop(0)
            oldest.destroy()
            # Also remove the divider below it
            children = self.rows_container.winfo_children()
            if children:
                children[0].destroy()

        row = ctk.CTkFrame(self.rows_container, fg_color="transparent", height=45)
        row.pack(fill="x")
        row.pack_propagate(False)
        row.grid_rowconfigure(0, weight=1)
        for i, w in enumerate(self.grid_weights):
            row.grid_columnconfigure(i, weight=w, uniform="col")

        ts         = event.get("timestamp", "—")
        src_ip     = event.get("src_ip", "—")
        p_class    = event.get("predicted_class", "—")
        vector     = event.get("attack_vector", "—")
        conf       = event.get("confidence", "—")
        priority   = event.get("priority", "—")
        action     = event.get("action_taken", "—")

        ctk.CTkLabel(row, text=ts, anchor="w", text_color=theme["subtext"],
                     font=("Arial", 11)).grid(row=0, column=0, sticky="w", padx=5)
        ctk.CTkLabel(row, text=src_ip, anchor="w", text_color=theme["text"],
                     font=("Arial", 11)).grid(row=0, column=1, sticky="w", padx=5)

        c_colors   = styles.CLASS_COLORS.get(p_class, {"text": (theme["subtext"], theme["subtext"])})
        c_text     = c_colors["text"][mode_idx]
        ctk.CTkButton(row, text=p_class, fg_color="transparent", text_color=c_text,
                      border_color=c_text, border_width=1, corner_radius=12,
                      font=("Arial", 10, "bold"), width=70, height=24,
                      hover=False).grid(row=0, column=2, sticky="w", padx=5)

        if vector in ("—", "Uncertain", None):
            ctk.CTkLabel(row, text=vector or "—", text_color=theme["subtext"],
                         font=("Arial", 11)).grid(row=0, column=3, sticky="w", padx=5)
        else:
            v_colors = styles.VECTOR_COLORS.get(vector, styles.VECTOR_COLORS["Uncertain"])
            v_text   = v_colors["text"][mode_idx]
            ctk.CTkButton(row, text=vector, fg_color="transparent", text_color=v_text,
                          border_color=v_text, border_width=1, corner_radius=12,
                          font=("Arial", 10, "bold"), width=100, height=24,
                          hover=False).grid(row=0, column=3, sticky="w", padx=5)

        ctk.CTkLabel(row, text=conf, anchor="w", text_color=theme["text"],
                     font=("Arial", 11)).grid(row=0, column=4, sticky="w", padx=5)

        p_colors = styles.PRIORITY_COLORS.get(priority, styles.PRIORITY_COLORS["Low"])
        p_text   = p_colors["text"][mode_idx]
        ctk.CTkLabel(row, text=priority, anchor="w", text_color=p_text,
                     font=("Arial", 11, "bold" if priority == "High" else "normal")
                     ).grid(row=0, column=5, sticky="w", padx=5)

        a_colors     = styles.ACTION_COLORS.get(action, styles.ACTION_COLORS["Blocked"])
        a_border     = a_colors["border"][mode_idx]
        a_text       = a_colors["text"][mode_idx]
        ctk.CTkButton(row, text=action, fg_color="transparent", text_color=a_text,
                      border_color=a_border, border_width=1, corner_radius=12,
                      font=("Arial", 10, "bold"), width=90, height=24,
                      hover=False).grid(row=0, column=6, sticky="w", padx=5)

        ctk.CTkFrame(self.rows_container, height=1,
                     fg_color=theme["border"]).pack(fill="x", padx=5)
        self._rows.append(row)

    def clear(self) -> None:
        for w in self.rows_container.winfo_children():
            w.destroy()
        self._rows.clear()


class QuarantinePanel(ctk.CTkFrame):
    """Active Quarantine & Watch List panel — polled every 2 seconds."""

    def __init__(self, parent, mode="Dark",
                 on_release=None, on_block=None):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1,
                         fg_color=theme["card"], border_color=theme["border"])
        self.mode       = mode
        self.on_release = on_release
        self.on_block   = on_block
        self._if_threshold = 0.0
        self._last_data: list = []  # cache to skip redraws when data unchanged

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(15, 10))
        self._title_lbl = ctk.CTkLabel(
            top, text="Active Quarantine & Watch List",
            font=("Arial", 14, "bold"), text_color=theme["text"])
        self._title_lbl.pack(side="left")

        col_frame = ctk.CTkFrame(self, fg_color="transparent", height=30)
        col_frame.pack(fill="x", padx=(15, 32))
        col_frame.pack_propagate(False)
        self._col_weights = [2, 2, 2, 1, 1, 2, 2]
        headers = ["IP Address", "Phase", "Attack Vector",
                   "IF Score", "Confidence", "Time in Phase", "Actions"]
        for i, w in enumerate(self._col_weights):
            col_frame.grid_columnconfigure(i, weight=w, uniform="qcol")
            ctk.CTkLabel(col_frame, text=headers[i], anchor="w",
                         text_color=theme["subtext"],
                         font=("Arial", 11, "bold")).grid(row=0, column=i,
                                                          sticky="w", padx=5)

        ctk.CTkFrame(self, height=1, fg_color=theme["border"]).pack(fill="x", padx=15, pady=(5, 0))

        self.rows_container = ctk.CTkScrollableFrame(
            self, fg_color="transparent", height=200)
        self.rows_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self._empty_lbl = ctk.CTkLabel(
            self.rows_container,
            text="No IPs currently under active mitigation.",
            font=("Arial", 11), text_color=theme["subtext"])
        self._empty_lbl.pack(pady=20)

    def set_threshold(self, threshold: float) -> None:
        self._if_threshold = threshold

    def refresh(self, data: list[dict]) -> None:
        # Skip redraw entirely if data is unchanged — prevents flicker from
        # destroying and recreating every widget row on each 2-second poll
        def _key(e):
            return (e.get("src_ip"), e.get("phase"), e.get("attack_vector"),
                    e.get("time_in_phase_sec"), e.get("confidence"))
        if [_key(e) for e in data] == [_key(e) for e in self._last_data]:
            return
        self._last_data = list(data)

        theme    = styles.THEME_CONFIG[self.mode]
        mode_idx = 0 if self.mode == "Light" else 1

        for w in self.rows_container.winfo_children():
            w.destroy()

        count = len(data)
        self._title_lbl.configure(
            text=f"Active Quarantine & Watch List ({count} IPs)")

        if count == 0:
            ctk.CTkLabel(self.rows_container,
                         text="No IPs currently under active mitigation.",
                         font=("Arial", 11),
                         text_color=theme["subtext"]).pack(pady=20)
            return

        for entry in data:
            self._add_row(entry, theme, mode_idx)

    def _if_score_color(self, score: float, mode_idx: int) -> str:
        thr = self._if_threshold
        if thr <= 0:
            return ("#6b7280", "#9ca3af")[mode_idx]
        if score >= thr * styles.IF_SCORE_RED:
            return ("#dc2626", "#ef4444")[mode_idx]
        if score >= thr * styles.IF_SCORE_AMBER:
            return ("#ea580c", "#f59e0b")[mode_idx]
        return ("#16a34a", "#10b981")[mode_idx]

    def _format_time(self, secs: int) -> str:
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"

    def _add_row(self, entry: dict, theme: dict, mode_idx: int) -> None:
        src_ip        = entry.get("src_ip", "—")
        phase         = entry.get("phase", "—")
        vector        = entry.get("attack_vector", "—")
        if_score      = entry.get("if_score", 0.0)
        confidence    = entry.get("confidence", "—")
        time_in_phase = self._format_time(entry.get("time_in_phase_sec", 0))

        row = ctk.CTkFrame(self.rows_container, fg_color="transparent", height=45)
        row.pack(fill="x")
        row.pack_propagate(False)
        row.grid_rowconfigure(0, weight=1)
        for i, w in enumerate(self._col_weights):
            row.grid_columnconfigure(i, weight=w, uniform="qcol")

        ctk.CTkLabel(row, text=src_ip, anchor="w", text_color=theme["text"],
                     font=("Arial", 11)).grid(row=0, column=0, sticky="w", padx=5)
        ctk.CTkLabel(row, text=phase, anchor="w", text_color=theme["subtext"],
                     font=("Arial", 10)).grid(row=0, column=1, sticky="w", padx=5)

        v_colors = styles.VECTOR_COLORS.get(vector, styles.VECTOR_COLORS["Uncertain"])
        v_text   = v_colors["text"][mode_idx]
        ctk.CTkLabel(row, text=vector, anchor="w", text_color=v_text,
                     font=("Arial", 11)).grid(row=0, column=2, sticky="w", padx=5)

        score_color = self._if_score_color(if_score, mode_idx)
        ctk.CTkLabel(row, text=f"{if_score:.4f}", anchor="w",
                     text_color=score_color,
                     font=("Arial", 11, "bold")).grid(row=0, column=3, sticky="w", padx=5)

        ctk.CTkLabel(row, text=confidence, anchor="w", text_color=theme["text"],
                     font=("Arial", 11)).grid(row=0, column=4, sticky="w", padx=5)

        ctk.CTkLabel(row, text=time_in_phase, anchor="w", text_color=theme["subtext"],
                     font=("Arial", 11)).grid(row=0, column=5, sticky="w", padx=5)

        btn_frame = ctk.CTkFrame(row, fg_color="transparent")
        btn_frame.grid(row=0, column=6, sticky="w", padx=5)

        ctk.CTkButton(btn_frame, text="Release", width=65, height=24,
                      fg_color="transparent",
                      text_color=("#16a34a", "#10b981")[mode_idx],
                      border_color=("#16a34a", "#10b981")[mode_idx],
                      border_width=1, corner_radius=8,
                      font=("Arial", 10, "bold"),
                      command=lambda ip=src_ip: self.on_release and self.on_release(ip)
                      ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(btn_frame, text="Block Now", width=75, height=24,
                      fg_color="transparent",
                      text_color=("#dc2626", "#ef4444")[mode_idx],
                      border_color=("#dc2626", "#ef4444")[mode_idx],
                      border_width=1, corner_radius=8,
                      font=("Arial", 10, "bold"),
                      command=lambda ip=src_ip: self.on_block and self.on_block(ip)
                      ).pack(side="left")

        ctk.CTkFrame(self.rows_container, height=1,
                     fg_color=theme["border"]).pack(fill="x", padx=5)