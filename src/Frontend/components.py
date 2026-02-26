import customtkinter as ctk
import styles

class MetricCard(ctk.CTkFrame):
    """Clean metric cards without icon badges"""
    def __init__(self, parent, title, value, subtext, color, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1, 
                         fg_color=theme["card"], border_color=theme["border"])
        
        ctk.CTkLabel(self, text=title, font=("Arial", 12), text_color=theme["subtext"]).pack(anchor="w", padx=20, pady=(20, 0))
        ctk.CTkLabel(self, text=value, font=("Arial", 28, "bold"), text_color=theme["text"]).pack(anchor="w", padx=20, pady=(5,0))
        ctk.CTkLabel(self, text=subtext, font=("Arial", 11, "bold"), text_color=color).pack(anchor="w", padx=20, pady=(0, 20))

class PerformanceInfo(ctk.CTkFrame):
    """ML Model statistics blocks"""
    def __init__(self, parent, title, main, detail, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1, 
                         fg_color=theme["card"], border_color=theme["border"])
        
        ctk.CTkLabel(self, text=title, font=("Arial", 11), text_color=theme["subtext"]).pack(anchor="w", padx=15, pady=(15, 0))
        ctk.CTkLabel(self, text=main, font=("Arial", 16, "bold"), text_color=theme["text"]).pack(anchor="w", padx=15, pady=(5,0))
        ctk.CTkLabel(self, text=detail, font=("Arial", 10), text_color=theme["subtext"]).pack(anchor="w", padx=15, pady=(0, 15))

class MitigationTable(ctk.CTkFrame):
    """Custom Grid-based Table perfectly aligned for Pills"""
    def __init__(self, parent, mode="Dark"):
        theme = styles.THEME_CONFIG[mode]
        super().__init__(parent, corner_radius=12, border_width=1, 
                         fg_color=theme["card"], border_color=theme["border"])
        self.mode = mode

        # 1. Table Title Area
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=20, pady=(15, 10))
        ctk.CTkLabel(top_frame, text="Mitigation Audit Log", font=("Arial", 14, "bold"), text_color=theme["text"]).pack(side="left")
        ctk.CTkLabel(top_frame, text="ML Model: Isolation Forest + Random Forest", font=("Arial", 11), text_color=theme["subtext"]).pack(side="right")

        # 2. Column Headers
        header_row = ctk.CTkFrame(self, fg_color="transparent", height=30)
        # FIX: Left padding 15px. Right padding 32px (15px margin + 17px to account for the scrollbar thickness)
        header_row.pack(fill="x", padx=(15, 32))
        header_row.pack_propagate(False)

        # Refined proportional widths: Time(3), IP(3), Class(2), Vector(2), Conf(1), Priority(1), Action(2)
        self.grid_weights = [3, 3, 2, 2, 1, 1, 2] 
        cols = ["Timestamp", "Source IP", "Predicted Class", "Attack Vector", "Confidence", "Priority", "Action Taken"]

        for i, w in enumerate(self.grid_weights):
            header_row.grid_columnconfigure(i, weight=w, uniform="col")
            ctk.CTkLabel(header_row, text=cols[i], anchor="w", text_color=theme["subtext"], 
                         font=("Arial", 11, "bold")).grid(row=0, column=i, sticky="w", padx=5)

        # Thin divider under headers
        ctk.CTkFrame(self, height=1, fg_color=theme["border"]).pack(fill="x", padx=15, pady=(5, 0))

        # 3. Scrollable container for rows
        self.rows_container = ctk.CTkScrollableFrame(self, fg_color="transparent", height=280)
        self.rows_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Dummy Data
        dummy_data = [
            ("2026-02-22 18:17:44", "192.168.1.99", "Normal", "—", "87.4%", "Low", "Allowed"),
            ("2026-02-22 18:17:41", "185.220.101.180", "Normal", "—", "80.5%", "Low", "Allowed"),
            ("2026-02-22 18:17:38", "45.154.24.166", "Anomaly", "UDP Flood", "86.7%", "Medium", "Blocked"),
            ("2026-02-22 18:17:35", "192.168.1.109", "Normal", "—", "87.2%", "Low", "Allowed"),
            ("2026-02-22 18:17:32", "45.154.24.192", "DDoS", "TCP SYN Flood", "96.5%", "High", "Blocked"),
            ("2026-02-22 18:17:29", "103.45.78.222", "Normal", "—", "86.5%", "Low", "Allowed")
        ]
        
        for item in dummy_data:
            self.add_row(*item)

    def add_row(self, ts, ip, p_class, vector, conf, priority, action):
        theme = styles.THEME_CONFIG[self.mode]
        mode_idx = 0 if self.mode == "Light" else 1
        
        row = ctk.CTkFrame(self.rows_container, fg_color="transparent", height=45)
        row.pack(fill="x")
        row.pack_propagate(False) 
        row.grid_rowconfigure(0, weight=1) # Vertically center the row contents

        # Apply the EXACT same grid configuration to the row as the header
        for i, w in enumerate(self.grid_weights):
            row.grid_columnconfigure(i, weight=w, uniform="col")

        # 1. Timestamp & 2. Source IP
        ctk.CTkLabel(row, text=ts, anchor="w", text_color=theme["subtext"], font=("Arial", 11)).grid(row=0, column=0, sticky="w", padx=5)
        ctk.CTkLabel(row, text=ip, anchor="w", text_color=theme["text"], font=("Arial", 11)).grid(row=0, column=1, sticky="w", padx=5)

        # 3. Predicted Class (Fully Rounded Outlined Pill)
        c_colors = styles.CLASS_COLORS.get(p_class, styles.CLASS_COLORS["Normal"])
        text_color = c_colors["text"][mode_idx]
        ctk.CTkButton(row, text=p_class, fg_color="transparent", text_color=text_color, 
                      border_color=text_color, border_width=1, corner_radius=12, 
                      font=("Arial", 10, "bold"), width=70, height=24, hover=False).grid(row=0, column=2, sticky="w", padx=5)

        # 4. Attack Vector
        if vector == "—":
            ctk.CTkLabel(row, text=vector, text_color=theme["subtext"], font=("Arial", 11)).grid(row=0, column=3, sticky="w", padx=5)
        else:
            v_colors = styles.VECTOR_COLORS.get(vector, styles.VECTOR_COLORS["—"])
            text_color = v_colors["text"][mode_idx]
            ctk.CTkButton(row, text=vector, fg_color="transparent", text_color=text_color, 
                          border_color=text_color, border_width=1, corner_radius=12, 
                          font=("Arial", 10, "bold"), width=90, height=24, hover=False).grid(row=0, column=3, sticky="w", padx=5)

        # 5. Confidence
        ctk.CTkLabel(row, text=conf, anchor="w", text_color=theme["text"], font=("Arial", 11)).grid(row=0, column=4, sticky="w", padx=5)

        # 6. Priority 
        fallback_priority_colors = {
            "Low": {"text": ("#6b7280", "#9ca3af")},
            "Medium": {"text": ("#ea580c", "#f59e0b")},
            "High": {"text": ("#dc2626", "#ef4444")}
        }
        p_colors = getattr(styles, "PRIORITY_COLORS", fallback_priority_colors).get(priority, fallback_priority_colors["Low"])
        p_text_color = p_colors["text"][mode_idx]
        p_font_weight = "bold" if priority in ["Medium", "High"] else "normal"
        
        ctk.CTkLabel(row, text=priority, anchor="w", text_color=p_text_color, 
                     font=("Arial", 11, p_font_weight)).grid(row=0, column=5, sticky="w", padx=5)

        # 7. Action Taken
        a_colors = styles.ACTION_COLORS.get(action, styles.ACTION_COLORS["Allowed"])
        border_color = a_colors["border"][mode_idx]
        text_color = a_colors["text"][mode_idx]
        
        ctk.CTkButton(row, text=action, fg_color="transparent", text_color=text_color, 
                      border_color=border_color, border_width=1, corner_radius=12, 
                      font=("Arial", 10, "bold"), width=70, height=24, hover=False).grid(row=0, column=6, sticky="w", padx=5)

        # Thin divider line under row
        ctk.CTkFrame(self.rows_container, height=1, fg_color=theme["border"]).pack(fill="x", padx=5)