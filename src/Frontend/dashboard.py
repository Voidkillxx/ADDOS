import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import styles
from components import MetricCard, PerformanceInfo, MitigationTable

class DDoSDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DDoS Mitigation System Dashboard")
        self.geometry("1300x950")
        self.current_mode = "Dark"
        ctk.set_appearance_mode(self.current_mode)
        self.setup_ui()

    def setup_ui(self):
        # Clear UI for fresh render during theme switch
        for widget in self.winfo_children():
            widget.destroy()
            
        theme = styles.THEME_CONFIG[self.current_mode]
        self.configure(fg_color=theme["bg"])

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(20, 10))
        
        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="A-DDoS", font=("Arial", 26, "bold"), text_color=theme["text"]).pack(anchor="w")
        ctk.CTkLabel(title_box, text="Threat detection & mitigation System", font=("Arial", 12), text_color=theme["subtext"]).pack(anchor="w")

        self.mode_btn = ctk.CTkButton(header,  text="Dark Mode" if self.current_mode == "Light" else "Light Mode", width=120, command=self.toggle_mode, 
                                      fg_color=theme["card"], text_color=theme["text"], border_width=1, border_color=theme["border"])
        self.mode_btn.pack(side="right", padx=10)
        
        # System Active Button styling logic
        mode_idx = 0 if self.current_mode == "Light" else 1
        active_bg = "#1b3a2a" if self.current_mode == "Dark" else "#ecfdf5"
        ctk.CTkButton(header, text="● System Active", fg_color=active_bg, 
                      text_color=styles.SUCCESS_GREEN[mode_idx], corner_radius=20, hover=False).pack(side="right")

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20)

        # --- Row 1: Metrics ---
        m_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        m_frame.pack(fill="x", pady=10)
        m_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        MetricCard(m_frame, "Total Packets Detected", "15,938", "+12.5%", styles.ACCENT_BLUE, self.current_mode).grid(row=0, column=0, padx=8, sticky="nsew")
        MetricCard(m_frame, "Malicious Packets Dropped", "3,251", "-8.3%", styles.DANGER_RED, self.current_mode).grid(row=0, column=1, padx=8, sticky="nsew")
        MetricCard(m_frame, "Normal Traffic", "12,666", "+5.2%", styles.SUCCESS_GREEN, self.current_mode).grid(row=0, column=2, padx=8, sticky="nsew")
        MetricCard(m_frame, "Active Threats", "1", "Currently being mitigated", styles.WARNING_ORANGE, self.current_mode).grid(row=0, column=3, padx=8, sticky="nsew")

        # --- Row 2: Live Traffic Monitor ---
        self.setup_graph(scroll, theme, mode_idx)

        # --- Row 3: ML Performance ---
        p_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        p_frame.pack(fill="x", pady=(10, 20))
        p_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        PerformanceInfo(p_frame, "Detection Model", "Isolation Forest", "Anomaly detection accuracy: 94.7%", self.current_mode).grid(row=0, column=0, padx=8, sticky="nsew")
        PerformanceInfo(p_frame, "Classification Model", "Random Forest", "Classification accuracy: 96.2%", self.current_mode).grid(row=0, column=1, padx=8, sticky="nsew")
        PerformanceInfo(p_frame, "Response Time", "12ms", "Average mitigation latency", self.current_mode).grid(row=0, column=2, padx=8, sticky="nsew")
        PerformanceInfo(p_frame, "False Positive Rate", "2.1%", "Legitimate traffic blocked", self.current_mode).grid(row=0, column=3, padx=8, sticky="nsew")

        # --- Row 4: Audit Log Table ---
        self.table = MitigationTable(scroll, self.current_mode)
        self.table.pack(fill="x", padx=8, pady=(0, 20))

    def setup_graph(self, parent, theme, mode_idx):
        graph_card = ctk.CTkFrame(parent, corner_radius=12, border_width=1, 
                                  fg_color=theme["card"], border_color=theme["border"])
        graph_card.pack(fill="x", padx=8, pady=10)
        
        # Graph Header
        header_frame = ctk.CTkFrame(graph_card, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(15, 0))
        ctk.CTkLabel(header_frame, text="Live Traffic Monitor", font=("Arial", 14, "bold"), text_color=theme["text"]).pack(side="left")
        
        # Pull single green hex for real-time dot
        green_hex = styles.SUCCESS_GREEN[mode_idx]
        ctk.CTkLabel(header_frame, text=" ● Real-time", font=("Arial", 11, "bold"), text_color=green_hex).pack(side="left", padx=5)

        # Plot Setup
        fig, ax = plt.subplots(figsize=(10, 2.5), facecolor=theme["card"])
        ax.set_facecolor(theme["card"])
        
        # Spine configuration
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color(theme["border"])
        ax.spines['left'].set_color(theme["border"])
        
        # Extract single hex color from the tuple for Matplotlib
        line_blue = styles.ACCENT_BLUE[mode_idx]
        line_red = styles.DANGER_RED[mode_idx]
        line_green = styles.SUCCESS_GREEN[mode_idx]
        
        x = list(range(10))
        ax.plot(x, [500, 700, 900, 850, 500, 250, 180, 250, 200, 200], color=line_blue, label="Incoming Traffic")
        ax.plot(x, [300, 600, 750, 700, 200, 50, 20, 50, 40, 40], color=line_red, label="Blocked Traffic")
        ax.plot(x, [200, 100, 150, 150, 300, 200, 160, 200, 160, 160], color=line_green, label="Forwarded Traffic")
        
        ax.tick_params(colors=theme["subtext"], labelsize=9)
        ax.grid(True, axis='y', linestyle='--', color=theme["border"], alpha=0.7)
        
        # Custom Legend placement
        legend = ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.3), ncol=3, frameon=False)
        for text in legend.get_texts():
            text.set_color(theme["subtext"])
            
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=graph_card)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def toggle_mode(self):
        self.current_mode = "Light" if self.current_mode == "Dark" else "Dark"
        ctk.set_appearance_mode(self.current_mode)
        self.setup_ui()