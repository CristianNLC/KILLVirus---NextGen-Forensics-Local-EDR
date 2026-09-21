import time
import os
import customtkinter as ctk
from ui.theme import (
    COLOR_CARD, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    COLOR_ACCENT, FONT_FAMILY
)

class ProgressCard(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=COLOR_CARD, corner_radius=12, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.start_time = 0
        self.total_items = 0

        # Título de la operación
        self.lbl_title = ctk.CTkLabel(
            self, text="Escaneo inactivo",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY, anchor="w"
        )
        self.lbl_title.grid(row=0, column=0, padx=16, pady=(12, 4), sticky="ew")

        # Archivo / Proceso actual en evaluación
        self.lbl_current_item = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY, anchor="w"
        )
        self.lbl_current_item.grid(row=1, column=0, padx=16, pady=(0, 6), sticky="ew")

        # Contenedor de la barra y el porcentaje
        bar_box = ctk.CTkFrame(self, fg_color="transparent")
        bar_box.grid(row=2, column=0, padx=16, pady=(0, 6), sticky="ew")
        bar_box.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(bar_box, height=12, corner_radius=6, progress_color=COLOR_ACCENT)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.progress_bar.set(0.0)

        self.lbl_percent = ctk.CTkLabel(
            bar_box, text="0%", width=45,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        self.lbl_percent.grid(row=0, column=1)

        # Fila de Estadísticas: Contador X / Y | ETA
        stats_box = ctk.CTkFrame(self, fg_color="transparent")
        stats_box.grid(row=3, column=0, padx=16, pady=(0, 12), sticky="ew")

        self.lbl_count = ctk.CTkLabel(
            stats_box, text="Archivos escaneados: 0 / 0",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLOR_TEXT_SECONDARY
        )
        self.lbl_count.pack(side="left")

        self.lbl_eta = ctk.CTkLabel(
            stats_box, text="ETA: --:--",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            text_color=COLOR_ACCENT
        )
        self.lbl_eta.pack(side="right")

    def start(self, title="Analizando archivos...", total=0):
        self.start_time = time.time()
        self.total_items = total
        self.lbl_title.configure(text=title)
        self.lbl_current_item.configure(text="Iniciando motor de análisis...")
        self.progress_bar.set(0.0)
        self.lbl_percent.configure(text="0%")
        self.lbl_count.configure(text=f"Archivos escaneados: 0 / {total}")
        self.lbl_eta.configure(text="ETA: Calculando...")

    def update_progress(self, current, total, item_path=""):
        if total <= 0:
            pct = 1.0
        else:
            pct = min(1.0, max(0.0, current / total))

        pct_int = int(pct * 100)
        elapsed = time.time() - self.start_time

        # Cálculo preciso de ETA: (tiempo_actual - tiempo_inicio) / archivos_procesados = sec_per_file
        if current > 0 and elapsed > 0.05 and current < total:
            sec_per_file = elapsed / current
            remaining_items = total - current
            remaining_seconds = int(sec_per_file * remaining_items)
            mins, secs = divmod(remaining_seconds, 60)
            hrs, mins = divmod(mins, 60)
            if hrs > 0:
                eta_str = f"ETA: {hrs:02d}:{mins:02d}:{secs:02d}"
            else:
                eta_str = f"ETA: {mins:02d}:{secs:02d}"
        elif current >= total and total > 0:
            eta_str = "ETA: 00:00"
        else:
            eta_str = "ETA: Calculando..."

        filename = os.path.basename(item_path) if item_path else ""
        display_text = f"Analizando actualmente: {filename}" if filename else ""

        # Actualizar widgets
        self.progress_bar.set(pct)
        self.lbl_percent.configure(text=f"{pct_int}%")
        self.lbl_count.configure(text=f"Archivos escaneados: {current} / {total}")
        self.lbl_eta.configure(text=eta_str)
        if display_text:
            self.lbl_current_item.configure(text=display_text)

    def set_complete(self, title="Análisis completado", total=0):
        self.progress_bar.set(1.0)
        self.lbl_percent.configure(text="100%")
        self.lbl_title.configure(text=title)
        self.lbl_current_item.configure(text="Análisis completado con éxito.")
        self.lbl_count.configure(text=f"Archivos escaneados: {total} / {total}")
        self.lbl_eta.configure(text="ETA: 00:00")
