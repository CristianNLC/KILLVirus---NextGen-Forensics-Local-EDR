import os
import json
from datetime import datetime
import customtkinter as ctk
from ui.theme import (
    COLOR_CARD, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, FONT_FAMILY
)

def format_quarantine_date(raw_date_str: str) -> str:
    """Convierte un timestamp crudo o ISO a DD/MM/YYYY HH:MM:SS."""
    if not raw_date_str or raw_date_str == "Desconocida":
        return "Fecha Desconocida"

    # Intentar varios formatos
    formats = [
        "%Y%m%d_%H%M%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d"
    ]
    
    clean_str = raw_date_str.split(".")[0].replace("Z", "").strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(clean_str, fmt)
            return dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            continue

    return raw_date_str

class QuarantineDetailModal(ctk.CTkToplevel):
    def __init__(self, parent, quarantine_filepath: str):
        super().__init__(parent)
        self.title("Detalle del Archivo Aislado")
        self.geometry("560x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Cargar datos de la metadata si existe
        meta_path = quarantine_filepath + ".meta"
        meta_data = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
            except Exception:
                pass

        filename = os.path.basename(quarantine_filepath)
        size_bytes = os.path.getsize(quarantine_filepath) if os.path.exists(quarantine_filepath) else 0
        size_str = f"{round(size_bytes / 1024, 2)} KB ({size_bytes} bytes)" if size_bytes < 1024*1024 else f"{round(size_bytes / (1024*1024), 2)} MB"

        orig_path = meta_data.get("original_path", "No registrado")
        raw_date = meta_data.get("date", "Desconocida")
        date_formatted = format_quarantine_date(raw_date)
        reason = meta_data.get("reason", "Detención preventiva en cuarentena")
        f_hash = meta_data.get("sha256", "No registrado")

        # Encabezado
        header = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=54)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        lbl_t = ctk.CTkLabel(
            header, text="📦 Detalles del Elemento en Cuarentena",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        lbl_t.pack(anchor="w", padx=20, pady=14)

        # Cuerpo del modal
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=16)
        body.grid_columnconfigure(1, weight=1)

        fields = [
            ("Archivo Aislado:", filename),
            ("Ruta Original:", orig_path),
            ("Motivo de Detección:", reason),
            ("Fecha de Aislamiento:", date_formatted),
            ("Tamaño en Disco:", size_str),
            ("Hash SHA-256:", f_hash)
        ]

        for idx, (label, val) in enumerate(fields):
            lbl_key = ctk.CTkLabel(
                body, text=label,
                font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
                text_color=COLOR_TEXT_PRIMARY, anchor="e"
            )
            lbl_key.grid(row=idx, column=0, padx=(0, 10), pady=6, sticky="ne")

            txt_val = ctk.CTkTextbox(
                body, height=28 if idx != 1 and idx != 5 else 48,
                font=ctk.CTkFont(family="Consolas" if idx in (1, 5) else FONT_FAMILY, size=11),
                fg_color=COLOR_CARD, text_color=COLOR_TEXT_SECONDARY
            )
            txt_val.grid(row=idx, column=1, pady=4, sticky="ew")
            txt_val.insert("1.0", str(val))
            txt_val.configure(state="disabled")

        # Footer
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 16))

        btn_close = ctk.CTkButton(
            footer, text="Cerrar", width=110, height=36,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            command=self.destroy
        )
        btn_close.pack(side="right")
