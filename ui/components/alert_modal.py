import customtkinter as ctk
from ui.theme import (
    COLOR_CARD, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_DANGER_HOVER,
    COLOR_SUCCESS, COLOR_WARNING, FONT_FAMILY
)

class CustomAlertModal(ctk.CTkToplevel):
    def __init__(self, parent, title="Notificación", message="", alert_type="info", callback=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("480x240")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.callback = callback
        self.result = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Seleccionar icono y color según tipo
        icons = {
            "info": ("ℹ️", COLOR_ACCENT),
            "warning": ("⚠️", COLOR_WARNING),
            "error": ("❌", COLOR_DANGER),
            "success": ("✓", COLOR_SUCCESS),
            "confirm": ("❓", COLOR_WARNING)
        }
        icon_symbol, header_color = icons.get(alert_type, ("ℹ️", COLOR_ACCENT))

        # Encabezado estilizado
        header = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=50)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(header, text=icon_symbol, font=ctk.CTkFont(family=FONT_FAMILY, size=20))
        lbl_icon.pack(side="left", padx=(16, 8), pady=12)

        lbl_title = ctk.CTkLabel(
            header, text=title,
            font=ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        lbl_title.pack(side="left", pady=12)

        # Cuerpo del mensaje
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=16)

        lbl_msg = ctk.CTkLabel(
            body, text=message,
            font=ctk.CTkFont(family=FONT_FAMILY, size=13),
            text_color=COLOR_TEXT_SECONDARY,
            justify="left", wraplength=440
        )
        lbl_msg.pack(anchor="w", fill="both", expand=True)

        # Footer con botones
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 16))

        if alert_type == "confirm":
            btn_no = ctk.CTkButton(
                footer, text="Cancelar / No", width=110, height=36,
                fg_color=COLOR_CARD, hover_color=COLOR_CARD,
                text_color=COLOR_TEXT_PRIMARY,
                command=self._on_no
            )
            btn_no.pack(side="right", padx=(8, 0))

            btn_yes = ctk.CTkButton(
                footer, text="Confirmar / Sí", width=120, height=36,
                fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER,
                command=self._on_yes
            )
            btn_yes.pack(side="right")
        else:
            btn_ok = ctk.CTkButton(
                footer, text="Entendido", width=120, height=36,
                fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                command=self._on_yes
            )
            btn_ok.pack(side="right")

    def _on_yes(self):
        self.result = True
        if self.callback:
            self.callback(True)
        self.destroy()

    def _on_no(self):
        self.result = False
        if self.callback:
            self.callback(False)
        self.destroy()


def show_alert(parent, title, message, alert_type="info", callback=None):
    """Muestra un modal estilizado personalizado en lugar de messagebox."""
    CustomAlertModal(parent, title=title, message=message, alert_type=alert_type, callback=callback)


def ask_confirm(parent, title, message, callback):
    """Muestra un modal de confirmación y llama al callback con True/False."""
    CustomAlertModal(parent, title=title, message=message, alert_type="confirm", callback=callback)
