import webbrowser
import customtkinter as ctk
from ui.theme import (
    COLOR_CARD, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_GOLD, COLOR_SUCCESS,
    COLOR_SUCCESS_HOVER, FONT_FAMILY
)

class ProUpgradeModal(ctk.CTkToplevel):
    def __init__(self, parent, feature_name="Esta funcionalidad", on_activate_callback=None):
        super().__init__(parent)
        self.title("Desbloquear KILLVirus PRO")
        self.geometry("520x460")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.on_activate_callback = on_activate_callback

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Encabezado destacado
        header_frame = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        lbl_badge = ctk.CTkLabel(
            header_frame, text="🔒 FUNCIÓN EXCLUSIVA PRO",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLOR_GOLD
        )
        lbl_badge.pack(padx=20, pady=(16, 4), anchor="w")

        lbl_title = ctk.CTkLabel(
            header_frame, text=f"Pasa a la versión PRO para acceder a {feature_name}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY, wraplength=480, justify="left"
        )
        lbl_title.pack(padx=20, pady=(0, 16), anchor="w")

        # Contenido / Beneficios
        body_frame = ctk.CTkFrame(self, fg_color="transparent")
        body_frame.grid(row=1, column=0, sticky="nsew", padx=20)
        body_frame.grid_columnconfigure(0, weight=1)

        benefits = [
            "🛡️ Protección en Tiempo Real: Monitoreo continuo de archivos y carpetas.",
            "🧠 Escáner de Memoria RAM: Neutralización inmediata de procesos activos maliciosos.",
            "🔑 Auditoría de Persistencia: Verificación de llaves Run y firmas Authenticode.",
            "🚀 Actualizaciones automáticas prioritarias y soporte extendido."
        ]

        lbl_intro = ctk.CTkLabel(
            body_frame, text="La versión Gratuita incluye análisis manual de disco y cuarentena. Actualiza a PRO para desbloquear toda la suite:",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLOR_TEXT_SECONDARY, wraplength=480, justify="left"
        )
        lbl_intro.pack(anchor="w", pady=(0, 12))

        for ben in benefits:
            lbl_b = ctk.CTkLabel(
                body_frame, text=ben,
                font=ctk.CTkFont(family=FONT_FAMILY, size=12),
                text_color=COLOR_TEXT_PRIMARY, anchor="w", justify="left"
            )
            lbl_b.pack(fill="x", pady=4)

        # Sección de Ingreso de Clave
        key_card = ctk.CTkFrame(body_frame, fg_color=COLOR_CARD, corner_radius=10)
        key_card.pack(fill="x", pady=(16, 0))
        
        ctk.CTkLabel(
            key_card, text="¿Ya tienes una clave de licencia?",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        ).pack(anchor="w", padx=14, pady=(10, 4))

        input_box = ctk.CTkFrame(key_card, fg_color="transparent")
        input_box.pack(fill="x", padx=14, pady=(0, 10))

        self.entry_key = ctk.CTkEntry(
            input_box, placeholder_text="KV-PRO-XXXX-XXXX-XXXX", height=36
        )
        self.entry_key.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_val = ctk.CTkButton(
            input_box, text="Activar", width=90, height=36,
            fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER,
            command=self._on_click_activate
        )
        btn_val.pack(side="left")

        # Botones inferiores
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=16)

        btn_buy = ctk.CTkButton(
            footer_frame, text="💳 Comprar Licencia PRO", height=38,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            command=self._open_buy_link
        )
        btn_buy.pack(side="left", fill="x", expand=True, padx=(0, 8))

        btn_cancel = ctk.CTkButton(
            footer_frame, text="Cerrar", width=90, height=38,
            fg_color=COLOR_CARD, hover_color=COLOR_CARD,
            command=self.destroy
        )
        btn_cancel.pack(side="right")

    def _on_click_activate(self):
        key = self.entry_key.get().strip()
        if key and self.on_activate_callback:
            self.destroy()
            self.on_activate_callback(key)

    def _open_buy_link(self):
        # Abre el endpoint local o URL de compra
        webbrowser.open("http://localhost/Proyecto_Antivirus/billing/create_preference.php")
