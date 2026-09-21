import customtkinter as ctk
from ui.theme import (
    COLOR_CARD, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, FONT_FAMILY
)

class HelpModal(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Guía de Funcionalidades - KILLVirus")
        self.geometry("640x540")
        self.minsize(580, 480)
        self.transient(parent)
        self.grab_set()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Encabezado
        header_frame = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=60)
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            header_frame,
            text="❓ Guía de Funcionalidades KILLVirus",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        title_lbl.pack(padx=20, pady=16, anchor="w")

        # Contenido scrollable
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew", padx=20, pady=16)
        scroll.grid_columnconfigure(0, weight=1)

        features = [
            ("🔍 Escaneo de Disco / Archivos",
             "Realiza un análisis profundo de archivos y carpetas buscando códigos sospechosos. "
             "Utiliza 5 niveles de inspección: comparación de hashes SHA-256 en base de datos local, "
             "reglas de patrones YARA, análisis sintáctico de encabezados PE, motor heurístico y "
             "filtrado por firma digital Authenticode para evitar falsos positivos."),

            ("🛡️ Protección en Tiempo Real (PRO)",
             "Monitorea en segundo plano cualquier archivo creado o modificado en los directorios seleccionados. "
             "Al detectar un archivo ejecutable nuevo, lo escanea instantáneamente antes de que pueda dañar el sistema."),

            ("🧠 Análisis de Memoria RAM activa (PRO)",
             "Inspecciona todos los procesos ejecutándose en la RAM del sistema. "
             "Calcula el hash de los binarios cargados y termina de inmediato cualquier proceso maligno detectado."),

            ("🔑 Auditoría de Persistencia en el Registro (PRO)",
             "Examina las claves de auto-inicio del Registro de Windows (HKEY_CURRENT_USER y HKEY_LOCAL_MACHINE\\Run/RunOnce). "
             "Filtra entradas sospechosas y verifica la firma digital Authenticode de cada programa al inicio."),

            ("🌐 Consulta en VirusTotal",
             "Calcula el hash SHA-256 de un archivo puntual y consulta en tiempo real los servidores de VirusTotal "
             "para saber si más de 70 motores antivirus lo han catalogado como dañino."),

            ("📦 Gestor de Cuarentena",
             "Aísla de forma segura las amenazas detectadas en un contenedor encriptado (.quarantine), "
             "impidiendo su ejecución pero permitiendo restaurar el archivo si es un falso positivo o eliminarlo definitivamente.")
        ]

        for title, desc in features:
            card = ctk.CTkFrame(scroll, fg_color=COLOR_CARD, corner_radius=10)
            card.pack(fill="x", pady=6)

            lbl_t = ctk.CTkLabel(
                card, text=title,
                font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"),
                text_color=COLOR_TEXT_PRIMARY
            )
            lbl_t.pack(anchor="w", padx=14, pady=(12, 4))

            lbl_d = ctk.CTkLabel(
                card, text=desc,
                font=ctk.CTkFont(family=FONT_FAMILY, size=12),
                text_color=COLOR_TEXT_SECONDARY,
                justify="left", wraplength=540
            )
            lbl_d.pack(anchor="w", padx=14, pady=(0, 12))

        # Botón de Cierre
        btn_close = ctk.CTkButton(
            self, text="Entendido", width=120, height=36,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            command=self.destroy
        )
        btn_close.grid(row=2, column=0, pady=(0, 16))
