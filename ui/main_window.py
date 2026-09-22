import os
import sys
import json
import time
import shutil
import threading
import webbrowser
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, simpledialog, ttk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ui.theme import (
    COLOR_BG, COLOR_SIDEBAR, COLOR_CARD, COLOR_CARD_HOVER,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_DANGER_HOVER,
    COLOR_SUCCESS, COLOR_SUCCESS_HOVER, COLOR_WARNING, COLOR_GOLD,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_TEXT_MUTED, FONT_FAMILY
)
from ui.components import (
    HelpModal, ProgressCard,
    show_alert, ask_confirm, QuarantineDetailModal, format_quarantine_date
)

from core.scanner import (
    TARGET_EXTENSIONS, calculate_sha256, analyze_heuristics,
    analyze_binary_pe, analyze_yara, check_authenticode
)
from core.quarantine import isolate_file, QUARANTINE_DIR
from core.memory import scan_running_processes
from core.persistence import audit_registry
from core.virustotal import check_virustotal_hash
from core.updater import update_signatures_from_cloud
from core.reporter import generate_html_report
from core.tray import SystemTrayManager
from core.context_menu import register_context_menu, unregister_context_menu

SIGNATURES_FILE = os.path.join("data", "signatures.json")
CONFIG_FILE = os.path.join("data", "config.json")


class LiveProtectionHandler(FileSystemEventHandler):
    def __init__(self, app_instance):
        super().__init__()
        self.app = app_instance
        self.last_scanned = {}

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, filepath):
        now = time.time()
        if filepath in self.last_scanned and (now - self.last_scanned[filepath]) < 1.5:
            return
        self.last_scanned[filepath] = now

        ext = os.path.splitext(filepath)[1].lower()
        if ext in TARGET_EXTENSIONS:
            time.sleep(0.3)
            self.app.scan_single_file_live(filepath)


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.config = self.load_config()
        appearance = self.config.get("appearance_mode", "Oscuro")
        ctk.set_appearance_mode("Dark" if appearance == "Oscuro" else "Light")

        self.geometry("1100x720")
        self.minsize(980, 640)
        self.configure(fg_color=COLOR_BG)
        self.title("KILLVirus - NextGen Forensics & EDR")

        # Icono de aplicación
        icon_path = os.path.join("assets", "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self.signatures = self.load_signatures()
        self.vt_api_key = self.config.get("vt_api_key", "")
        self.exclusions = set(self.config.get("exclusions", []))

        self.observer = None
        self.is_monitoring = False
        self.tray = None

        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        if len(sys.argv) > 1:
            target = sys.argv[1].strip()
            if os.path.exists(target):
                self.entry_path.delete(0, "end")
                self.entry_path.insert(0, target)
                if os.path.isdir(target):
                    self.start_scan_thread()
                elif os.path.isfile(target):
                    threading.Thread(target=self.scan_single_file_live, args=(target,), daemon=True).start()

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------- BARRA LATERAL (SIDEBAR) ----------------
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        brand_lbl = ctk.CTkLabel(
            self.sidebar, text="⚔️ KILLVirus",
            font=ctk.CTkFont(family=FONT_FAMILY, size=22, weight="bold"),
            text_color=COLOR_GOLD
        )
        brand_lbl.grid(row=0, column=0, padx=20, pady=(24, 16), sticky="w")

        self.btn_nav_scanner = self._create_sidebar_btn("Análisis de Amenazas", 1, self.show_scanner_view)
        self.btn_nav_tools = self._create_sidebar_btn("Motores del Sistema", 2, self.show_tools_view)
        self.btn_nav_quar = self._create_sidebar_btn("Cuarentena", 3, self.show_quarantine_view)
        self.btn_nav_config = self._create_sidebar_btn("Configuración", 4, self.show_config_view)

        # Botón de Ayuda (?)
        self.btn_help = ctk.CTkButton(
            self.sidebar, text="❓ Guía de Uso (?)", height=36, corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY, anchor="w",
            command=self.open_help_modal
        )
        self.btn_help.grid(row=5, column=0, padx=12, pady=(12, 4), sticky="ew")

        # Selector de Tema (Modo Oscuro / Claro)
        theme_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        theme_box.grid(row=7, column=0, padx=16, pady=(0, 10), sticky="ew")

        lbl_theme = ctk.CTkLabel(
            theme_box, text="Tema:",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLOR_TEXT_SECONDARY
        )
        lbl_theme.pack(side="left", padx=(0, 8))

        saved_mode = self.config.get("appearance_mode", "Oscuro")
        self.opt_theme = ctk.CTkOptionMenu(
            theme_box, values=["Oscuro", "Claro"], height=28, width=110,
            command=self.change_appearance_mode_event,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12)
        )
        self.opt_theme.set(saved_mode)
        self.opt_theme.pack(side="right")

        # Botón de Donaciones / Apoyo al Proyecto
        self.btn_donate = ctk.CTkButton(
            self.sidebar, text="☕ Apoyar el Proyecto", height=32, corner_radius=6,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            fg_color="#eab308", text_color="#18181b", hover_color="#ca8a04",
            command=self.open_donation_modal
        )
        self.btn_donate.grid(row=8, column=0, padx=16, pady=(0, 10), sticky="ew")

        self.lbl_sig_count = ctk.CTkLabel(
            self.sidebar, text=f"Firmas CTI: {len(self.signatures)}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLOR_TEXT_MUTED
        )
        self.lbl_sig_count.grid(row=9, column=0, padx=20, pady=(0, 16), sticky="w")

        # ---------------- CONTENEDOR PRINCIPAL ----------------
        self.container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.views = {}
        self._init_scanner_view()
        self._init_tools_view()
        self._init_quarantine_view()
        self._init_config_view()

        self.show_scanner_view()

    def _create_sidebar_btn(self, text, row, cmd):
        btn = ctk.CTkButton(
            self.sidebar, text=text, height=40, corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=13),
            fg_color="transparent", hover_color=COLOR_CARD,
            text_color=COLOR_TEXT_PRIMARY, anchor="w", command=cmd
        )
        btn.grid(row=row, column=0, padx=12, pady=4, sticky="ew")
        return btn

    def _set_active_tab(self, active_btn):
        for btn in [self.btn_nav_scanner, self.btn_nav_tools, self.btn_nav_quar, self.btn_nav_config]:
            btn.configure(fg_color=COLOR_ACCENT if btn == active_btn else "transparent")
            btn.configure(text_color="#ffffff" if btn == active_btn else COLOR_TEXT_PRIMARY)

    # ================= VISTA 1: ESCÁNER =================
    def _init_scanner_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(3, weight=1)

        # Tarjeta de Entrada
        input_card = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        input_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        input_card.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(input_card, text="Ruta a Inspeccionar / Supervisar", font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"), text_color=COLOR_TEXT_PRIMARY)
        lbl.grid(row=0, column=0, columnspan=3, padx=16, pady=(12, 4), sticky="w")

        self.entry_path = ctk.CTkEntry(input_card, placeholder_text="Seleccione un archivo o carpeta objetivo...", height=36)
        self.entry_path.grid(row=1, column=0, padx=(16, 8), pady=(0, 14), sticky="ew")

        ctk.CTkButton(input_card, text="Carpeta", width=80, height=36, command=self.select_folder).grid(row=1, column=1, padx=(0, 6), pady=(0, 14))
        ctk.CTkButton(input_card, text="Archivo", width=80, height=36, command=self.select_file).grid(row=1, column=2, padx=(0, 16), pady=(0, 14))

        # Barra de Acciones
        actions = ctk.CTkFrame(v, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        actions.grid_columnconfigure((0, 1, 2), weight=1)

        self.btn_scan = ctk.CTkButton(actions, text="Iniciar Escaneo de Disco", height=42, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, command=self.start_scan_thread)
        self.btn_scan.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.btn_live = ctk.CTkButton(actions, text="Protección en Tiempo Real: Inactiva", height=42, fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER, command=self.toggle_live_protection)
        self.btn_live.grid(row=0, column=1, padx=4, sticky="ew")

        self.btn_vt = ctk.CTkButton(actions, text="Consultar VirusTotal", height=42, fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_PRIMARY, command=self.start_vt_thread)
        self.btn_vt.grid(row=0, column=2, padx=(8, 0), sticky="ew")

        # Tarjeta de Progreso con ETA y Archivo Actual Dinámico
        self.progress_card = ProgressCard(v)
        self.progress_card.grid(row=2, column=0, sticky="ew", pady=(0, 12))

        # Consola de Eventos Profesional (Solo Detecciones)
        log_card = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        log_card.grid(row=3, column=0, sticky="nsew")
        log_card.grid_rowconfigure(0, weight=1)
        log_card.grid_columnconfigure(0, weight=1)

        self.log_textbox = ctk.CTkTextbox(log_card, font=ctk.CTkFont(family="Consolas", size=12), text_color="#d1d5db", fg_color="#18191f")
        self.log_textbox.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")
        self.log_textbox.configure(state="disabled")

        self.lbl_status = ctk.CTkLabel(v, text="Sistema listo para operar.", anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLOR_TEXT_SECONDARY)
        self.lbl_status.grid(row=4, column=0, sticky="ew", pady=(6, 0))

        self.views["scanner"] = v

    # ================= VISTA 2: MOTORES DEL SISTEMA =================
    def _init_tools_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure((0, 1), weight=1)

        # RAM
        card_ram = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ram.grid(row=0, column=0, padx=(0, 10), pady=(0, 12), sticky="nsew")
        
        lbl_ram_h = ctk.CTkLabel(card_ram, text="Inspección de Procesos RAM", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY)
        lbl_ram_h.pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ram, text="Examina los binarios cargados en memoria y neutraliza procesos maliciosos activos.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_ram, text="Escanear Memoria RAM", command=self.start_procs_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # Persistencia
        card_pers = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_pers.grid(row=0, column=1, padx=(10, 0), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_pers, text="Auditoría de Registro (Persistencia)", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_pers, text="Verifica claves Run/RunOnce y valida certificados Authenticode de cada programa al inicio.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_pers, text="Auditar Registro de Windows", command=self.start_persistence_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # ThreatFox CTI
        card_upd = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_upd.grid(row=1, column=0, padx=(0, 10), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_upd, text="Actualizador de Firmas CTI", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_upd, text="Descarga el volcado más reciente de hashes maliciosos SHA-256 desde el feed de ThreatFox.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_upd, text="Actualizar Base de Datos", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, command=self.start_update_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # Menú Contextual de Windows
        card_ctx = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ctx.grid(row=1, column=1, padx=(10, 0), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_ctx, text="Integración Shell de Windows", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ctx, text="Añade o remueve la opción de clic derecho en el Explorador de archivos de Windows.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_ctx, text="Configurar Clic Derecho", command=self.manage_context_menu).pack(anchor="w", padx=16, pady=(0, 16))

        self.views["tools"] = v

    # ================= VISTA 3: CUARENTENA MEJORADA (SELECCIÓN MÚLTIPLE) =================
    def _init_quarantine_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(v, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ctk.CTkLabel(top, text="Elementos Aislados en Cuarentena", font=ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(side="left")
        ctk.CTkButton(top, text="Refrescar Lista", width=120, command=self.refresh_quarantine_table).pack(side="right")

        table_frame = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        cols = ("archivo", "tamano", "fecha")
        # Configuración con selectmode="extended" para permitir selección múltiple nativa (Ctrl+Clic / Shift+Clic)
        self.tree_quar = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        self.tree_quar.heading("archivo", text="Archivo Aislado")
        self.tree_quar.heading("tamano", text="Tamaño")
        self.tree_quar.heading("fecha", text="Fecha de Aislamiento")
        self.tree_quar.column("archivo", width=380)
        self.tree_quar.column("tamano", width=110, anchor="center")
        self.tree_quar.column("fecha", width=190, anchor="center")
        self.tree_quar.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        btn_bar = ctk.CTkFrame(v, fg_color="transparent")
        btn_bar.grid(row=2, column=0, sticky="ew", pady=(12, 0))

        # Botones de acción en lote
        ctk.CTkButton(
            btn_bar, text="Seleccionar Todo", width=130,
            fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_PRIMARY,
            command=self.select_all_quarantine
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_bar, text="🔍 Ver Detalle", width=110,
            fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_PRIMARY,
            command=self.show_quarantine_detail
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_bar, text="Restaurar Seleccionados", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER,
            command=self.restore_selected_quarantine
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_bar, text="Eliminar Seleccionados", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER,
            command=self.delete_selected_quarantine
        ).pack(side="left")

        self.views["quarantine"] = v

    # ================= VISTA 4: CONFIGURACIÓN =================
    def _init_config_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)

        # VirusTotal
        card_vt = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_vt.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        ctk.CTkLabel(card_vt, text="Credenciales de VirusTotal API", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))

        box_api = ctk.CTkFrame(card_vt, fg_color="transparent")
        box_api.pack(fill="x", padx=16, pady=(0, 16))
        self.entry_vt_key = ctk.CTkEntry(box_api, height=36, show="*")
        self.entry_vt_key.insert(0, self.vt_api_key)
        self.entry_vt_key.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(box_api, text="Guardar Clave", width=110, height=36, command=self.save_api_key).pack(side="left")

        # Whitelist / Exclusiones
        card_ex = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ex.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(card_ex, text="Lista Blanca / Exclusiones", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ex, text="Las carpetas o rutas especificadas serán ignoradas en todos los escaneos.", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 10))

        self.txt_exclusions = ctk.CTkTextbox(card_ex, height=130, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_exclusions.pack(fill="x", padx=16, pady=(0, 10))
        self.txt_exclusions.insert("end", "\n".join(sorted(self.exclusions)))

        btn_ex_box = ctk.CTkFrame(card_ex, fg_color="transparent")
        btn_ex_box.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkButton(btn_ex_box, text="Añadir Carpeta...", command=self.add_exclusion_folder).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_ex_box, text="Guardar Exclusiones", command=self.save_exclusions).pack(side="left")

        self.views["config"] = v

    # ================= NAVEGACIÓN Y EVENTOS =================
    def show_scanner_view(self):
        self._switch_view("scanner", self.btn_nav_scanner)

    def show_tools_view(self):
        self._switch_view("tools", self.btn_nav_tools)

    def show_quarantine_view(self):
        self._switch_view("quarantine", self.btn_nav_quar)
        self.refresh_quarantine_table()

    def show_config_view(self):
        self._switch_view("config", self.btn_nav_config)

    def _switch_view(self, view_name, nav_button):
        for name, frame in self.views.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()
        self._set_active_tab(nav_button)

    def open_help_modal(self):
        HelpModal(self)

    def open_donation_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title("☕ Apoyar el Proyecto KILLVirus")
        modal.geometry("480x360")
        modal.resizable(False, False)
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)

        modal.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (480 // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (360 // 2)
        modal.geometry(f"480x360+{max(0, x)}+{max(0, y)}")

        container = ctk.CTkFrame(modal, fg_color=COLOR_CARD, corner_radius=12)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        title_lbl = ctk.CTkLabel(
            container,
            text="☕ Apoyar el Proyecto KILLVirus",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLOR_GOLD
        )
        title_lbl.pack(pady=(20, 10), padx=20)

        desc_text = (
            "KILLVirus es una suite de seguridad y análisis forense 100% gratuita "
            "y de código abierto. Si la herramienta te resulta de utilidad y deseas "
            "colaborar con su mantenimiento continuo, cualquier contribución es bienvenida."
        )
        desc_lbl = ctk.CTkLabel(
            container,
            text=desc_text,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLOR_TEXT_SECONDARY,
            wraplength=400,
            justify="center"
        )
        desc_lbl.pack(pady=(0, 20), padx=20)

        btn_cafecito = ctk.CTkButton(
            container,
            text="☕ Donar en Cafecito (Argentina)",
            height=38,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            fg_color="#eab308",
            text_color="#18181b",
            hover_color="#ca8a04",
            command=lambda: webbrowser.open("https://cafecito.app/cristian_dev")
        )
        btn_cafecito.pack(fill="x", padx=30, pady=(0, 10))

        btn_github = ctk.CTkButton(
            container,
            text="⭐ Ver Repositorio en GitHub",
            height=38,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            command=lambda: webbrowser.open("https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR")
        )
        btn_github.pack(fill="x", padx=30, pady=(0, 12))

        btn_close = ctk.CTkButton(
            container,
            text="Cerrar",
            height=32,
            corner_radius=6,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            fg_color="transparent",
            border_width=1,
            border_color=COLOR_TEXT_MUTED,
            text_color=COLOR_TEXT_PRIMARY,
            hover_color=COLOR_CARD_HOVER,
            command=modal.destroy
        )
        btn_close.pack(padx=30, pady=(0, 15))

        modal.grab_set()
        modal.focus_force()

    def change_appearance_mode_event(self, new_mode_str: str):
        mode = "Dark" if new_mode_str == "Oscuro" else "Light"
        ctk.set_appearance_mode(mode)
        self.config["appearance_mode"] = new_mode_str
        self.save_config()

    # ================= LOGS Y ESTADOS =================
    def clear_log(self):
        def _clear():
            self.log_textbox.configure(state="normal")
            self.log_textbox.delete("1.0", "end")
            self.log_textbox.configure(state="disabled")
        self.after(0, _clear)

    def log(self, text):
        def _append():
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", text + "\n")
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")
        self.after(0, _append)

    def set_status(self, text):
        self.after(0, lambda: self.lbl_status.configure(text=text))

    # ================= I/O CONFIG =================
    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_config(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass

    def load_signatures(self):
        if not os.path.exists(SIGNATURES_FILE):
            return {}
        try:
            with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.entry_path.delete(0, "end")
            self.entry_path.insert(0, folder)

    def select_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.entry_path.delete(0, "end")
            self.entry_path.insert(0, file)

    def is_path_excluded(self, path):
        norm_path = os.path.normpath(path).lower()
        for excl in self.exclusions:
            norm_excl = os.path.normpath(excl).lower()
            if norm_path == norm_excl or norm_path.startswith(norm_excl + os.sep):
                return True
        return False

    # ================= ESCÁNER DE DISCO CON CONSOLA LIMPIA Y ETA =================
    def start_scan_thread(self):
        folder = self.entry_path.get().strip()
        if not folder or not os.path.isdir(folder):
            show_alert(self, "Atención", "Seleccione una carpeta válida para inspeccionar.", alert_type="warning")
            return
        self.btn_scan.configure(state="disabled")
        threading.Thread(target=self._run_scan, args=(folder,), daemon=True).start()

    def _run_scan(self, target_dir):
        self.after(0, self.show_scanner_view)
        self.clear_log()
        self.log(f"--- Escaneando directorio: {target_dir} ---")
        self.set_status("Contando archivos para análisis...")

        # 1. Contar total de archivos elegibles
        target_files = []
        for root, _, files in os.walk(target_dir):
            if self.is_path_excluded(root):
                continue
            for file in files:
                filepath = os.path.join(root, file)
                if self.is_path_excluded(filepath):
                    continue
                ext = os.path.splitext(file)[1].lower()
                if ext in TARGET_EXTENSIONS:
                    target_files.append(filepath)

        total_files = len(target_files)
        self.after(0, lambda: self.progress_card.start("Analizando archivos...", total_files))
        self.set_status("Analizando contenido...")

        scanned = 0
        threats = []

        for idx, filepath in enumerate(target_files, 1):
            file = os.path.basename(filepath)
            ext = os.path.splitext(file)[1].lower()
            scanned += 1

            self.after(0, lambda c=scanned, t=total_files, fp=filepath: self.progress_card.update_progress(c, t, fp))

            det_name, det_reason = None, None
            f_hash = calculate_sha256(filepath)

            # Hashes SHA-256
            if f_hash and f_hash in self.signatures:
                det_reason = "Firma SHA-256"
                det_name = self.signatures[f_hash].get("malware_name", "Malware")

            # Reglas YARA
            if not det_name:
                y_id, y_desc = analyze_yara(filepath)
                if y_id:
                    det_reason = f"YARA ({y_id})"
                    det_name = y_desc

            # Heurística
            if not det_name:
                h_id, h_desc = analyze_heuristics(filepath)
                if h_id:
                    det_reason = f"Heurística ({h_id})"
                    det_name = h_desc

            # Análisis PE
            if not det_name:
                pe_id, pe_desc = analyze_binary_pe(filepath)
                if pe_id:
                    det_reason = f"Análisis PE ({pe_id})"
                    det_name = pe_desc

            # Filtro Authenticode
            if det_name and ext in {".exe", ".dll", ".sys"}:
                is_signed, sign_msg = check_authenticode(filepath)
                if is_signed:
                    det_name = None

            # SOLO registrar si hay DETECCIÓN de amenaza
            if det_name:
                self.log(f"[!] DETECCIÓN: {file} | {det_reason}: {det_name}")
                qp = isolate_file(filepath)
                if qp:
                    self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")
                threats.append({
                    "file": file, "path": filepath, "hash": f_hash or "N/A",
                    "reason": f"{det_reason}: {det_name}", "quarantined": qp is not None
                })

        self.log("-" * 50)
        self.log(f"Finalizado: {scanned} inspeccionados, {len(threats)} neutralizados.")
        self.set_status(f"Completado: {len(threats)} detecciones.")
        self.after(0, lambda: self.progress_card.set_complete("Análisis finalizado", scanned))
        self.after(0, lambda: self.btn_scan.configure(state="normal"))

        try:
            rep = generate_html_report(target_dir, scanned, threats)
            self.log(f"[✓] Reporte generado: {os.path.basename(rep)}")
        except Exception as e:
            self.log(f"[x] Error en reporte: {e}")

        if threats:
            self.after(0, lambda: show_alert(
                self, "Amenazas Aisladas",
                f"Se detectaron y aislaron {len(threats)} archivo(s) malicioso(s) en la carpeta de Cuarentena.",
                alert_type="warning"
            ))
        else:
            self.after(0, lambda: show_alert(
                self, "Escaneo Completado",
                f"Análisis finalizado con éxito.\nNo se encontraron amenazas en los {scanned} archivos inspeccionados.",
                alert_type="success"
            ))

    # ================= PROTECCIÓN EN TIEMPO REAL =================
    def toggle_live_protection(self):
        if not self.is_monitoring:
            folder = self.entry_path.get().strip()
            if not folder or not os.path.isdir(folder):
                show_alert(self, "Atención", "Seleccione un directorio válido para supervisar.", alert_type="warning")
                return

            handler = LiveProtectionHandler(self)
            self.observer = Observer()
            self.observer.schedule(handler, folder, recursive=True)
            self.observer.start()

            self.is_monitoring = True
            self.btn_live.configure(text="Protección en Tiempo Real: Activa", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER)
            self.set_status(f"Supervisando: {folder}")
            self.log(f"\n[>>>] SUPERVISIÓN ACTIVA: {folder}")
        else:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
            self.is_monitoring = False
            self.btn_live.configure(text="Protección en Tiempo Real: Inactiva", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
            self.set_status("Supervisión detenida.")
            self.log("[<<<] Supervisión en tiempo real pausada.")

    def scan_single_file_live(self, filepath):
        if not os.path.isfile(filepath) or self.is_path_excluded(filepath):
            return

        filename = os.path.basename(filepath)
        ext = os.path.splitext(filepath)[1].lower()
        f_hash = calculate_sha256(filepath)
        det_name, det_reason = None, None

        if f_hash and f_hash in self.signatures:
            det_reason = "Firma SHA-256"
            det_name = self.signatures[f_hash].get("malware_name", "Malware")

        if not det_name:
            y_id, y_desc = analyze_yara(filepath)
            if y_id:
                det_reason = f"YARA ({y_id})"
                det_name = y_desc

        if not det_name:
            h_id, h_desc = analyze_heuristics(filepath)
            if h_id:
                det_reason = f"Heurística ({h_id})"
                det_name = h_desc

        if not det_name:
            pe_id, pe_desc = analyze_binary_pe(filepath)
            if pe_id:
                det_reason = f"Análisis PE ({pe_id})"
                det_name = pe_desc

        if det_name and ext in {".exe", ".dll", ".sys"}:
            is_signed, sign_msg = check_authenticode(filepath)
            if is_signed:
                return

        if det_name:
            self.log(f"\n[!] ALERTA EN VIVO: {filename} | {det_reason}: {det_name}")
            qp = isolate_file(filepath)
            if qp:
                self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")

    # ================= MÓDULOS DEL SISTEMA: ESCÁNER RAM AUTOMÁTICO =================
    def start_procs_thread(self):
        # 1. Redirigir a la vista de análisis
        self.show_scanner_view()
        # 2. Vaciar texto de búsquedas anteriores obligatoriamente
        self.clear_log()
        # 3. Cambiar la etiqueta de estado
        self.set_status("Escaneando procesos activos en memoria RAM...")
        # 4. Iniciar automáticamente el hilo de psutil
        threading.Thread(target=self._run_procs, daemon=True).start()

    def _run_procs(self):
        self.log("=== INSPECCIONANDO PROCESOS EN MEMORIA RAM ===")
        self.set_status("Escaneando procesos activos en memoria RAM...")

        def _on_ram_progress(cur, tot, item_name):
            self.after(0, lambda c=cur, t=tot, item=item_name: self.progress_card.update_progress(c, t, item))

        self.after(0, lambda: self.progress_card.start("Escaneando procesos activos en RAM...", 100))

        inspected, threats = scan_running_processes(self.signatures, progress_callback=_on_ram_progress)

        for t in threats:
            self.log(f"[!] PROCESO TERMINADO: {t['name']} (PID: {t['pid']}) -> {t['malware']}")

        self.log("-" * 50)
        self.log(f"Inspección de RAM concluida: {inspected} procesos evaluados, {len(threats)} neutralizados.")
        self.set_status("Inspección de RAM finalizada.")
        self.after(0, lambda: self.progress_card.set_complete("Inspección de RAM finalizada", inspected))

        if threats:
            self.after(0, lambda: show_alert(
                self, "Procesos Neutralizados",
                f"Se detectaron y terminaron {len(threats)} proceso(s) malicioso(s) en RAM.",
                alert_type="warning"
            ))
        else:
            self.after(0, lambda: show_alert(
                self, "RAM Limpia",
                f"Se evaluaron {inspected} procesos en ejecución.\nNo se detectaron binarios maliciosos en memoria.",
                alert_type="success"
            ))

    def start_persistence_thread(self):
        self.show_scanner_view()
        self.clear_log()
        self.set_status("Auditando entradas del registro de auto-inicio...")
        threading.Thread(target=self._run_persistence, daemon=True).start()

    def _run_persistence(self):
        self.log("=== AUDITORÍA DE PERSISTENCIA EN REGISTRO DE WINDOWS ===")
        self.set_status("Auditando entradas del registro...")
        self.after(0, lambda: self.progress_card.start("Auditando registro de auto-inicio...", 100))

        total, flagged = audit_registry(self.signatures)

        verified = []
        for item in flagged:
            path = item.get("command", "")
            if os.path.isfile(path):
                is_signed, _ = check_authenticode(path)
                if is_signed:
                    continue
            verified.append(item)

        for item in verified:
            self.log(f"[!] ENTRADA SOSPECHOSA: [{item['label']}] {item['name']}")
            self.log(f"    Ejecutable: {item['command']}")

        self.log("-" * 50)
        self.log(f"Persistencia finalizada: {total} examinadas, {len(verified)} sospechosas.")
        self.set_status("Auditoría de registro concluida.")
        self.after(0, lambda: self.progress_card.set_complete("Auditoría de registro concluida", total))

    def start_vt_thread(self):
        target = self.entry_path.get().strip()
        if not target or not os.path.isfile(target):
            show_alert(self, "Atención", "Seleccione un archivo puntual para consultar en VirusTotal.", alert_type="warning")
            return
        if not self.vt_api_key:
            show_alert(self, "Configuración requerida", "Ingrese su API Key de VirusTotal en la pestaña Configuración.", alert_type="info")
            self.show_config_view()
            return
        threading.Thread(target=self._run_vt, args=(target,), daemon=True).start()

    def _run_vt(self, filepath):
        self.after(0, self.show_scanner_view)
        self.clear_log()
        self.log(f"[*] Consultando VirusTotal: {os.path.basename(filepath)}...")
        self.after(0, lambda: self.progress_card.start("Consultando VirusTotal API...", 1))

        f_hash = calculate_sha256(filepath)
        code, stats, results = check_virustotal_hash(f_hash, self.vt_api_key)

        if code == 200:
            mal = stats.get("malicious", 0)
            total = sum(stats.values())
            if mal > 0:
                self.log(f"[!] DETECCIONES VIRUSTOTAL: {mal}/{total}")
                for eng, res in results.items():
                    if res.get("category") == "malicious":
                        self.log(f"    - {eng}: {res.get('result')}")
            else:
                self.log(f"[✓] Archivo limpio en VirusTotal (0/{total}).")
        elif code == 404:
            self.log("[i] El hash no figura en los registros de VirusTotal.")
        else:
            self.log(f"[x] Error en la API de VirusTotal (Código: {code}).")

        self.after(0, lambda: self.progress_card.set_complete("Consulta VirusTotal finalizada", 1))

    def start_update_thread(self):
        self.show_scanner_view()
        self.clear_log()
        threading.Thread(target=self._run_update, daemon=True).start()

    def _run_update(self):
        self.log("[*] Sincronizando firmas desde ThreatFox...")
        self.after(0, lambda: self.progress_card.start("Sincronizando firmas desde ThreatFox...", 100))

        ok, res, new_sigs = update_signatures_from_cloud(self.signatures)
        if ok:
            self.signatures = new_sigs
            self.after(0, lambda: self.lbl_sig_count.configure(text=f"Firmas CTI: {len(self.signatures)}"))
            self.log(f"[✓] Actualización completada: +{res} firmas añadidas.")
            self.after(0, lambda: show_alert(self, "Actualización Exitosa", f"Se incorporaron {res} nuevas firmas de malware.", alert_type="success"))
        else:
            self.log(f"[!] Error de sincronización: {res}")

        self.after(0, lambda: self.progress_card.set_complete("Actualización de firmas completada", len(self.signatures)))

    def manage_context_menu(self):
        def _on_confirm(ok_choice):
            if ok_choice is True:
                ok, msg = register_context_menu()
                show_alert(self, "Menú Contextual", msg, alert_type="success" if ok else "error")
            elif ok_choice is False:
                ok, msg = unregister_context_menu()
                show_alert(self, "Menú Contextual", msg, alert_type="info" if ok else "error")

        ask_confirm(
            self, "Integración Shell de Windows",
            "¿Desea registrar 'Analizar con KILLVirus' en el menú contextual de clic derecho de Windows?",
            callback=_on_confirm
        )

    # ================= GESTOR DE CUARENTENA MEJORADO =================
    def refresh_quarantine_table(self):
        self.tree_quar.delete(*self.tree_quar.get_children())
        if not os.path.exists(QUARANTINE_DIR):
            return
        for file in os.listdir(QUARANTINE_DIR):
            if file.endswith(".quarantine"):
                p = os.path.join(QUARANTINE_DIR, file)
                sz = f"{round(os.path.getsize(p) / 1024, 2)} KB"
                meta_p = p + ".meta"
                date_str = "Desconocida"
                if os.path.exists(meta_p):
                    try:
                        with open(meta_p, "r", encoding="utf-8") as m:
                            date_str = json.load(m).get("date", "Desconocida")
                    except Exception:
                        pass

                # Formato de fecha legible DD/MM/YYYY HH:MM:SS
                formatted_date = format_quarantine_date(date_str)
                self.tree_quar.insert("", "end", iid=file, values=(file, sz, formatted_date))

    def select_all_quarantine(self):
        children = self.tree_quar.get_children()
        if children:
            self.tree_quar.selection_set(children)

    def show_quarantine_detail(self):
        sel = self.tree_quar.selection()
        if not sel:
            show_alert(self, "Atención", "Seleccione un archivo de la lista para ver su detalle.", alert_type="info")
            return
        item_file = sel[0]
        q_path = os.path.join(QUARANTINE_DIR, item_file)
        QuarantineDetailModal(self, q_path)

    def restore_selected_quarantine(self):
        sel = self.tree_quar.selection()
        if not sel:
            show_alert(self, "Atención", "Seleccione uno o varios archivos para restaurar.", alert_type="info")
            return

        restored_count = 0
        for item_file in sel:
            q_path = os.path.join(QUARANTINE_DIR, item_file)
            meta_p = q_path + ".meta"
            dest = None

            if os.path.exists(meta_p):
                try:
                    with open(meta_p, "r", encoding="utf-8") as m:
                        dest = json.load(m).get("original_path")
                except Exception:
                    pass

            if not dest:
                dest = filedialog.asksaveasfilename(initialfile=item_file.replace(".quarantine", ""))

            if dest:
                try:
                    shutil.move(q_path, dest)
                    if os.path.exists(meta_p):
                        os.remove(meta_p)
                    restored_count += 1
                except Exception as e:
                    show_alert(self, "Error al restaurar", f"No se pudo restaurar {item_file}: {e}", alert_type="error")

        if restored_count > 0:
            show_alert(self, "Restauración Completada", f"Se restauraron {restored_count} archivo(s) a su ubicación original.", alert_type="success")
            self.refresh_quarantine_table()

    def delete_selected_quarantine(self):
        sel = self.tree_quar.selection()
        if not sel:
            show_alert(self, "Atención", "Seleccione uno o varios archivos para eliminar.", alert_type="info")
            return

        def _do_delete(confirmed):
            if not confirmed:
                return
            deleted_count = 0
            for item_file in sel:
                q_path = os.path.join(QUARANTINE_DIR, item_file)
                meta_p = q_path + ".meta"
                try:
                    if os.path.exists(q_path):
                        os.remove(q_path)
                    if os.path.exists(meta_p):
                        os.remove(meta_p)
                    deleted_count += 1
                except Exception as e:
                    show_alert(self, "Error de eliminación", f"No se pudo eliminar {item_file}: {e}", alert_type="error")

            show_alert(self, "Eliminación Completada", f"Se eliminaron {deleted_count} elemento(s) de la cuarentena.", alert_type="success")
            self.refresh_quarantine_table()

        ask_confirm(
            self, "Confirmar Eliminación",
            f"¿Está seguro de eliminar definitivamente los {len(sel)} archivo(s) seleccionados del disco?",
            callback=_do_delete
        )

    # ================= CONFIGURACIÓN =================
    def save_api_key(self):
        key = self.entry_vt_key.get().strip()
        self.vt_api_key = key
        self.config["vt_api_key"] = key
        self.save_config()
        show_alert(self, "Configuración", "API Key de VirusTotal guardada correctamente.", alert_type="success")

    def add_exclusion_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.exclusions.add(os.path.abspath(folder))
            self.txt_exclusions.delete("1.0", "end")
            self.txt_exclusions.insert("end", "\n".join(sorted(self.exclusions)))

    def save_exclusions(self):
        lines = [line.strip() for line in self.txt_exclusions.get("1.0", "end").splitlines() if line.strip()]
        self.exclusions = set(lines)
        self.config["exclusions"] = list(self.exclusions)
        self.save_config()
        show_alert(self, "Configuración", "Lista de exclusiones actualizada correctamente.", alert_type="success")

    # ================= BANDEJA Y CIERRE =================
    def on_closing(self):
        if self.is_monitoring:
            self.withdraw()
            if not self.tray:
                self.tray = SystemTrayManager(
                    on_show_callback=self.show_window,
                    on_exit_callback=self.quit_app
                )
                self.tray.start()
        else:
            self.quit_app()

    def show_window(self):
        self.after(0, self._restore_gui)

    def _restore_gui(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        if self.tray:
            self.tray.stop()
        if self.observer and self.is_monitoring:
            self.observer.stop()
            self.observer.join()
        self.after(0, self.destroy)