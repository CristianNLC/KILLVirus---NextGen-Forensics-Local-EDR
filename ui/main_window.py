import os
import sys
import json
import time
import queue
import shutil
import logging
import threading
import webbrowser
from datetime import datetime
import tkinter as tk
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

from core import __app_name__, __version__
from core.exclusions import is_excluded, parse_exclusions
from core.scanner import TARGET_EXTENSIONS, calculate_sha256, check_authenticode
from core.scan_engine import scan_file
from core.signatures import create_signature_store
from core.yara_scanner import HAS_YARA, UNAVAILABLE_REASON
from core.logging_setup import install_excepthook, setup_logging
from core.paths import (
    init_app, is_inside_runtime_dir,
    CONFIG_FILE, SIGNATURES_FILE, SIGNATURES_DB, QUARANTINE_DIR,
)
from core.quarantine import isolate_file
from core.memory import scan_running_processes
from core.persistence import audit_registry, extract_binary_path
from core.virustotal import check_virustotal_hash
from core.updater import update_signatures_from_cloud
from core.reporter import generate_html_report
from core.tray import SystemTrayManager
from core.context_menu import register_context_menu, unregister_context_menu
from core.monitor.watcher import LiveProtectionManager
from core.canary import CanaryManager
from core.startup_audit import list_startup_entries, list_console_processes, terminate_process
from services.scan_service import ScanService

logger = logging.getLogger(__name__)


class LiveProtectionHandler(FileSystemEventHandler):
    """Encola eventos del sistema de archivos y los procesa aparte.

    - No bloquea al observador con sleeps ni con hashing (antes se dormían
      0,3 s dentro del callback y se perdían eventos).
    - Deduplica por ruta con ventana de tiempo.
    - Escucha creación, modificación, cierre y renombrado: renombrar un .exe a
      .txt y volver a .exe ya no evade la detección.
    - Espera a que el archivo termine de escribirse antes de escanearlo.
    """

    def __init__(self, app_instance, dedupe_seconds=2.0):
        super().__init__()
        self.app = app_instance
        self.dedupe_seconds = dedupe_seconds
        self._queue = queue.Queue()
        self._recent = {}
        self._recent_lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self._run, name="killvirus-live", daemon=True
        )

    # --- ciclo de vida ---
    def start(self):
        if not self._worker.is_alive():
            self._worker.start()

    def stop(self):
        self._stop.set()
        self._queue.put(None)

    # --- callbacks de watchdog ---
    def on_created(self, event):
        self._handle(event.src_path, event.is_directory)

    def on_modified(self, event):
        self._handle(event.src_path, event.is_directory)

    def on_moved(self, event):
        self._handle(event.dest_path, event.is_directory)

    def on_closed(self, event):
        self._handle(event.src_path, event.is_directory)

    def _handle(self, filepath, is_directory):
        if is_directory or not filepath:
            return
        if os.path.splitext(filepath)[1].lower() not in TARGET_EXTENSIONS:
            return
        if self._is_duplicate(filepath):
            return
        self._queue.put(filepath)

    def _is_duplicate(self, filepath):
        now = time.monotonic()
        with self._recent_lock:
            last = self._recent.get(filepath)
            if last is not None and (now - last) < self.dedupe_seconds:
                return True
            self._recent[filepath] = now
            # Poda para que el diccionario no crezca sin límite.
            if len(self._recent) > 4096:
                cutoff = now - 60
                self._recent = {p: t for p, t in self._recent.items() if t >= cutoff}
        return False

    def _run(self):
        while not self._stop.is_set():
            filepath = self._queue.get()
            if filepath is None:
                break
            try:
                if is_inside_runtime_dir(filepath):
                    continue
                self._wait_until_stable(filepath)
                self.app.scan_single_file_live(filepath)
            except Exception:
                continue

    @staticmethod
    def _wait_until_stable(filepath, attempts=6, delay=0.25):
        """Espera a que el archivo esté completo y se pueda abrir."""
        last_size = -1
        for _ in range(attempts):
            try:
                size = os.path.getsize(filepath)
                with open(filepath, "rb"):
                    pass
                if size == last_size and size >= 0:
                    return
                last_size = size
            except OSError:
                pass
            time.sleep(delay)


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Logging a archivo (idempotente si ya lo configuró app.pyw).
        setup_logging()
        install_excepthook()

        # Crea/valida las carpetas de datos antes de leer configuración.
        init_app()

        self.config = self.load_config()
        appearance = self.config.get("appearance_mode", "Oscuro")
        ctk.set_appearance_mode("Dark" if appearance == "Oscuro" else "Light")

        # Centrado exacto en pantalla (1040x690)
        app_width = 1040
        app_height = 690
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = max(0, int((screen_width - app_width) / 2))
        y = max(0, int((screen_height - app_height) / 2))
        self.geometry(f"{app_width}x{app_height}+{x}+{y}")
        self.minsize(980, 620)

        self.configure(fg_color=COLOR_BG)
        self.title(f"{__app_name__} - NextGen Forensics & Local EDR v{__version__}")

        # Cargar icono por RUTA ABSOLUTA calculada desde __file__
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ico_path = os.path.join(base_dir, "assets", "icon.ico")
        png_path = os.path.join(base_dir, "assets", "icon.png")

        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass

        if os.path.exists(png_path):
            try:
                img = tk.PhotoImage(file=png_path)
                self.iconphoto(False, img)
            except Exception:
                pass

        self.signatures = self.load_signatures()
        self.signature_store = create_signature_store(
            SIGNATURES_DB,
            json_path=SIGNATURES_FILE,
            use_sqlite=True,
        )
        self.vt_api_key = self.config.get("vt_api_key", "")
        self.exclusions = set(self.config.get("exclusions", []))

        # Servicio de lógica de negocio (desacoplado de la UI).
        self.scan_service = ScanService(self.signature_store, self.config)

        # Protección en tiempo real (watcher + observador desacoplados).
        self.live_protection = None
        self.is_monitoring = False
        self.tray = None

        # Canarios anti-ransomware.
        self.canary_manager = None
        self.canary_alerts = []

        self._build_layout()
        if not HAS_YARA:
            self.log(
                "[!] Motor YARA no disponible en este equipo "
                f"({UNAVAILABLE_REASON}). Se usan firmas SHA-256, heurísticas y análisis PE; "
                "las reglas de data/rules.yar quedan inactivas."
            )
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
        self.sidebar.grid_rowconfigure(10, weight=1)

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
        self.btn_nav_startup = self._create_sidebar_btn("Inicio del Sistema", 5, self.show_startup_view)
        self.btn_nav_canary = self._create_sidebar_btn("🛡️ Canarios Anti-Ransomware", 6, self.show_canary_view)

        # Botón de Ayuda (?)
        self.btn_help = ctk.CTkButton(
            self.sidebar, text="❓ Guía de Uso (?)", height=36, corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY, anchor="w",
            command=self.open_help_modal
        )
        self.btn_help.grid(row=7, column=0, padx=12, pady=(12, 4), sticky="ew")

        # Selector de Tema (Modo Oscuro / Claro)
        theme_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        theme_box.grid(row=9, column=0, padx=16, pady=(0, 10), sticky="ew")

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
        self.btn_donate.grid(row=10, column=0, padx=16, pady=(0, 10), sticky="ew")

        self.lbl_sig_count = ctk.CTkLabel(
            self.sidebar, text=f"Firmas CTI: {len(self.signature_store)}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLOR_TEXT_MUTED
        )
        self.lbl_sig_count.grid(row=9, column=0, padx=20, pady=(0, 4), sticky="w")

        self.lbl_yara_status = ctk.CTkLabel(
            self.sidebar,
            text="Motor YARA: activo" if HAS_YARA else "Motor YARA: no disponible",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLOR_TEXT_MUTED if HAS_YARA else COLOR_WARNING,
        )
        self.lbl_yara_status.grid(row=10, column=0, padx=20, pady=(0, 16), sticky="w")

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
        self._init_startup_view()
        self._init_canary_view()

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
        for btn in [self.btn_nav_scanner, self.btn_nav_tools, self.btn_nav_quar, self.btn_nav_config, self.btn_nav_startup, self.btn_nav_canary]:
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

        # ThreatFox (actualización de firmas)
        card_tf = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_tf.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        ctk.CTkLabel(card_tf, text="Auth-Key de abuse.ch (actualización de firmas)", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLOR_TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(
            card_tf,
            text="Gratis en https://auth.abuse.ch/. Sin esta clave, la app funciona igual pero no descarga firmas nuevas.",
            text_color=COLOR_TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(0, 8))

        box_tf = ctk.CTkFrame(card_tf, fg_color="transparent")
        box_tf.pack(fill="x", padx=16, pady=(0, 16))
        self.entry_tf_key = ctk.CTkEntry(box_tf, height=36, show="*")
        self.entry_tf_key.insert(0, self.config.get("threatfox_auth_key", ""))
        self.entry_tf_key.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(box_tf, text="Guardar Clave", width=110, height=36, command=self.save_threatfox_key).pack(side="left")

        # Whitelist / Exclusiones
        card_ex = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ex.grid(row=2, column=0, sticky="ew")
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

    # ================= VISTA 5: INICIO DEL SISTEMA =================
    def _init_startup_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            v, text="Inicio del Sistema",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        ctk.CTkLabel(
            v,
            text="Revisa qué se ejecuta al prender la PC (Registro Run/RunOnce, carpetas Startup, Servicios y Tareas Programadas). "
                 "Filas en rojo: el archivo no existe o la ruta es inusual.",
            text_color=COLOR_TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
        ).grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # --- Sección: Entradas de inicio ---
        card_start = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_start.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        card_start.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card_start, text="Entradas de Auto-Inicio",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=16, pady=(12, 4), sticky="w")

        btn_start_box = ctk.CTkFrame(card_start, fg_color="transparent")
        btn_start_box.grid(row=1, column=0, padx=16, pady=(0, 8), sticky="ew")
        ctk.CTkButton(
            btn_start_box, text="Refrescar", width=100,
            command=self.refresh_startup_table,
        ).pack(side="left")
        ctk.CTkButton(
            btn_start_box, text="Terminar Seleccionado", width=140, fg_color=COLOR_DANGER,
            hover_color=COLOR_DANGER_HOVER,
            command=self.terminate_selected_startup,
        ).pack(side="left", padx=(10, 0))

        tree_frame = ctk.CTkFrame(card_start, fg_color="transparent")
        tree_frame.grid(row=2, column=0, padx=16, pady=(0, 12), sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        self.tree_startup = ttk.Treeview(
            tree_frame,
            columns=("type", "source", "name", "command", "path", "exists", "risk"),
            show="headings",
            height=10,
        )
        for col, txt, w in [
            ("type", "Tipo", 100),
            ("source", "Origen", 140),
            ("name", "Nombre", 160),
            ("command", "Comando", 320),
            ("path", "Ruta", 260),
            ("exists", "Existe", 55),
            ("risk", "Riesgo", 70),
        ]:
            self.tree_startup.heading(col, text=txt)
            self.tree_startup.column(col, width=w, stretch=(col == "command"))
        self.tree_startup.grid(row=0, column=0, sticky="nsew")

        scroll_start = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_startup.yview)
        scroll_start.grid(row=0, column=1, sticky="ns")
        self.tree_startup.configure(yscrollcommand=scroll_start.set)

        # --- Sección: Procesos de consola ---
        card_console = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_console.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        card_console.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(
            card_console, text="Procesos de Consola Activos",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=16, pady=(12, 4), sticky="w")

        btn_console_box = ctk.CTkFrame(card_console, fg_color="transparent")
        btn_console_box.grid(row=1, column=0, padx=16, pady=(0, 8), sticky="ew")
        ctk.CTkButton(
            btn_console_box, text="Refrescar", width=100,
            command=self.refresh_console_table,
        ).pack(side="left")
        ctk.CTkButton(
            btn_console_box, text="Terminar Seleccionado", width=140, fg_color=COLOR_DANGER,
            hover_color=COLOR_DANGER_HOVER,
            command=self.terminate_selected_console,
        ).pack(side="left", padx=(10, 0))

        tree_console_frame = ctk.CTkFrame(card_console, fg_color="transparent")
        tree_console_frame.grid(row=2, column=0, padx=16, pady=(0, 12), sticky="nsew")
        tree_console_frame.grid_columnconfigure(0, weight=1)
        tree_console_frame.grid_rowconfigure(0, weight=1)

        self.tree_console = ttk.Treeview(
            tree_console_frame,
            columns=("pid", "name", "exe", "cmdline"),
            show="headings",
            height=8,
        )
        for col, txt, w in [
            ("pid", "PID", 60),
            ("name", "Nombre", 120),
            ("exe", "Ejecutable", 250),
            ("cmdline", "Línea de Comandos", 400),
        ]:
            self.tree_console.heading(col, text=txt)
            self.tree_console.column(col, width=w, stretch=(col == "cmdline"))
        self.tree_console.grid(row=0, column=0, sticky="nsew")

        scroll_console = ttk.Scrollbar(tree_console_frame, orient="vertical", command=self.tree_console.yview)
        scroll_console.grid(row=0, column=1, sticky="ns")
        self.tree_console.configure(yscrollcommand=scroll_console.set)

        self.views["startup"] = v

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

    def show_startup_view(self):
        self._switch_view("startup", self.btn_nav_startup)
        self.refresh_startup_table()
        self.refresh_console_table()

    def show_canary_view(self):
        self._switch_view("canary", self.btn_nav_canary)
        self.refresh_canary_view()

    def refresh_startup_table(self):
        self.tree_startup.delete(*self.tree_startup.get_children())
        try:
            entries = list_startup_entries()
        except Exception as e:
            self.log(f"[x] Error listando inicio: {e}")
            return
        for e in entries:
            risk = self._startup_risk(e)
            self.tree_startup.insert(
                "", "end",
                values=(
                    e.get("type", ""),
                    f"{e['hive']} / {e['source']}" if e.get('hive') else e['source'],
                    e['name'],
                    e['command'],
                    e.get('path') or "",
                    "Sí" if e.get('exists') else "No",
                    risk,
                ),
                tags=("risk",) if risk == "Alto" else (),
            )
        self.tree_startup.tag_configure("risk", foreground=COLOR_DANGER)

    def _startup_risk(self, entry: dict) -> str:
        """Calcula nivel de riesgo de una entrada de inicio."""
        path = entry.get("path") or ""
        command = entry.get("command", "").lower()
        name = entry.get("name", "").lower()
        source = entry.get("source", "").lower()

        # Si el archivo no existe, entrada rota o posible malware ya borrado
        if not entry.get("exists") and path:
            return "Alto"

        # Rutas inusuales (temp, appdata local temp, programdata)
        suspicious_keywords = [
            "temp", "appdata\\local\\temp", "programdata",
            "powershell", "wscript", "cscript", "cmd.exe /c",
        ]
        lower_command = command
        lower_path = path.lower()
        for kw in suspicious_keywords:
            if kw in lower_command or kw in lower_path:
                return "Alto"

        # Tareas programadas con triggers de inicio/logon son medio riesgo
        if entry.get("type") == "Tarea":
            trigger = (entry.get("trigger") or "").lower()
            if any(t in trigger for t in ("inicio", "logon", "boot", "startup")):
                return "Medio"

        return "Bajo"

    def refresh_console_table(self):
        self.tree_console.delete(*self.tree_console.get_children())
        try:
            procs = list_console_processes()
        except Exception as e:
            self.log(f"[x] Error listando consolas: {e}")
            return
        for p in procs:
            self.tree_console.insert(
                "", "end",
                values=(p['pid'], p['name'], p['exe'] or "", p['cmdline'] or ""),
            )

    def _confirm_terminate(self, pid, name, callback):
        def _do(confirmed):
            if confirmed:
                ok = terminate_process(pid)
                if ok:
                    self.log(f"[✓] Proceso terminado: {name} (PID {pid})")
                else:
                    self.log(f"[x] No se pudo terminar: {name} (PID {pid})")
                callback()
        ask_confirm(
            self, "Terminar Proceso",
            f"¿Está seguro de terminar el proceso {name} (PID {pid})?",
            callback=_do,
        )

    def terminate_selected_startup(self):
        sel = self.tree_startup.selection()
        if not sel:
            show_alert(self, "Atención", "Seleccione una entrada de inicio.", alert_type="warning")
            return
        item = self.tree_startup.item(sel[0])
        entry_type = item["values"][0]
        name = item["values"][2]
        command = item["values"][3]
        path = item["values"][4]

        if entry_type == "Servicio":
            show_alert(
                self, "No disponible",
                "Los servicios de Windows no se pueden terminar desde aquí. "
                "Usá 'services.msc' para detenerlos.",
                alert_type="info",
            )
            return
        if entry_type == "Tarea":
            show_alert(
                self, "No disponible",
                "Las tareas programadas no se pueden eliminar desde aquí. "
                "Usá el Programador de Tareas de Windows.",
                alert_type="info",
            )
            return

        # Para entradas de registro/carpeta: intentar terminar el proceso si está corriendo
        import psutil
        found = False
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                exe = proc.info.get('exe') or ""
                if exe and os.path.normcase(exe) == os.path.normcase(path):
                    self._confirm_terminate(proc.info['pid'], name, self.refresh_startup_table)
                    found = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        if not found:
            show_alert(
                self, "Información",
                f"No se encontró el proceso '{name}' en ejecución. "
                "La entrada de inicio seguirá activa al próximo reinicio hasta que la deshabilites.",
                alert_type="info",
            )

    def terminate_selected_console(self):
        sel = self.tree_console.selection()
        if not sel:
            show_alert(self, "Atención", "Seleccione un proceso de consola.", alert_type="warning")
            return
        item = self.tree_console.item(sel[0])
        pid = item["values"][0]
        name = item["values"][1]
        self._confirm_terminate(pid, name, self.refresh_console_table)

    # ================= VISTA 6: CANARIOS ANTI-RANSOMWARE =================
    def _init_canary_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            v, text="🛡️ Canarios Anti-Ransomware",
            font=ctk.CTkFont(family=FONT_FAMILY, size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        ctk.CTkLabel(
            v,
            text="Archivos cebo en carpetas sensibles del usuario. Si se modifican, renombran o borran, "
                 "es fuerte indicio de ransomware en acción.",
            text_color=COLOR_TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
        ).grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # --- Botones de acción ---
        btn_box = ctk.CTkFrame(v, fg_color="transparent")
        btn_box.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.btn_canary_install = ctk.CTkButton(
            btn_box, text="Instalar Canarios", width=140,
            command=self.install_canaries,
        )
        self.btn_canary_install.pack(side="left", padx=(0, 10))

        self.btn_canary_verify = ctk.CTkButton(
            btn_box, text="Verificar Integridad", width=140,
            command=self.verify_canaries,
        )
        self.btn_canary_verify.pack(side="left", padx=(0, 10))

        self.btn_canary_monitor = ctk.CTkButton(
            btn_box, text="Activar Monitoreo", width=140,
            command=self.toggle_canary_monitoring,
        )
        self.btn_canary_monitor.pack(side="left")

        # --- Tabla de canarios ---
        tree_frame = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        tree_frame.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        self.tree_canary = ttk.Treeview(
            tree_frame,
            columns=("name", "path", "status", "hash"),
            show="headings",
            height=10,
        )
        for col, txt, w in [
            ("name", "Nombre", 150),
            ("path", "Ruta", 400),
            ("status", "Estado", 100),
            ("hash", "SHA-256", 80),
        ]:
            self.tree_canary.heading(col, text=txt)
            self.tree_canary.column(col, width=w, stretch=(col == "path"))
        self.tree_canary.grid(row=0, column=0, sticky="nsew")

        scroll_canary = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_canary.yview)
        scroll_canary.grid(row=0, column=1, sticky="ns")
        self.tree_canary.configure(yscrollcommand=scroll_canary.set)

        # --- Tabla de alertas ---
        ctk.CTkLabel(
            v, text="Alertas de Canario",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
        ).grid(row=4, column=0, padx=20, pady=(16, 4), sticky="w")

        alert_frame = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        alert_frame.grid(row=5, column=0, padx=20, pady=(0, 20), sticky="nsew")
        alert_frame.grid_columnconfigure(0, weight=1)
        alert_frame.grid_rowconfigure(0, weight=1)
        v.grid_rowconfigure(5, weight=1)

        self.tree_canary_alerts = ttk.Treeview(
            alert_frame,
            columns=("timestamp", "name", "event", "process"),
            show="headings",
            height=6,
        )
        for col, txt, w in [
            ("timestamp", "Fecha/Hora", 160),
            ("name", "Canario", 150),
            ("event", "Evento", 100),
            ("process", "Proceso", 200),
        ]:
            self.tree_canary_alerts.heading(col, text=txt)
            self.tree_canary_alerts.column(col, width=w, stretch=(col == "process"))
        self.tree_canary_alerts.grid(row=0, column=0, sticky="nsew")

        scroll_alerts = ttk.Scrollbar(alert_frame, orient="vertical", command=self.tree_canary_alerts.yview)
        scroll_alerts.grid(row=0, column=1, sticky="ns")
        self.tree_canary_alerts.configure(yscrollcommand=scroll_alerts.set)

        self.views["canary"] = v

    def refresh_canary_view(self):
        self.tree_canary.delete(*self.tree_canary.get_children())
        if not self.canary_manager:
            self.tree_canary.insert("", "end", values=("—", "No instalados", "—", ""))
            return
        results = self.canary_manager.verify()
        for p in self.canary_manager.canary_paths:
            name = os.path.basename(p)
            ok = results.get(p, False)
            status = "OK" if ok else "⚠️ ALTERADO"
            h = self.canary_manager._hashes.get(p, "")[:16] + "..."
            self.tree_canary.insert(
                "", "end",
                values=(name, p, status, h),
                tags=("alert",) if not ok else (),
            )
        self.tree_canary.tag_configure("alert", foreground=COLOR_DANGER)

        # Alertas
        self.tree_canary_alerts.delete(*self.tree_canary_alerts.get_children())
        for a in self.canary_alerts:
            proc = a.process_name or a.process_exe or "desconocido"
            self.tree_canary_alerts.insert(
                "", "end",
                values=(a.timestamp, a.canary_name, a.event, proc),
            )

    def install_canaries(self):
        if not self.canary_manager:
            self.canary_manager = CanaryManager(on_alert=self._on_canary_alert)
        installed = self.canary_manager.install()
        self.log(f"[✓] Canarios instalados: {len(installed)} archivos")
        self.refresh_canary_view()

    def verify_canaries(self):
        if not self.canary_manager or not self.canary_manager.canary_paths:
            show_alert(self, "Atención", "Primero instalá los canarios.", alert_type="warning")
            return
        results = self.canary_manager.verify()
        altered = [p for p, ok in results.items() if not ok]
        if altered:
            self.log(f"[!] CANARIOS ALTERADOS: {len(altered)} archivo(s) modificado(s)")
            for p in altered:
                self.log(f"    - {os.path.basename(p)}: {p}")
            show_alert(
                self, "Alerta de Ransomware",
                f"Se detectaron {len(altered)} canario(s) alterado(s). "
                "Esto puede indicar cifrado de archivos en curso.",
                alert_type="warning",
            )
        else:
            self.log("[✓] Todos los canarios están íntegros")
            show_alert(self, "Canarios OK", "Todos los archivos canario están íntegros.", alert_type="success")
        self.refresh_canary_view()

    def toggle_canary_monitoring(self):
        if not self.canary_manager:
            show_alert(self, "Atención", "Primero instalá los canarios.", alert_type="warning")
            return
        if self.canary_manager._thread and self.canary_manager._thread.is_alive():
            self.canary_manager.stop_monitoring()
            self.btn_canary_monitor.configure(text="Activar Monitoreo", fg_color=COLOR_ACCENT)
            self.log("[i] Monitoreo de canarios detenido")
        else:
            self.canary_manager.start_monitoring()
            self.btn_canary_monitor.configure(text="Detener Monitoreo", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
            self.log("[i] Monitoreo de canarios activado")

    def _on_canary_alert(self, alert):
        self.canary_alerts.append(alert)
        self.log(
            f"[!] CANARIO ALERT: {alert.canary_name} | {alert.event} | "
            f"Proceso: {alert.process_name or 'desconocido'} (PID {alert.process_pid})"
        )
        # Refrescar si la vista está visible
        try:
            self.refresh_canary_view()
        except Exception:
            pass

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
        modal.geometry("480x340")
        modal.resizable(False, False)
        modal.configure(fg_color=COLOR_BG)
        modal.transient(self)

        modal.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (480 // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (340 // 2)
        modal.geometry(f"480x340+{max(0, x)}+{max(0, y)}")

        container = ctk.CTkFrame(modal, fg_color=COLOR_CARD, corner_radius=12)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        title_lbl = ctk.CTkLabel(
            container,
            text="☕ Apoyar el Proyecto KILLVirus",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLOR_GOLD
        )
        title_lbl.pack(pady=(16, 8), padx=20)

        desc_text = (
            "KILLVirus es una solución EDR y forense 100% gratuita "
            "y de código abierto. Si la herramienta te resulta útil y deseas "
            "colaborar con su desarrollo, tu apoyo es muy valioso."
        )
        desc_lbl = ctk.CTkLabel(
            container,
            text=desc_text,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLOR_TEXT_SECONDARY,
            wraplength=410,
            justify="center"
        )
        desc_lbl.pack(pady=(0, 16), padx=20)

        btn_cafecito = ctk.CTkButton(
            container,
            text="☕ Apoyar en Cafecito (cafecito.app/cristian_dev)",
            height=36,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            fg_color="#eab308",
            text_color="#18181b",
            hover_color="#ca8a04",
            command=lambda: webbrowser.open("https://cafecito.app/cristian_dev")
        )
        btn_cafecito.pack(fill="x", padx=30, pady=(0, 10))

        btn_github = ctk.CTkButton(
            container,
            text="⭐ Repositorio en GitHub",
            height=36,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            command=lambda: webbrowser.open("https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR")
        )
        btn_github.pack(fill="x", padx=30)

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
                # utf-8-sig tolera el BOM que dejan algunos editores (Notepad,
                # PowerShell) sin romper la carga de exclusiones y claves.
                with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
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
        return is_excluded(path, list(self.exclusions))

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

        def _on_progress(scanned, total, current_file):
            self.after(0, lambda c=scanned, t=total, fp=current_file: self.progress_card.update_progress(c, t, fp))

        self.after(0, lambda: self.progress_card.start("Analizando archivos...", 0))
        self.set_status("Analizando contenido...")

        result = self.scan_service.scan_folder(target_dir, progress_cb=_on_progress)
        scanned = result["scanned"]
        threats = result["threats"]

        self.log("-" * 50)
        self.log(f"Finalizado: {scanned} inspeccionados, {len(threats)} neutralizados.")
        self.set_status(f"Completado: {len(threats)} detecciones.")
        self.after(0, lambda: self.progress_card.set_complete("Análisis finalizado", scanned))
        self.after(0, lambda: self.btn_scan.configure(state="normal"))

        try:
            rep = self.scan_service.generate_report(target_dir, scanned, threats)
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

            self.live_protection = LiveProtectionManager(
                self.signature_store,
                on_detect=self._on_live_detect,
            )
            self.live_protection.start(folder)

            self.is_monitoring = True
            self.btn_live.configure(text="Protección en Tiempo Real: Activa", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER)
            self.set_status(f"Supervisando: {folder}")
            self.log(f"\n[>>>] SUPERVISIÓN ACTIVA: {folder}")
        else:
            if self.live_protection:
                self.live_protection.stop()
                self.live_protection = None
            self.is_monitoring = False
            self.btn_live.configure(text="Protección en Tiempo Real: Inactiva", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
            self.set_status("Supervisión detenida.")
            self.log("[<<<] Supervisión en tiempo real pausada.")

    def _on_live_detect(self, filepath, detection):
        """Callback del watcher: se ejecuta en el hilo trabajador de protección."""
        filename = os.path.basename(filepath)
        self.log(f"\n[!] ALERTA EN VIVO: {filename} | {detection.reason}: {detection.name}")
        qp = self.scan_service.quarantine_file(filepath, detection)
        if qp:
            self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")
        return detection

    def scan_single_file_live(self, filepath):
        if not os.path.isfile(filepath) or self.is_path_excluded(filepath):
            return None
        if is_inside_runtime_dir(filepath):
            return None

        detection = self.scan_service.scan_file_live(filepath)
        if detection is None:
            return None

        filename = os.path.basename(filepath)
        self.log(f"\n[!] ALERTA EN VIVO: {filename} | {detection.reason}: {detection.name}")
        qp = self.scan_service.quarantine_file(filepath, detection)
        if qp:
            self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")
        return detection

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

        inspected, threats = self.scan_service.scan_processes(progress_callback=_on_ram_progress)

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

        total, flagged = self.scan_service.audit_persistence()

        verified = []
        for item in flagged:
            # Una firma válida solo descarta indicios débiles (ruta inusual /
            # heurística). Un match de hash sigue siendo malware aunque el
            # binario esté firmado (certificado robado o LOLBin firmado).
            if not item.get("signature_match"):
                path = extract_binary_path(item.get("command", ""))
                if path and os.path.isfile(path) and check_authenticode(path)[0]:
                    continue
            verified.append(item)

        for item in verified:
            self.log(f"[!] ENTRADA SOSPECHOSA: [{item['label']}] {item['name']}")
            self.log(f"    Ejecutable: {item['command']}")
            for reason in item.get("reasons", []):
                self.log(f"    Motivo: {reason}")

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

        code, stats, results = self.scan_service.check_virustotal(filepath, self.vt_api_key)

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

        ok, res, new_sigs = self.scan_service.update_signatures()
        if ok:
            count, added = self.scan_service.apply_updated_signatures(new_sigs)
            self.after(0, lambda: self.lbl_sig_count.configure(text=f"Firmas CTI: {count}"))
            self.log(f"[✓] Actualización completada: +{added} firmas añadidas.")
            self.after(0, lambda: show_alert(self, "Actualización Exitosa", f"Se incorporaron {added} nuevas firmas de malware.", alert_type="success"))
        else:
            self.log(f"[!] Error de sincronización: {res}")
            self.after(0, lambda: show_alert(
                self, "No se pudo actualizar",
                f"{res}\n\nPodés obtener un Auth-Key gratuito en https://auth.abuse.ch/ y guardarlo en Configuración.",
                alert_type="warning"
            ))

        self.after(0, lambda: self.progress_card.set_complete("Actualización de firmas completada", len(self.signature_store)))

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

    def save_threatfox_key(self):
        key = self.entry_tf_key.get().strip()
        self.config["threatfox_auth_key"] = key
        self.save_config()
        show_alert(self, "Configuración", "Auth-Key de abuse.ch guardada correctamente.", alert_type="success")

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
        if self.live_handler:
            self.live_handler.stop()
            self.live_handler = None
        if self.observer and self.is_monitoring:
            self.observer.stop()
            self.observer.join()
        self.after(0, self.destroy)