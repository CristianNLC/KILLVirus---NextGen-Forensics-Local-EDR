import os
import sys
import json
import shutil
import threading
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog, ttk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ui.theme import (
    COLOR_BG_DARK, COLOR_SIDEBAR, COLOR_CARD, COLOR_CARD_HOVER,
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_DANGER_HOVER,
    COLOR_SUCCESS, COLOR_SUCCESS_HOVER, COLOR_WARNING,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_TEXT_MUTED, FONT_FAMILY
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
        import time
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

        ctk.set_appearance_mode("Dark")
        self.title("KILLVirus - NextGen Forensics & EDR")
        self.geometry("1080x700")
        self.minsize(980, 620)
        self.configure(fg_color=COLOR_BG_DARK)

        # Vincular icono oficial en la ventana
        icon_path = os.path.join("assets", "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self.signatures = self.load_signatures()
        self.config = self.load_config()
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
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        brand_lbl = ctk.CTkLabel(
            self.sidebar, text="⚔️ KILLVirus",
            font=ctk.CTkFont(family=FONT_FAMILY, size=20, weight="bold"),
            text_color="#eab308"
        )
        brand_lbl.grid(row=0, column=0, padx=20, pady=(24, 20), sticky="w")

        self.btn_nav_scanner = self._create_sidebar_btn("Análisis de Amenazas", 1, self.show_scanner_view)
        self.btn_nav_tools = self._create_sidebar_btn("Motores del Sistema", 2, self.show_tools_view)
        self.btn_nav_quar = self._create_sidebar_btn("Cuarentena", 3, self.show_quarantine_view)
        self.btn_nav_config = self._create_sidebar_btn("Configuración", 4, self.show_config_view)

        self.lbl_sig_count = ctk.CTkLabel(
            self.sidebar, text=f"Firmas: {len(self.signatures)}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLOR_TEXT_MUTED
        )
        self.lbl_sig_count.grid(row=6, column=0, padx=20, pady=(0, 16), sticky="w")

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
            anchor="w", command=cmd
        )
        btn.grid(row=row, column=0, padx=12, pady=4, sticky="ew")
        return btn

    def _set_active_tab(self, active_btn):
        for btn in [self.btn_nav_scanner, self.btn_nav_tools, self.btn_nav_quar, self.btn_nav_config]:
            btn.configure(fg_color=COLOR_ACCENT if btn == active_btn else "transparent")

    # ================= VISTA 1: ESCÁNER =================
    def _init_scanner_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(2, weight=1)

        # Tarjeta de Entrada
        input_card = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        input_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        input_card.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(input_card, text="Ruta a Inspeccionar / Supervisar", font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"))
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

        self.btn_vt = ctk.CTkButton(actions, text="Consultar VirusTotal", height=42, fg_color=COLOR_CARD, hover_color=COLOR_CARD_HOVER, command=self.start_vt_thread)
        self.btn_vt.grid(row=0, column=2, padx=(8, 0), sticky="ew")

        # Tarjeta Consola de Eventos
        log_card = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        log_card.grid(row=2, column=0, sticky="nsew")
        log_card.grid_rowconfigure(0, weight=1)
        log_card.grid_columnconfigure(0, weight=1)

        self.log_textbox = ctk.CTkTextbox(log_card, font=ctk.CTkFont(family="Consolas", size=12), text_color="#d1d5db", fg_color="#18191f")
        self.log_textbox.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")
        self.log_textbox.configure(state="disabled")

        self.lbl_status = ctk.CTkLabel(v, text="Sistema listo para operar.", anchor="w", font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLOR_TEXT_SECONDARY)
        self.lbl_status.grid(row=3, column=0, sticky="ew", pady=(6, 0))

        self.views["scanner"] = v

    # ================= VISTA 2: MOTORES DEL SISTEMA =================
    def _init_tools_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure((0, 1), weight=1)

        # RAM
        card_ram = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ram.grid(row=0, column=0, padx=(0, 10), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_ram, text="Inspección de Procesos (RAM)", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ram, text="Examina los binarios cargados en memoria y neutraliza procesos maliciosos activos.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_ram, text="Escanear Memoria RAM", command=self.start_procs_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # Persistencia
        card_pers = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_pers.grid(row=0, column=1, padx=(10, 0), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_pers, text="Auditoría de Registro (Persistencia)", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_pers, text="Verifica claves Run/RunOnce y valida certificados Authenticode de cada programa al inicio.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_pers, text="Auditar Registro de Windows", command=self.start_persistence_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # ThreatFox CTI
        card_upd = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_upd.grid(row=1, column=0, padx=(0, 10), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_upd, text="Actualizador de Firmas CTI", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_upd, text="Descarga el volcado más reciente de hashes maliciosos SHA-256 desde el feed de ThreatFox.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_upd, text="Actualizar Base de Datos", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, command=self.start_update_thread).pack(anchor="w", padx=16, pady=(0, 16))

        # Menú Contextual de Windows
        card_ctx = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ctx.grid(row=1, column=1, padx=(10, 0), pady=(0, 12), sticky="nsew")
        ctk.CTkLabel(card_ctx, text="Integración Shell de Windows", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ctx, text="Añade o remueve la opción de clic derecho en el Explorador de archivos de Windows.", wraplength=340, justify="left", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 14))
        ctk.CTkButton(card_ctx, text="Configurar Clic Derecho", command=self.manage_context_menu).pack(anchor="w", padx=16, pady=(0, 16))

        self.views["tools"] = v

    # ================= VISTA 3: CUARENTENA =================
    def _init_quarantine_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)
        v.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(v, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ctk.CTkLabel(top, text="Elementos Aislados en Cuarentena", font=ctk.CTkFont(family=FONT_FAMILY, size=15, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="Refrescar Lista", width=120, command=self.refresh_quarantine_table).pack(side="right")

        table_frame = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        cols = ("archivo", "tamano", "fecha")
        self.tree_quar = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_quar.heading("archivo", text="Archivo Aislado")
        self.tree_quar.heading("tamano", text="Tamaño")
        self.tree_quar.heading("fecha", text="Fecha de Aislamiento")
        self.tree_quar.column("archivo", width=420)
        self.tree_quar.column("tamano", width=100, anchor="center")
        self.tree_quar.column("fecha", width=180, anchor="center")
        self.tree_quar.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        btn_bar = ctk.CTkFrame(v, fg_color="transparent")
        btn_bar.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        ctk.CTkButton(btn_bar, text="Restaurar a Destino Original", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, command=self.restore_quarantined_file).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_bar, text="Eliminar de Forma Permanente", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER, command=self.delete_quarantined_file).pack(side="left")

        self.views["quarantine"] = v

    # ================= VISTA 4: CONFIGURACIÓN =================
    def _init_config_view(self):
        v = ctk.CTkFrame(self.container, fg_color="transparent")
        v.grid_columnconfigure(0, weight=1)

        # VirusTotal
        card_vt = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_vt.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        ctk.CTkLabel(card_vt, text="Credenciales de VirusTotal API", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        
        box_api = ctk.CTkFrame(card_vt, fg_color="transparent")
        box_api.pack(fill="x", padx=16, pady=(0, 16))
        self.entry_vt_key = ctk.CTkEntry(box_api, height=36, show="*")
        self.entry_vt_key.insert(0, self.vt_api_key)
        self.entry_vt_key.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(box_api, text="Guardar Clave", width=110, height=36, command=self.save_api_key).pack(side="left")

        # Whitelist / Exclusiones
        card_ex = ctk.CTkFrame(v, fg_color=COLOR_CARD, corner_radius=12)
        card_ex.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(card_ex, text="Lista Blanca / Exclusiones", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(card_ex, text="Las carpetas o rutas especificadas serán ignoradas en todos los escaneos.", text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(0, 10))

        self.txt_exclusions = ctk.CTkTextbox(card_ex, height=130, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_exclusions.pack(fill="x", padx=16, pady=(0, 10))
        self.txt_exclusions.insert("end", "\n".join(sorted(self.exclusions)))

        btn_ex_box = ctk.CTkFrame(card_ex, fg_color="transparent")
        btn_ex_box.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkButton(btn_ex_box, text="Añadir Carpeta...", command=self.add_exclusion_folder).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_ex_box, text="Guardar Exclusiones", command=self.save_exclusions).pack(side="left")

        self.views["config"] = v

    # ================= NAVEGACIÓN =================
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

    # ================= LOGS Y ESTADOS =================
    def log(self, text):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", text + "\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def set_status(self, text):
        self.lbl_status.configure(text=text)

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

    # ================= ESCÁNER DE DISCO =================
    def start_scan_thread(self):
        folder = self.entry_path.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Atención", "Seleccione una carpeta válida para inspeccionar.")
            return
        self.btn_scan.configure(state="disabled")
        threading.Thread(target=self._run_scan, args=(folder,), daemon=True).start()

    def _run_scan(self, target_dir):
        self.show_scanner_view()
        self.log(f"--- Escaneando directorio: {target_dir} ---")
        self.set_status("Analizando archivos...")
        scanned = 0
        threats = []

        for root, _, files in os.walk(target_dir):
            if self.is_path_excluded(root):
                continue

            for file in files:
                filepath = os.path.join(root, file)
                if self.is_path_excluded(filepath):
                    continue

                ext = os.path.splitext(file)[1].lower()
                if ext in TARGET_EXTENSIONS:
                    scanned += 1
                    det_name, det_reason = None, None
                    f_hash = calculate_sha256(filepath)

                    # 1. Hashes SHA-256
                    if f_hash and f_hash in self.signatures:
                        det_reason = "Firma SHA-256"
                        det_name = self.signatures[f_hash].get("malware_name", "Malware")

                    # 2. Reglas YARA
                    if not det_name:
                        y_id, y_desc = analyze_yara(filepath)
                        if y_id:
                            det_reason = f"YARA ({y_id})"
                            det_name = y_desc

                    # 3. Heurística
                    if not det_name:
                        h_id, h_desc = analyze_heuristics(filepath)
                        if h_id:
                            det_reason = f"Heurística ({h_id})"
                            det_name = h_desc

                    # 4. Análisis PE
                    if not det_name:
                        pe_id, pe_desc = analyze_binary_pe(filepath)
                        if pe_id:
                            det_reason = f"Análisis PE ({pe_id})"
                            det_name = pe_desc

                    # 5. Filtro Authenticode (mitigación de falsos positivos)
                    if det_name and ext in {".exe", ".dll", ".sys"}:
                        is_signed, sign_msg = check_authenticode(filepath)
                        if is_signed:
                            self.log(f"[CONFIANZA] {file} firmado válidamente ({sign_msg}). Falso positivo omitido.")
                            det_name = None

                    if det_name:
                        self.log(f"[!] DETECCIÓN: {file} | {det_reason}: {det_name}")
                        qp = isolate_file(filepath)
                        if qp:
                            self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")
                        threats.append({
                            "file": file, "path": filepath, "hash": f_hash or "N/A",
                            "reason": f"{det_reason}: {det_name}", "quarantined": qp is not None
                        })
                    else:
                        self.log(f"[OK] {file}")

        self.log("-" * 50)
        self.log(f"Finalizado: {scanned} inspeccionados, {len(threats)} neutralizados.")
        self.set_status(f"Completado: {len(threats)} detecciones.")
        self.btn_scan.configure(state="normal")

        try:
            rep = generate_html_report(target_dir, scanned, threats)
            self.log(f"[✓] Reporte generado: {os.path.basename(rep)}")
        except Exception as e:
            self.log(f"[x] Error en reporte: {e}")

        if threats:
            messagebox.showwarning("Amenazas aisladas", f"Se detectaron y aislaron {len(threats)} archivo(s).")
        else:
            messagebox.showinfo("Limpio", "No se encontraron anomalías en la ruta analizada.")

    # ================= PROTECCIÓN EN TIEMPO REAL =================
    def toggle_live_protection(self):
        if not self.is_monitoring:
            folder = self.entry_path.get().strip()
            if not folder or not os.path.isdir(folder):
                messagebox.showwarning("Atención", "Seleccione un directorio válido para supervisar.")
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
                self.log(f"[Monitor Confiable] {filename} verificado por firma digital ({sign_msg}).")
                return

        if det_name:
            self.log(f"\n[!] ALERTA EN VIVO: {filename} | {det_reason}: {det_name}")
            qp = isolate_file(filepath)
            if qp:
                self.log(f"    [+] Aislado en cuarentena: {os.path.basename(qp)}")
        else:
            self.log(f"[Monitor OK] {filename}")

    # ================= MÓDULOS DEL SISTEMA =================
    def start_procs_thread(self):
        self.show_scanner_view()
        threading.Thread(target=self._run_procs, daemon=True).start()

    def _run_procs(self):
        self.log("\n=== INSPECCIONANDO PROCESOS EN RAM ===")
        self.set_status("Examinando procesos activos...")
        inspected, threats = scan_running_processes(self.signatures)
        for t in threats:
            self.log(f"[!] PROCESO TERMINADO: {t['name']} (PID: {t['pid']}) -> {t['malware']}")
        self.log(f"RAM concluida: {inspected} evaluados, {len(threats)} neutralizados.")
        self.set_status("Inspección de RAM finalizada.")

    def start_persistence_thread(self):
        self.show_scanner_view()
        threading.Thread(target=self._run_persistence, daemon=True).start()

    def _run_persistence(self):
        self.log("\n=== AUDITORÍA DE PERSISTENCIA EN REGISTRO ===")
        self.set_status("Auditando entradas del registro...")
        total, flagged = audit_registry(self.signatures)

        verified = []
        for item in flagged:
            path = item.get("command", "")
            if os.path.isfile(path):
                is_signed, _ = check_authenticode(path)
                if is_signed:
                    self.log(f"[OK Authenticode] Entrada de inicio verificada: {item['name']}")
                    continue
            verified.append(item)

        for item in verified:
            self.log(f"[!] ENTRADA SOSPECHOSA: [{item['label']}] {item['name']}")
            self.log(f"    Ejecutable: {item['command']}")
        self.log(f"Persistencia finalizada: {total} examinadas, {len(verified)} sospechosas.")
        self.set_status("Auditoría de registro concluida.")

    def start_vt_thread(self):
        target = self.entry_path.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showwarning("Atención", "Seleccione un archivo puntual para consultar en VirusTotal.")
            return
        if not self.vt_api_key:
            messagebox.showinfo("Configuración requerida", "Ingrese su API Key de VirusTotal en la pestaña Configuración.")
            self.show_config_view()
            return
        threading.Thread(target=self._run_vt, args=(target,), daemon=True).start()

    def _run_vt(self, filepath):
        self.show_scanner_view()
        self.log(f"\n[*] Consultando VirusTotal: {os.path.basename(filepath)}...")
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

    def start_update_thread(self):
        self.show_scanner_view()
        threading.Thread(target=self._run_update, daemon=True).start()

    def _run_update(self):
        self.log("\n[*] Sincronizando firmas desde ThreatFox...")
        ok, res, new_sigs = update_signatures_from_cloud(self.signatures)
        if ok:
            self.signatures = new_sigs
            self.lbl_sig_count.configure(text=f"Firmas: {len(self.signatures)}")
            self.log(f"[✓] Actualización completada: +{res} firmas añadidas.")
            messagebox.showinfo("Actualización exitosa", f"Se incorporaron {res} nuevas firmas.")
        else:
            self.log(f"[!] Error de sincronización: {res}")

    def manage_context_menu(self):
        op = messagebox.askyesnocancel(
            "Integración Shell",
            "¿Desea registrar 'Analizar con KILLVirus' en el menú contextual de Windows?\n\n"
            "- Sí: Activar\n- No: Desactivar\n- Cancelar: Salir"
        )
        if op is True:
            ok, msg = register_context_menu()
            messagebox.showinfo("Menú Contextual", msg) if ok else messagebox.showerror("Error", msg)
        elif op is False:
            ok, msg = unregister_context_menu()
            messagebox.showinfo("Menú Contextual", msg) if ok else messagebox.showerror("Error", msg)

    # ================= GESTOR DE CUARENTENA =================
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
                self.tree_quar.insert("", "end", values=(file, sz, date_str))

    def restore_quarantined_file(self):
        sel = self.tree_quar.selection()
        if not sel:
            messagebox.showwarning("Atención", "Seleccione un archivo de la lista.")
            return
        item = self.tree_quar.item(sel[0])["values"][0]
        q_path = os.path.join(QUARANTINE_DIR, item)
        meta_p = q_path + ".meta"
        dest = None

        if os.path.exists(meta_p):
            try:
                with open(meta_p, "r", encoding="utf-8") as m:
                    dest = json.load(m).get("original_path")
            except Exception:
                pass

        if not dest:
            dest = filedialog.asksaveasfilename(initialfile=item.replace(".quarantine", ""))

        if dest:
            try:
                shutil.move(q_path, dest)
                if os.path.exists(meta_p):
                    os.remove(meta_p)
                messagebox.showinfo("Éxito", f"Archivo restaurado en:\n{dest}")
                self.refresh_quarantine_table()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo restaurar: {e}")

    def delete_quarantined_file(self):
        sel = self.tree_quar.selection()
        if not sel:
            messagebox.showwarning("Atención", "Seleccione un elemento de la lista.")
            return
        if not messagebox.askyesno("Confirmar", "¿Eliminar definitivamente este archivo del disco?"):
            return
        item = self.tree_quar.item(sel[0])["values"][0]
        q_path = os.path.join(QUARANTINE_DIR, item)
        meta_p = q_path + ".meta"
        try:
            os.remove(q_path)
            if os.path.exists(meta_p):
                os.remove(meta_p)
            self.refresh_quarantine_table()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo eliminar: {e}")

    # ================= CONFIGURACIÓN =================
    def save_api_key(self):
        key = self.entry_vt_key.get().strip()
        self.vt_api_key = key
        self.config["vt_api_key"] = key
        self.save_config()
        messagebox.showinfo("Configuración", "API Key de VirusTotal guardada.")

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
        messagebox.showinfo("Configuración", "Lista de exclusiones actualizada.")

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