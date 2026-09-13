import os
import hashlib
import re
from core.pe_analyzer import analyze_pe
from core.yara_scanner import YaraDetector
from core.authenticode import verify_file_signature

TARGET_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", 
    ".vbs", ".js", ".scr", ".pif", ".jar", ".php"
}

# Motor global de reglas YARA
yara_engine = YaraDetector()

HEURISTIC_RULES = [
    {
        "id": "HEUR.PS.Downloader",
        "description": "Descarga de archivos sospechosa mediante PowerShell",
        "pattern": re.compile(rb"(invoke-webrequest|downloadfile|downloadstring|start-bitstransfer)", re.IGNORECASE)
    },
    {
        "id": "HEUR.Win.CertutilAbuse",
        "description": "Uso de certutil como descargador de payloads",
        "pattern": re.compile(rb"certutil(\.exe)?\s+(-urlcache|-split)", re.IGNORECASE)
    },
    {
        "id": "HEUR.PS.DisableAV",
        "description": "Intento de desactivar Windows Defender",
        "pattern": re.compile(rb"set-mppreference\s+-disablerealtimemonitoring", re.IGNORECASE)
    },
    {
        "id": "HEUR.PS.ObfuscatedExec",
        "description": "Decodificación Base64 y ejecución en memoria (iex)",
        "pattern": re.compile(rb"frombase64string.*?(iex|invoke-expression)", re.IGNORECASE | re.DOTALL)
    },
    {
        "id": "HEUR.Win.PersistTask",
        "description": "Creación forzada de tarea programada persistente",
        "pattern": re.compile(rb"schtasks(\.exe)?\s+/create.*?/sc\s+(onlogon|onstart)", re.IGNORECASE)
    }
]

def calculate_sha256(filepath):
    """Calcula SHA-256 en bloques de 64 KB para evitar consumo alto de RAM."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def analyze_heuristics(filepath):
    """Evalúa patrones mediante expresiones regulares en scripts."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in {".bat", ".cmd", ".ps1", ".vbs", ".js"}:
        return None, None
    try:
        with open(filepath, "rb") as f:
            content = f.read(5 * 1024 * 1024)
        for rule in HEURISTIC_RULES:
            if rule["pattern"].search(content):
                return rule["id"], rule["description"]
    except Exception:
        pass
    return None, None

def analyze_binary_pe(filepath):
    """Inspecciona entropía e imports sospechosos en archivos PE (.exe, .dll)."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in {".exe", ".dll", ".scr"}:
        is_suspicious, reasons, _ = analyze_pe(filepath)
        if is_suspicious:
            return "PE.Heuristic.Anomaly", " | ".join(reasons)
    return None, None

def analyze_yara(filepath):
    """Evalúa un archivo con el motor compilado de reglas YARA."""
    return yara_engine.scan_file(filepath)

def check_authenticode(filepath):
    """
    Verifica si el binario ejecutable cuenta con una firma digital legítima.
    Retorna: (is_signed: bool, status_message: str)
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext in {".exe", ".dll", ".sys"}:
        return verify_file_signature(filepath)
    return False, "Extensión no aplicable para firma Authenticode"