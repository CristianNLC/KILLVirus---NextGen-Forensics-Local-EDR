"""Capa de servicios: lógica de negocio sin depender de la UI."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from core.amsi import AMSI
from core.paths import is_inside_runtime_dir, QUARANTINE_DIR
from core.quarantine import isolate_file
from core.reporter import generate_html_report
from core.scanner import TARGET_EXTENSIONS, calculate_sha256
from core.signatures import DictStore, SignatureStore, SignatureEntry
from core.updater import update_signatures_from_cloud
from core.virustotal import check_virustotal_hash
from core.memory import scan_running_processes
from core.persistence import audit_registry

# Instancia global de AMSI (se inicializa una sola vez)
_amsi = AMSI()

# Extensiones de script que se envían a AMSI
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".wsh"}


@dataclass
class DetectionResult:
    filepath: str
    detection: object  # core.scan_engine.Detection
    quarantined: bool
    quarantine_path: Optional[str] = None


class ScanService:
    """Orquesta escaneos, actualización de firmas y consultas externas.

    No toca la UI: solo retorna datos. La UI decide qué loguear y mostrar.
    """

    def __init__(self, store: SignatureStore, config: dict):
        self.store = store
        self.config = config

    # --- escaneo de un solo archivo (protección en vivo o archivo suelto) ---
    def scan_file_live(self, filepath: str):
        """Escanear un archivo puntual. Devuelve Detection o None."""
        if not os.path.isfile(filepath):
            return None
        if is_inside_runtime_dir(filepath):
            return None
        return scan_file_engine(filepath, self.store)

    def quarantine_file(self, filepath: str, detection) -> Optional[str]:
        """Aislar un archivo en cuarentena con metadatos de la detección."""
        f_hash = getattr(detection, "sha256", "") or calculate_sha256(filepath)
        reason = f"{getattr(detection, 'reason', 'Detección')}: {getattr(detection, 'name', '')}"
        return isolate_file(filepath, reason=reason, sha256=f_hash)

    # --- escaneo de carpeta ---
    def scan_folder(self, folder: str, progress_cb: Optional[Callable[[int, int, str], None]] = None):
        """Recorrer carpeta y retornar lista de threats detectados.

        Cada threat: {"file", "path", "hash", "reason", "quarantined", "quarantine_path"}
        """
        target_files = []
        for root, _, files in os.walk(folder):
            if is_inside_runtime_dir(root):
                continue
            for file in files:
                filepath = os.path.join(root, file)
                if is_inside_runtime_dir(filepath):
                    continue
                ext = os.path.splitext(file)[1].lower()
                if ext in TARGET_EXTENSIONS:
                    target_files.append(filepath)

        total = len(target_files)
        threats = []
        scanned = 0

        for filepath in target_files:
            scanned += 1
            if progress_cb:
                progress_cb(scanned, total, os.path.basename(filepath))

            detection = scan_file_engine(filepath, self.store)
            if detection is None:
                continue

            f_hash = detection.sha256 or calculate_sha256(filepath)
            qp = self.quarantine_file(filepath, detection)
            threats.append({
                "file": os.path.basename(filepath),
                "path": filepath,
                "hash": f_hash or "N/A",
                "reason": f"{detection.reason}: {detection.name}",
                "quarantined": qp is not None,
                "quarantine_path": qp,
            })

        return {
            "scanned": scanned,
            "total": total,
            "threats": threats,
        }

    # --- procesos en RAM ---
    def scan_processes(self, progress_cb: Optional[Callable[[int, int, str], None]] = None):
        return scan_running_processes(self.store, progress_callback=progress_cb)

    # --- persistencia (registro de auto-inicio) ---
    def audit_persistence(self):
        return audit_registry(self.store)

    # --- actualización de firmas desde ThreatFox ---
    def update_signatures(self):
        """Retorna (ok, resultado:int|str, new_signatures_dict)."""
        auth_key = self.config.get("threatfox_auth_key", "")
        return update_signatures_from_cloud(self.store.to_dict(), auth_key=auth_key)

    def apply_updated_signatures(self, new_sigs_dict: dict):
        """Mezcla las nuevas firmas en el store existente (persistente)."""
        new_store = DictStore(new_sigs_dict)
        added = self.store.merge(new_store)
        return len(self.store), added

    # --- VirusTotal ---
    def check_virustotal(self, filepath: str, api_key: str):
        f_hash = calculate_sha256(filepath)
        return check_virustotal_hash(f_hash, api_key)

    # --- reporte HTML ---
    def generate_report(self, target_path: str, scanned: int, threats: list):
        return generate_html_report(target_path, scanned, threats)


# Import local para evitar import circular con core.scanner (que importa de core.yara_scanner etc.)
def scan_file_engine(filepath, store: SignatureStore):
    from core.scan_engine import scan_file as _scan_file
    from core.scan_engine import Detection, SEV_YARA

    detection = _scan_file(filepath, store)
    if detection is not None:
        return detection

    # Si no hay detección por firmas/YARA/heurística, probar AMSI en scripts
    ext = os.path.splitext(filepath)[1].lower()
    if ext in SCRIPT_EXTENSIONS and _amsi.available:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return None

        if not content.strip():
            return None

        es_malicioso, msg = _amsi.scan_string(content, os.path.basename(filepath))
        if es_malicioso:
            return Detection(
                name="AMSI.Detected",
                reason=f"AMSI ({msg})",
                severity=SEV_YARA,
                sha256=calculate_sha256(filepath),
            )

    return None
