"""
Motor de veredicto único.

Antes la lógica de detección estaba duplicada en el escaneo de disco y en la
protección en vivo, y ambos caminos trataban una firma Authenticode válida como
un "indulto" total: cualquier binario firmado (incluidos LOLBins, certificados
robados o malware firmado) evitaba todas las detecciones.

Aquí la firma es un modificador de confianza:
  * Coincidencia de hash  -> se reporta siempre (aunque esté firmado).
  * Regla YARA            -> se reporta siempre.
  * Heurística/PE         -> si el binario tiene firma válida, se descarta
                             como falso positivo; si no, se reporta.

`store` es cualquier objeto que implemente `core.signatures.SignatureStore`.
"""

import os
from dataclasses import dataclass

from core.scanner import (
    calculate_sha256,
    analyze_heuristics,
    analyze_binary_pe,
    analyze_yara,
    check_authenticode,
)
from core.signatures import SignatureStore, SignatureEntry

SEV_SIGNATURE = 3
SEV_YARA = 2
SEV_HEURISTIC = 1

PE_EXTENSIONS = {".exe", ".dll", ".sys"}


@dataclass(frozen=True)
class Detection:
    name: str
    reason: str
    severity: int
    sha256: str = ""
    signed: bool = False
    signature_message: str = ""


def scan_file(filepath, store: SignatureStore):
    """Analiza un archivo y devuelve Detection o None.

    `store` debe implementar `lookup(hash) -> SignatureEntry | None`.
    """
    if not os.path.isfile(filepath):
        return None

    file_hash = calculate_sha256(filepath)
    detection = None

    # 1. Firma de hash (máxima confianza, no se descarta por Authenticode)
    if file_hash:
        entry = store.lookup(file_hash)
        if entry is not None:
            detection = Detection(
                name=entry.malware_name,
                reason="Firma SHA-256",
                severity=SEV_SIGNATURE,
                sha256=file_hash,
            )

    # 2. Reglas YARA (alta confianza, tampoco se descarta)
    if detection is None:
        yara_id, yara_desc = analyze_yara(filepath)
        if yara_id:
            detection = Detection(
                name=yara_desc,
                reason=f"YARA ({yara_id})",
                severity=SEV_YARA,
                sha256=file_hash or "",
            )

    # 3. Heurísticas de scripts
    if detection is None:
        heur_id, heur_desc = analyze_heuristics(filepath)
        if heur_id:
            detection = Detection(
                name=heur_desc,
                reason=f"Heurística ({heur_id})",
                severity=SEV_HEURISTIC,
                sha256=file_hash or "",
            )

    # 4. Anomalías estructurales del PE
    if detection is None:
        pe_id, pe_desc = analyze_binary_pe(filepath)
        if pe_id:
            detection = Detection(
                name=pe_desc,
                reason=f"Análisis PE ({pe_id})",
                severity=SEV_HEURISTIC,
                sha256=file_hash or "",
            )

    if detection is None:
        return None

    # 5. Authenticode como modificador (solo para detecciones débiles)
    ext = os.path.splitext(filepath)[1].lower()
    if detection.severity == SEV_HEURISTIC and ext in PE_EXTENSIONS:
        is_signed, sign_message = check_authenticode(filepath)
        if is_signed:
            # Falso positivo probable: binario legítimo firmado.
            return None
        return Detection(
            name=detection.name,
            reason=detection.reason,
            severity=detection.severity,
            sha256=detection.sha256,
            signed=False,
            signature_message=sign_message,
        )

    return detection
