import os
import math
import pefile

# APIs críticas comúnmente abusadas por malware
SUSPICIOUS_FUNCTIONS = {
    # Inyección de procesos y ejecución remota
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", 
    "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
    # Evasión de defensas y hooking
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    # Descarga directa en memoria
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenUrlA"
}

def calculate_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon (0.0 a 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def analyze_pe(filepath: str):
    """
    Analiza un binario PE (.exe o .dll).
    Retorna: (es_sospechoso: bool, razones: list, info: dict)
    """
    if not os.path.isfile(filepath):
        return False, [], {}

    reasons = []
    pe_info = {"sections": [], "suspicious_imports": []}

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()

        # 1. Auditoría de secciones y cálculo de entropía
        high_entropy_sections = []
        for section in pe.sections:
            sec_name = section.Name.decode(errors="ignore").strip("\x00")
            sec_data = section.get_data()
            entropy = calculate_entropy(sec_data)
            pe_info["sections"].append({"name": sec_name, "entropy": entropy})

            if entropy >= 7.0:
                high_entropy_sections.append(f"{sec_name} ({entropy})")

        if high_entropy_sections:
            reasons.append(f"Secciones empaquetadas/cifradas (Entropía alta): {', '.join(high_entropy_sections)}")

        # 2. Análisis de tabla de importaciones (IAT)
        detected_apis = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode(errors="ignore")
                        if func_name in SUSPICIOUS_FUNCTIONS:
                            detected_apis.append(func_name)

        if detected_apis:
            unique_apis = list(set(detected_apis))
            pe_info["suspicious_imports"] = unique_apis
            reasons.append(f"Imports peligrosos detectados: {', '.join(unique_apis[:4])}")

        pe.close()
        is_suspicious = len(reasons) > 0
        return is_suspicious, reasons, pe_info

    except pefile.PEFormatError:
        # No es un ejecutable Windows PE válido
        return False, [], {}
    except Exception as e:
        return False, [f"Error al analizar PE: {e}"], {}