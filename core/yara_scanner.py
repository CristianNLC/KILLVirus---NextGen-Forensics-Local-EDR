import os

from core.paths import RULES_FILE, ensure_runtime_dirs, seed_data_files

try:
    import yara
    HAS_YARA = True
    UNAVAILABLE_REASON = ""
except Exception as exc:  # ImportError, DLL faltante, wheel inexistente...
    yara = None
    HAS_YARA = False
    UNAVAILABLE_REASON = f"{type(exc).__name__}: {exc}"

# No pasar archivos gigantes al motor YARA: evita cuelgues en discos lentos o
# archivos de decenas de GB (imágenes, backups).
MAX_YARA_SIZE = 200 * 1024 * 1024
YARA_TIMEOUT = 30


class YaraDetector:
    def __init__(self, rule_file=None):
        self.rule_file = rule_file or RULES_FILE
        self.rules = None
        if HAS_YARA:
            self.reload_rules()

    def reload_rules(self):
        """(Re)compila las reglas desde disco."""
        if not HAS_YARA:
            return False
        ensure_runtime_dirs()
        seed_data_files()
        if not os.path.isfile(self.rule_file):
            self.rules = None
            return False
        try:
            self.rules = yara.compile(filepath=self.rule_file)
            return True
        except Exception:
            self.rules = None
            return False

    # Compatibilidad con el nombre anterior.
    def load_rules(self):
        return self.reload_rules()

    def scan_file(self, filepath):
        """Evalúa un archivo con las reglas YARA. Retorna (regla, descripción)."""
        if not HAS_YARA or not self.rules or not os.path.isfile(filepath):
            return None, None
        try:
            if os.path.getsize(filepath) > MAX_YARA_SIZE:
                return None, None
            matches = self.rules.match(filepath, timeout=YARA_TIMEOUT)
            if matches:
                match = matches[0]
                description = match.meta.get("description", "Patrón YARA detectado")
                return match.rule, description
        except Exception:
            pass
        return None, None
