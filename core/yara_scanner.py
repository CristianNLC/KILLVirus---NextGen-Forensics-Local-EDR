import os
import yara

RULES_PATH = os.path.join("data", "rules.yar")

class YaraDetector:
    def __init__(self, rule_file=RULES_PATH):
        self.rule_file = rule_file
        self.rules = None
        self.load_rules()

    def load_rules(self):
        """Compila las reglas YARA si el archivo existe."""
        if os.path.exists(self.rule_file):
            try:
                self.rules = yara.compile(filepath=self.rule_file)
            except Exception as e:
                self.rules = None
        else:
            self.rules = None

    def scan_file(self, filepath):
        """
        Analiza un archivo físico con las reglas compiladas.
        Retorna (nombre_regla, descripcion_meta) o (None, None).
        """
        if not self.rules or not os.path.isfile(filepath):
            return None, None

        try:
            matches = self.rules.match(filepath)
            if matches:
                match = matches[0]
                rule_name = match.rule
                desc = match.meta.get("description", "Patrón YARA detectado")
                return rule_name, desc
        except Exception:
            pass

        return None, None