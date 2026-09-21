import os

try:
    import yara
    HAS_YARA = True
except Exception:
    yara = None
    HAS_YARA = False

RULES_PATH = os.path.join("data", "rules.yar")

class YaraDetector:
    def __init__(self, rule_file=RULES_PATH):
        self.rule_file = rule_file
        self.rules = None
        if HAS_YARA:
            self.load_rules()

    def load_rules(self):
        if os.path.exists(self.rule_file) and HAS_YARA:
            try:
                self.rules = yara.compile(filepath=self.rule_file)
            except Exception:
                self.rules = None

    def scan_file(self, filepath):
        if not HAS_YARA or not self.rules or not os.path.isfile(filepath):
            return None, None
        try:
            matches = self.rules.match(filepath)
            if matches:
                match = matches[0]
                return match.rule, match.meta.get("description", "Patrón YARA detectado")
        except Exception:
            pass
        return None, None