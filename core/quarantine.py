import os
import json
import shutil
from datetime import datetime

QUARANTINE_DIR = os.path.join(os.getcwd(), "cuarentena")

def isolate_file(filepath):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantined_name = f"{filename}_{timestamp}.quarantine"
        dest_path = os.path.join(QUARANTINE_DIR, quarantined_name)
        
        meta_path = dest_path + ".meta"
        with open(meta_path, "w", encoding="utf-8") as meta:
            json.dump({"original_path": os.path.abspath(filepath), "date": timestamp}, meta)

        shutil.move(filepath, dest_path)
        return dest_path
    except Exception:
        return None