import os
import json
import requests

FEED_URL = "https://threatfox.abuse.ch/export/csv/sha256/recent/"
SIGNATURES_FILE = "signatures.json"

def update_signatures_from_cloud(current_signatures):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(FEED_URL, headers=headers, timeout=30)
        response.raise_for_status()

        new_signatures = current_signatures.copy()
        added = 0
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip().strip('"') for p in line.split('","')]
            if len(parts) < 3:
                parts = [p.strip().strip('"') for p in line.split(',')]

            for token in parts:
                clean_hash = token.lower().strip()
                if len(clean_hash) == 64 and all(c in "0123456789abcdef" for c in clean_hash):
                    if clean_hash not in new_signatures:
                        new_signatures[clean_hash] = {
                            "malware_name": parts[5] if len(parts) > 5 and parts[5] else "Trojan.ThreatFox",
                            "threat_type": parts[3] if len(parts) > 3 and parts[3] else "Payload",
                            "severity": "Critical"
                        }
                        added += 1
                    break

        with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
            json.dump(new_signatures, f, indent=2)

        return True, added, new_signatures
    except Exception as e:
        return False, str(e), current_signatures