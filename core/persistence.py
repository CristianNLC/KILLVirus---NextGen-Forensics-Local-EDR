import os
import winreg
import re
from core.scanner import calculate_sha256, analyze_heuristics

REG_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce")
]

def extract_binary_path(cmd_string):
    cmd = cmd_string.strip()
    if cmd.startswith('"'):
        match = re.match(r'^"([^"]+)"', cmd)
        return match.group(1) if match else cmd
    return cmd.split()[0] if cmd else ""

def audit_registry(signatures):
    suspicious_keywords = ["temp", "appdata\\local\\temp", "programdata", "powershell", "wscript", "cscript", "cmd.exe /c"]
    found_entries = 0
    flagged_results = []

    for root_key, subkey, label in REG_PATHS:
        try:
            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as k:
                count = winreg.QueryInfoKey(k)[1]
                for i in range(count):
                    name, val, _ = winreg.EnumValue(k, i)
                    found_entries += 1
                    val_str = str(val).strip()
                    raw_path = extract_binary_path(val_str)
                    is_suspicious = False
                    reasons = []

                    lower_val = val_str.lower()
                    for kw in suspicious_keywords:
                        if kw in lower_val:
                            is_suspicious = True
                            reasons.append(f"Ruta inusual ('{kw}')")

                    if os.path.isfile(raw_path):
                        f_hash = calculate_sha256(raw_path)
                        if f_hash and f_hash in signatures:
                            is_suspicious = True
                            reasons.append(f"Firma: {signatures[f_hash].get('malware_name')}")
                        else:
                            h_id, h_desc = analyze_heuristics(raw_path)
                            if h_id:
                                is_suspicious = True
                                reasons.append(f"Heurística: {h_desc}")

                    if is_suspicious:
                        flagged_results.append({"label": label, "name": name, "command": val_str, "reasons": reasons})
        except Exception:
            continue

    return found_entries, flagged_results