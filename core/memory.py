import os
import psutil
from core.scanner import calculate_sha256

def scan_running_processes(signatures):
    inspected = 0
    threats_found = []

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            p_info = proc.info
            exe_path = p_info['exe']
            p_name = p_info['name']
            pid = p_info['pid']

            if not exe_path or not os.path.isfile(exe_path):
                continue

            inspected += 1
            f_hash = calculate_sha256(exe_path)

            if f_hash and f_hash in signatures:
                malware_name = signatures[f_hash].get("malware_name", "Amenaza")
                threats_found.append({"pid": pid, "name": p_name, "path": exe_path, "malware": malware_name})
                try:
                    proc.kill()
                except Exception:
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return inspected, threats_found