import os
import psutil

from core.scanner import calculate_sha256
from core.signatures import SignatureStore


def scan_running_processes(store: SignatureStore, progress_callback=None):
    """Inspecciona procesos en ejecución y termina los que coincidan con firmas.

    `store` debe implementar `lookup(hash) -> SignatureEntry | None`.
    """
    inspected = 0
    threats_found = []

    try:
        procs = list(psutil.process_iter(['pid', 'name', 'exe']))
    except Exception:
        procs = []

    total_procs = len(procs)

    for idx, proc in enumerate(procs, 1):
        try:
            p_info = proc.info
            exe_path = p_info.get('exe', '')
            p_name = p_info.get('name', '')
            pid = p_info.get('pid', 0)

            if progress_callback:
                progress_callback(idx, total_procs, exe_path or p_name)

            if not exe_path or not os.path.isfile(exe_path):
                continue

            inspected += 1
            f_hash = calculate_sha256(exe_path)

            entry = store.lookup(f_hash) if f_hash else None
            if entry is not None:
                threats_found.append({
                    "pid": pid,
                    "name": p_name,
                    "path": exe_path,
                    "malware": entry.malware_name,
                })
                try:
                    proc.kill()
                except Exception:
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return inspected, threats_found
