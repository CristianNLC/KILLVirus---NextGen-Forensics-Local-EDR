"""Autocomprobación del motor de detección.

Uso:  python scripts/selftest.py

No usa muestras reales de malware ni la cadena EICAR (el antivirus del sistema
podría borrar el propio script). Verifica rutas, firmas, heurísticas, YARA,
Authenticode, el parser de ThreatFox y la cola de protección en vivo.
"""

import hashlib
import json
import os
import sys
import tempfile
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core import paths
from core.authenticode import verify_file_signature
from core.signatures import (
    DictStore,
    SignatureEntry,
    create_signature_store,
)
from core.scan_engine import scan_file
from core.updater import parse_iocs, update_signatures_from_cloud
from core.yara_scanner import HAS_YARA, UNAVAILABLE_REASON, YaraDetector

paths.init_app()

failures = []


def check(name, condition, extra=""):
    status = "OK   " if condition else "FALLO"
    if not condition:
        failures.append(name)
    print(f"{status} {name} {extra}")


# --- rutas ---
check("paths: data dir existe", os.path.isdir(paths.DATA_DIR), paths.DATA_DIR)
check("paths: cuarentena existe", os.path.isdir(paths.QUARANTINE_DIR))
check("paths: detecta cuarentena interna",
      paths.is_inside_runtime_dir(os.path.join(paths.QUARANTINE_DIR, "x.quarantine")))
check("paths: no marca archivo normal",
      not paths.is_inside_runtime_dir(os.path.join(tempfile.gettempdir(), "x.txt")))

# --- firmas ---
with open(paths.SIGNATURES_FILE, encoding="utf-8") as fh:
    sigs = json.load(fh)
check("firmas: cargan", len(sigs) > 0, f"({len(sigs)} entradas)")
check("firmas: sin hash de archivo vacio",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in sigs)

tmpdir = tempfile.mkdtemp(prefix="killvirus_test_")

# --- firma por hash ---
sample = os.path.join(tmpdir, "muestra.dat")
content = b"contenido de prueba benigno para el motor de firmas"
with open(sample, "wb") as fh:
    fh.write(content)
test_hash = hashlib.sha256(content).hexdigest()
sigs_with_test = dict(sigs)
sigs_with_test[test_hash] = {"malware_name": "Test.Signature", "threat_type": "Test"}
det = scan_file(sample, DictStore(sigs_with_test))
check("scan: detecta por hash SHA-256", det is not None and det.severity == 3,
      f"({det.reason if det else None})")

# --- archivo vacio: antes daba falso positivo ---
empty = os.path.join(tmpdir, "vacio.bat")
open(empty, "w").close()
check("scan: archivo vacio NO se marca", scan_file(empty, DictStore(sigs)) is None)

# --- heuristica PowerShell ---
ps = os.path.join(tmpdir, "descarga.ps1")
with open(ps, "w", encoding="utf-8") as fh:
    fh.write("$u = 'http://example.invalid/payload.exe'\nInvoke-WebRequest $u -OutFile x.exe\n")
det = scan_file(ps, DictStore(sigs))
check("scan: heuristica PS Downloader", det is not None and "HEUR" in det.reason,
      f"({det.reason if det else None})")

# --- YARA ---
if HAS_YARA:
    detector = YaraDetector()
    check("yara: reglas compilan", detector.rules is not None)
else:
    print(f"[i] YARA inactivo ({UNAVAILABLE_REASON}): se omite la prueba de reglas")

# --- Authenticode (solo firma embebida; muchos binarios de Windows van por catálogo) ---
signed_target = sys.executable
signed, msg = verify_file_signature(signed_target)
if signed:
    check("authenticode: python.exe firmado (embebido)", signed, f"({msg})")
else:
    print(f"[i] {signed_target} sin firma embebida verificable ({msg}): se omite")

unsigned = os.path.join(tmpdir, "sin_firma.exe")
with open(unsigned, "wb") as fh:
    fh.write(b"MZ" + b"\x00" * 200)
signed, msg = verify_file_signature(unsigned)
check("authenticode: PE falso sin firma", not signed, f"({msg})")

# --- parser ThreatFox ---
h1 = "a" * 64
h2 = "b" * 64
payload = {
    "query_status": "ok",
    "data": [
        {"ioc": h1, "ioc_type": "sha256_hash", "confidence_level": 75,
         "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc"},
        {"ioc": h2, "ioc_type": "sha256_hash", "confidence_level": 25,
         "malware_printable": "Baja confianza", "threat_type": "payload"},
        {"ioc": "c" * 32, "ioc_type": "md5_hash", "confidence_level": 100},
        {"ioc": "no-es-hash", "ioc_type": "sha256_hash", "confidence_level": 100},
        {"ioc": h1, "ioc_type": "sha256_hash", "confidence_level": 50,
         "malware_printable": "Duplicado peor", "threat_type": "payload"},
    ],
}
parsed = parse_iocs(payload)
check("updater: solo sha256 con confianza >= 50", len(parsed) == 1 and h1 in parsed, f"({len(parsed)})")
check("updater: conserva mayor confianza", parsed.get(h1, {}).get("malware_name") == "Cobalt Strike")
check("updater: sin Auth-Key falla claro", update_signatures_from_cloud({}, auth_key="")[0] is False)

# --- guardado atomico de firmas (sin tocar la base real) ---
import core.updater as updater_module

_orig_sig_file = updater_module.SIGNATURES_FILE
_temp_sig_file = os.path.join(tmpdir, "sig.json")
updater_module.SIGNATURES_FILE = _temp_sig_file
try:
    updater_module.save_signatures({"a" * 64: {"malware_name": "X"}})
    written = {}
    if os.path.isfile(_temp_sig_file):
        with open(_temp_sig_file, encoding="utf-8") as fh:
            written = json.load(fh)
    check("updater: guardado atomico", written.get("a" * 64, {}).get("malware_name") == "X")
    check("updater: sin archivos .tmp huerfanos",
          not any(n.endswith(".tmp") for n in os.listdir(tmpdir)))
finally:
    updater_module.SIGNATURES_FILE = _orig_sig_file

# --- cola de proteccion en vivo (no requiere ventana) ---
from ui.main_window import LiveProtectionHandler


class DummyApp:
    def scan_single_file_live(self, path):
        pass


handler = LiveProtectionHandler(DummyApp(), dedupe_seconds=5)
handler._handle(os.path.join(tmpdir, "nota.txt"), False)
check("live: ignora extensiones no objetivo", handler._queue.qsize() == 0)
handler._handle(os.path.join(tmpdir, "uno.exe"), False)
handler._handle(os.path.join(tmpdir, "uno.exe"), False)
check("live: deduplica el mismo archivo", handler._queue.qsize() == 1)
handler._handle(os.path.join(tmpdir, "dos.ps1"), False)
check("live: encola archivos distintos", handler._queue.qsize() == 2)
handler.stop()

# --- cuarentena: aislamiento y metadatos ---
from core.quarantine import isolate_file

victim = os.path.join(tmpdir, "victima.exe")
with open(victim, "wb") as fh:
    fh.write(b"MZ benigno")
qp = isolate_file(victim, reason="Prueba: firma de test", sha256="f" * 64)
check("cuarentena: aisla y devuelve ruta", qp is not None and os.path.isfile(qp))
check("cuarentena: borra el original", not os.path.exists(victim))

meta = {}
if qp and os.path.isfile(qp + ".meta"):
    with open(qp + ".meta", encoding="utf-8") as fh:
        meta = json.load(fh)
check("cuarentena: guarda motivo y sha256",
      meta.get("reason") == "Prueba: firma de test" and meta.get("sha256") == "f" * 64)

# Limpieza: no dejar basura en la cuarentena real.
for leftover in (qp, qp + ".meta" if qp else None):
    if leftover and os.path.isfile(leftover):
        os.remove(leftover)

# --- firmas en SQLite ---

tmpdb = os.path.join(tmpdir, "test_signatures.db")

# SqliteStore vacío al crear
ss = create_signature_store(tmpdb, use_sqlite=True)
check("sqlite: store vacío al crear", len(ss) == 0)

# Inserción y consulta
ss.add(SignatureEntry(hash="e" * 64, malware_name="SQL.Test", threat_type="T"))
check("sqlite: inserción y consulta", ss.lookup("e" * 64) is not None)
check("sqlite: nombre correcto", ss.lookup("e" * 64).malware_name == "SQL.Test")
check("sqlite: contiene", "e" * 64 in ss)
check("sqlite: no contiene inexistente", "z" * 64 not in ss)
ss.close()

# Reabrir: los datos persisten
ss2 = create_signature_store(tmpdb, use_sqlite=True)
check("sqlite: persiste tras reabrir", ss2.lookup("e" * 64) is not None)
check("sqlite: cuenta tras reabrir", len(ss2) == 1)
ss2.close()

# Migración JSON -> SQLite (BD vacía + JSON con datos)
json_tmp = os.path.join(tmpdir, "migracion.json")
import json as _json
with open(json_tmp, "w", encoding="utf-8") as f:
    _json.dump({"f" * 64: {"malware_name": "JSON.Test", "threat_type": "M"}}, f)
tmpdb2 = os.path.join(tmpdir, "test_signatures2.db")
ss3 = create_signature_store(tmpdb2, json_path=json_tmp, use_sqlite=True)
check("sqlite: migra JSON a SQLite", len(ss3) == 1)
check("sqlite: migración conserva nombre",
      ss3.lookup("f" * 64).malware_name == "JSON.Test")
# Segunda migración no duplica
ss3.add(SignatureEntry(hash="g" * 64, malware_name="Extra"))
check("sqlite: no duplica al reabrir", len(ss3) == 2)
ss3.close()

# --- agente headless (sin Tk) ---
from core.agent import AgentOptions, ProtectionAgent

agent_dir = os.path.join(tmpdir, "agent")
os.makedirs(agent_dir, exist_ok=True)
agent_status = os.path.join(agent_dir, "status.json")
agent_options = AgentOptions(
    watch_folders=[agent_dir],
    canary_dirs=[agent_dir],
    enable_process_monitor=False,
    canary_interval=0.2,
    heartbeat_interval=0.2,
    watchdog_interval=30.0,
    status_file=agent_status,
)
agent = ProtectionAgent(agent_options, store=DictStore())
agent.start()
time.sleep(0.7)
agent_state = agent.status()
check("agente: arranca", agent.is_running)
check("agente: heartbeat escrito", os.path.isfile(agent_status))
check("agente: proteccion en vivo activa",
      agent_state["components"]["live_protection"])
check("agente: canarios activos", agent_state["components"]["canary"])
agent.stop()
check("agente: se detiene", not agent.is_running)

# --- servicio de Windows y autoproteccion (sin tocar el SCM real) ---
from core.autoprotect import build_icacls_command, compute_manifest
from core.service_control import build_bin_path, service_status

check("servicio: binPath incluye --service", "--service" in build_bin_path())
check("servicio: binPath incluye --data-dir", "--data-dir" in build_bin_path())
missing = service_status("KILLVirusTestInexistente123")
check("servicio: consulta inexistente no falla", missing["installed"] is False)
acl_cmd = build_icacls_command(tmpdir)
check("acl: desactiva herencia", "/inheritance:r" in acl_cmd)
check("acl: concede a SYSTEM y Administradores",
      any("*S-1-5-18" in part for part in acl_cmd)
      and any("*S-1-5-32-544" in part for part in acl_cmd))
manifest = compute_manifest(PROJECT_ROOT)
check("integridad: manifiesto con archivos", len(manifest["files"]) > 10,
      f"({len(manifest['files'])} archivos)")

print()
print("RESULTADO:", "TODO OK" if not failures else f"FALLOS: {failures}")
sys.exit(0 if not failures else 1)
