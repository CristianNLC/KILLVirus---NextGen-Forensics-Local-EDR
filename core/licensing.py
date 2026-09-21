import os
import json
import uuid
import requests
import hashlib
from datetime import datetime

def _load_env():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(root_dir, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip('"').strip("'")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

_load_env()

# Credenciales de Supabase con fallback obligatorio para ejecutable compilado (.exe)
DEFAULT_SUPABASE_URL = "https://ppwfaogyofmskpshvldc.supabase.co"
DEFAULT_SUPABASE_KEY = "sb_secret_NMc5Jw4HI1R7GTO76lSCyg_mgXzv32c"

SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").strip() or DEFAULT_SUPABASE_URL
SUPABASE_ANON_KEY = (os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_KEY") or "").strip() or DEFAULT_SUPABASE_KEY

LOCAL_LICENSE_FILE = os.path.join("data", "license.json")

def get_machine_hwid() -> str:
    """Genera un identificador único y persistente de la máquina del cliente."""
    try:
        # Genera un hash basado en la dirección física de red del equipo
        mac = uuid.getnode()
        return hashlib.sha256(str(mac).encode()).hexdigest()[:32]
    except Exception:
        return "GENERIC-HWID-FALLBACK"

def get_saved_license():
    """Lee la licencia guardada localmente si existe."""
    if not os.path.exists(LOCAL_LICENSE_FILE):
        return None
    try:
        with open(LOCAL_LICENSE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_license_locally(data: dict):
    """Almacena la licencia de forma local en el equipo del cliente."""
    os.makedirs(os.path.dirname(LOCAL_LICENSE_FILE), exist_ok=True)
    with open(LOCAL_LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def verify_license_online(license_key: str):
    """
    Consulta la API REST de Supabase para validar la clave y asociar el hardware_id.
    Retorna: (es_valida: bool, mensaje: str, datos_licencia: dict)
    """
    clean_key = license_key.strip()
    if not clean_key:
        return False, "La clave no puede estar vacía.", None

    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json"
    }

    # Consulta a la tabla licencias filtrando por la clave ingresada
    endpoint = f"{SUPABASE_URL}/rest/v1/licencias?clave_licencia=eq.{clean_key}&select=*"

    try:
        response = requests.get(endpoint, headers=headers, timeout=8)
        if response.status_code != 200:
            return False, f"Error al contactar el servidor ({response.status_code})", None

        rows = response.json()
        if not rows:
            return False, "Clave de licencia no encontrada o inválida.", None

        lic = rows[0]
        estado = lic.get("estado", "")
        if estado != "activa":
            return False, f"La licencia se encuentra en estado: {estado.upper()}", None

        # Comprobar fecha de expiración
        exp_str = lic.get("fecha_expiracion")
        if exp_str:
            try:
                exp_date = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if datetime.now(exp_date.tzinfo) > exp_date:
                    return False, "La licencia ha expirado.", None
            except Exception:
                pass

        # Verificación y enlace de HWID (anti-piratería)
        current_hwid = get_machine_hwid()
        saved_hwid = lic.get("hardware_id")

        if saved_hwid is None:
            # Primera activación: registramos este equipo en Supabase
            try:
                patch_url = f"{SUPABASE_URL}/rest/v1/licencias?clave_licencia=eq.{clean_key}"
                requests.patch(
                    patch_url,
                    headers=headers,
                    json={"hardware_id": current_hwid, "ultima_verificacion": datetime.utcnow().isoformat()},
                    timeout=8
                )
            except Exception:
                pass
        elif saved_hwid != current_hwid:
            return False, "Esta licencia ya fue vinculada a otra computadora.", None

        # Guardar localmente
        save_license_locally({
            "clave": clean_key,
            "plan": lic.get("plan", "PRO"),
            "email": lic.get("email_cliente", "")
        })

        return True, f"Licencia PRO válida ({lic.get('plan', '').upper()})", lic

    except Exception as e:
        # Si no hay internet, revisamos si hay una copia local guardada
        local = get_saved_license()
        if local and local.get("clave") == clean_key:
            return True, "Modo Offline: Licencia PRO confirmada localmente.", local
        return False, f"No se pudo verificar la licencia (Sin conexión u error de red): {e}", None