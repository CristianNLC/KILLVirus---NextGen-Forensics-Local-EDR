import os
import secrets
import string
import requests
from datetime import datetime, timedelta, timezone

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

# Credenciales de Supabase leídas desde entorno / .env
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

def generate_key_string(prefix: str = "KV-PRO") -> str:
    """Genera una clave con formato legible: KV-PRO-XXXX-XXXX-XXXX"""
    alphabet = string.ascii_uppercase + string.digits
    # Excluir caracteres ambiguos (0, O, 1, I)
    alphabet = alphabet.replace("0", "").replace("O", "").replace("1", "").replace("I", "")
    
    parts = [''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return f"{prefix}-{'-'.join(parts)}"

def create_license(email: str, plan: str = "anual", days_valid: int = 365, payment_id: str = None):
    """
    Registra una nueva licencia en Supabase lista para ser activada.
    plan: 'mensual', 'anual', 'vitalicia'
    """
    key = generate_key_string()
    
    now_utc = datetime.now(timezone.utc)
    if plan == "vitalicia":
        expiration = now_utc + timedelta(days=365 * 10)  # 10 años
    else:
        expiration = now_utc + timedelta(days=days_valid)
        
    payload = {
        "clave_licencia": key,
        "email_cliente": email.strip().lower(),
        "plan": plan,
        "estado": "activa",
        "max_dispositivos": 1,
        "hardware_id": None, # Se asociará en la primera PC que la use
        "fecha_expiracion": expiration.isoformat(),
        "id_pago_pasarela": payment_id,
        "notas": f"Generada automáticamente. Plan: {plan}"
    }

    url = f"{SUPABASE_URL}/rest/v1/licencias"
    response = requests.post(url, headers=HEADERS, json=payload)
    
    if response.status_code in (200, 201):
        return True, key, response.json()
    else:
        return False, None, f"Error Supabase ({response.status_code}): {response.text}"

def create_batch_licenses(count: int = 5, plan: str = "anual", email_holder: str = "stock@killvirus.com"):
    """Genera un lote de licencias de reserva para revendedores o promociones."""
    created = []
    for _ in range(count):
        ok, key, _ = create_license(email=email_holder, plan=plan)
        if ok:
            created.append(key)
    return created

if __name__ == "__main__":
    print("=== GENERADOR DE LICENCIAS KILLVIRUS ===")
    target_email = input("Email del cliente: ").strip() or "cliente_prueba@gmail.com"
    selected_plan = input("Plan (mensual/anual/vitalicia) [anual]: ").strip().lower() or "anual"
    
    exito, key, info = create_license(email=target_email, plan=selected_plan)
    if exito:
        print(f"\n[✓] Licencia creada con éxito en Supabase:")
        print(f"    Clave: {key}")
        print(f"    Cliente: {target_email}")
        print(f"    Plan: {selected_plan.upper()}")
    else:
        print(f"\n[x] Error al crear licencia: {info}")